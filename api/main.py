from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from threading import Lock
from time import monotonic
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Query, Request

from checks.authz_matrix import analyze_authorization_matrix
from checks.cookie_security import inspect_cookie_security
from checks.cors_inspection import inspect_cors_configuration
from checks.endpoint_inventory import crawl_inventory
from checks.http_probe import fetch_response_snapshot
from checks.security_headers import REQUIRED_HEADERS, evaluate_security_headers
from checks.transport_security import inspect_transport_security

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCOPE_PATH = PROJECT_ROOT / 'scope' / 'production.yaml'
POLICY_PATH = PROJECT_ROOT / 'policies' / 'safe-production.yaml'


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open('r', encoding='utf-8') as handle:
        return yaml.safe_load(handle) or {}


def canonicalize_host(host: str | None) -> str:
    if not host:
        raise ValueError('URL must include a hostname.')
    return host.rstrip('.').lower()


def extract_target_host(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        raise ValueError('URL must be an absolute http:// or https:// target.')
    return canonicalize_host(parsed.hostname)


@lru_cache(maxsize=1)
def get_scope_config() -> dict[str, Any]:
    return load_yaml(SCOPE_PATH)


@lru_cache(maxsize=1)
def get_policy_config() -> dict[str, Any]:
    return load_yaml(POLICY_PATH)


def get_allowed_hosts() -> set[str]:
    scope = get_scope_config()
    hosts = scope.get('hosts', [])
    return {canonicalize_host(host) for host in hosts}


class InMemoryRateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: int,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.clock = clock
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str) -> tuple[bool, int]:
        now = self.clock()
        cutoff = now - self.window_seconds

        with self._lock:
            bucket = self._buckets[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self.limit:
                retry_after = max(1, int(self.window_seconds - (now - bucket[0])))
                return False, retry_after

            bucket.append(now)
            return True, 0


@lru_cache(maxsize=1)
def get_rate_limiter() -> InMemoryRateLimiter:
    rate_limit = get_policy_config().get('rate_limit', {})
    return InMemoryRateLimiter(
        limit=int(rate_limit.get('requests', 5)),
        window_seconds=int(rate_limit.get('period_seconds', 60)),
    )


def authorize_target_request(request: Request, url: str) -> tuple[str, dict[str, Any]]:
    try:
        target_host = extract_target_host(url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    allowed_hosts = get_allowed_hosts()
    if target_host not in allowed_hosts:
        raise HTTPException(
            status_code=403,
            detail=f"Host '{target_host}' is not listed in scope/production.yaml.",
        )

    client_ip = request.client.host if request.client else 'unknown'
    allowed, retry_after = get_rate_limiter().check(f'{client_ip}:{target_host}')
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded for host '{target_host}'.",
            headers={'Retry-After': str(retry_after)},
        )

    return target_host, get_policy_config()


def build_policy_summary(policy: dict[str, Any]) -> dict[str, Any]:
    checks = policy.get('checks', {})
    inventory = checks.get('endpoint_inventory', {})
    authz = checks.get('authorization_matrix', {})
    return {
        'name': policy.get('name', 'safe-production'),
        'destructive_tests': bool(policy.get('safety', {}).get('destructive_tests', False)),
        'rate_limit': policy.get('rate_limit', {}),
        'allowed_headers': list(REQUIRED_HEADERS),
        'enabled_checks': list(checks.keys()),
        'inventory_limits': {
            'max_pages': int(inventory.get('max_pages', 10)),
            'max_depth': int(inventory.get('max_depth', 2)),
        },
        'authorization_matrix': {
            'max_endpoints': int(authz.get('max_endpoints', 20)),
            'compare_headers': list(authz.get('compare_headers', [])),
            'profiles': list((authz.get('profiles') or {}).keys()),
        },
    }


app = FastAPI(
    title='Web PT Control Plane',
    description='Safe and auditable control plane for non-destructive web checks.',
    version='0.4.0',
)


@app.get('/scan')
def scan(
    request: Request,
    url: str = Query(..., description='Absolute http(s) URL to a host that is in scope.'),
) -> dict[str, Any]:
    target_host, policy = authorize_target_request(request, url)
    network = policy.get('network', {})

    try:
        snapshot = fetch_response_snapshot(
            url,
            timeout_seconds=float(network.get('timeout_seconds', 10)),
            max_redirects=int(network.get('max_redirects', 5)),
            user_agent=str(network.get('user_agent', 'web-pt-control-plane/0.1')),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f'Unable to retrieve target URL safely: {exc}',
        ) from exc

    security_headers = evaluate_security_headers(snapshot)
    cookie_security = inspect_cookie_security(snapshot)
    cors = inspect_cors_configuration(snapshot)
    transport = inspect_transport_security(snapshot)

    return {
        'target': {'url': url, 'host': target_host, 'in_scope': True},
        'policy': build_policy_summary(policy),
        'result': {
            'requested_url': snapshot.requested_url,
            'final_url': snapshot.final_url,
            'status_code': snapshot.status_code,
            'security_headers': security_headers.to_dict(),
            'cookie_security': cookie_security.to_dict(),
            'cors': cors.to_dict(),
            'transport': transport.to_dict(),
        },
    }


@app.get('/inventory')
def inventory(
    request: Request,
    url: str = Query(..., description='Absolute http(s) URL to a host that is in scope.'),
) -> dict[str, Any]:
    target_host, policy = authorize_target_request(request, url)
    network = policy.get('network', {})
    inventory_config = policy.get('checks', {}).get('endpoint_inventory', {})

    try:
        report = crawl_inventory(
            url,
            allowed_hosts=get_allowed_hosts(),
            timeout_seconds=float(network.get('timeout_seconds', 10)),
            max_redirects=int(network.get('max_redirects', 5)),
            user_agent=str(network.get('user_agent', 'web-pt-control-plane/0.1')),
            max_pages=int(inventory_config.get('max_pages', 10)),
            max_depth=int(inventory_config.get('max_depth', 2)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f'Unable to inventory target URL safely: {exc}') from exc

    return {
        'target': {'url': url, 'host': target_host, 'in_scope': True},
        'policy': build_policy_summary(policy),
        'result': report.to_dict(),
    }


@app.get('/authz/analyze')
def authz_analyze(
    request: Request,
    url: str = Query(..., description='Absolute http(s) URL to a host that is in scope.'),
) -> dict[str, Any]:
    target_host, policy = authorize_target_request(request, url)
    network = policy.get('network', {})
    authz_config = policy.get('checks', {}).get('authorization_matrix', {})
    inventory_config = policy.get('checks', {}).get('endpoint_inventory', {})

    try:
        report = analyze_authorization_matrix(
            seed_url=url,
            allowed_hosts=get_allowed_hosts(),
            timeout_seconds=float(network.get('timeout_seconds', 10)),
            max_redirects=int(network.get('max_redirects', 5)),
            user_agent=str(network.get('user_agent', 'web-pt-control-plane/0.1')),
            inventory_max_pages=int(inventory_config.get('max_pages', 10)),
            inventory_max_depth=int(inventory_config.get('max_depth', 2)),
            max_endpoints=int(authz_config.get('max_endpoints', 20)),
            compare_headers=list(authz_config.get('compare_headers', [])),
            body_markers=list(authz_config.get('body_markers', [])),
            profiles=authz_config.get('profiles', {}),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f'Unable to analyze authorization safely: {exc}') from exc

    return {
        'target': {'url': url, 'host': target_host, 'in_scope': True},
        'policy': build_policy_summary(policy),
        'result': report.to_dict(),
    }
