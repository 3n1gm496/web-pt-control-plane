from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from checks.http_probe import ResponseSnapshot, validate_absolute_http_url

HTML_CONTENT_TYPES = ('text/html', 'application/xhtml+xml')


@dataclass(frozen=True)
class InventoryEndpoint:
    url: str
    requested_url: str
    status_code: int
    content_type: str | None
    title: str | None
    depth: int


@dataclass(frozen=True)
class InventoryReport:
    seed_url: str
    pages_crawled: int
    endpoints: list[InventoryEndpoint]

    def to_dict(self) -> dict[str, Any]:
        endpoints = sorted(self.endpoints, key=lambda endpoint: (endpoint.depth, endpoint.url))
        return {
            'seed_url': self.seed_url,
            'pages_crawled': self.pages_crawled,
            'endpoints_discovered': len(endpoints),
            'endpoints': [asdict(endpoint) for endpoint in endpoints],
        }


class InventoryHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self._title_parts: list[str] = []
        self._inside_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key: value for key, value in attrs}
        if tag in {'a', 'link'} and attributes.get('href'):
            self.links.append(attributes['href'])
        elif tag == 'title':
            self._inside_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == 'title':
            self._inside_title = False

    def handle_data(self, data: str) -> None:
        if self._inside_title:
            self._title_parts.append(data)

    @property
    def title(self) -> str | None:
        normalized = ' '.join(part.strip() for part in self._title_parts if part.strip()).strip()
        return normalized or None


def canonicalize_host(host: str | None) -> str:
    if not host:
        raise ValueError('URL must include a hostname.')
    return host.rstrip('.').lower()


def normalize_url(url: str) -> str:
    validate_absolute_http_url(url)
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = canonicalize_host(parsed.hostname)
    default_port = 443 if scheme == 'https' else 80
    if parsed.port and parsed.port != default_port:
        netloc = f'{host}:{parsed.port}'
    else:
        netloc = host
    path = parsed.path or '/'
    return urlunsplit((scheme, netloc, path, parsed.query, ''))


def is_allowed_url(url: str, allowed_hosts: set[str]) -> bool:
    parsed = urlsplit(url)
    return parsed.scheme in {'http', 'https'} and canonicalize_host(parsed.hostname) in allowed_hosts


def is_html_response(snapshot: ResponseSnapshot) -> bool:
    content_type = (snapshot.first_header('Content-Type') or '').lower()
    return any(content_type.startswith(prefix) for prefix in HTML_CONTENT_TYPES)


def extract_in_scope_links(snapshot: ResponseSnapshot, allowed_hosts: set[str]) -> list[str]:
    if not snapshot.body_text or not is_html_response(snapshot):
        return []

    parser = InventoryHTMLParser()
    parser.feed(snapshot.body_text)

    normalized_links: list[str] = []
    seen: set[str] = set()
    for link in parser.links:
        absolute_link = urljoin(snapshot.final_url, link)
        try:
            normalized = normalize_url(absolute_link)
        except ValueError:
            continue
        if not is_allowed_url(normalized, allowed_hosts):
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        normalized_links.append(normalized)

    return normalized_links


def extract_title(snapshot: ResponseSnapshot) -> str | None:
    if not snapshot.body_text or not is_html_response(snapshot):
        return None
    parser = InventoryHTMLParser()
    parser.feed(snapshot.body_text)
    return parser.title


def fetch_inventory_snapshot(
    client: httpx.Client,
    url: str,
    *,
    allowed_hosts: set[str],
    max_redirects: int,
) -> ResponseSnapshot:
    requested_url = normalize_url(url)
    current_url = requested_url
    redirect_count = 0

    while True:
        response = client.get(current_url)
        headers: dict[str, list[str]] = defaultdict(list)
        for name, value in response.headers.multi_items():
            headers[name.lower()].append(value)

        snapshot = ResponseSnapshot(
            requested_url=requested_url,
            final_url=str(response.url),
            status_code=response.status_code,
            headers=dict(headers),
            redirect_count=redirect_count,
            body_text=response.text,
        )

        if not response.is_redirect:
            return snapshot

        location = response.headers.get('Location')
        if not location or redirect_count >= max_redirects:
            return snapshot

        try:
            next_url = normalize_url(urljoin(str(response.url), location))
        except ValueError:
            return snapshot

        if not is_allowed_url(next_url, allowed_hosts):
            return snapshot

        current_url = next_url
        redirect_count += 1


def crawl_inventory(
    seed_url: str,
    *,
    allowed_hosts: set[str],
    timeout_seconds: float = 10.0,
    max_redirects: int = 5,
    user_agent: str = 'web-pt-control-plane/0.1',
    max_pages: int = 10,
    max_depth: int = 2,
) -> InventoryReport:
    normalized_seed = normalize_url(seed_url)
    if not is_allowed_url(normalized_seed, allowed_hosts):
        raise ValueError('Seed URL host is not allowed by scope/production.yaml.')

    queue: deque[tuple[str, int]] = deque([(normalized_seed, 0)])
    enqueued: set[str] = {normalized_seed}
    visited: set[str] = set()
    endpoints: dict[str, InventoryEndpoint] = {}
    pages_crawled = 0

    with httpx.Client(
        follow_redirects=False,
        headers={'User-Agent': user_agent},
        timeout=timeout_seconds,
    ) as client:
        while queue and pages_crawled < max_pages:
            current_url, depth = queue.popleft()
            if current_url in visited:
                continue
            visited.add(current_url)

            snapshot = fetch_inventory_snapshot(
                client,
                current_url,
                allowed_hosts=allowed_hosts,
                max_redirects=max_redirects,
            )
            pages_crawled += 1

            final_url = normalize_url(snapshot.final_url)
            endpoint = InventoryEndpoint(
                url=final_url,
                requested_url=current_url,
                status_code=snapshot.status_code,
                content_type=snapshot.first_header('Content-Type'),
                title=extract_title(snapshot),
                depth=depth,
            )
            endpoints.setdefault(final_url, endpoint)

            if depth >= max_depth:
                continue

            for link in extract_in_scope_links(snapshot, allowed_hosts):
                if link in visited or link in enqueued:
                    continue
                enqueued.add(link)
                queue.append((link, depth + 1))

    return InventoryReport(
        seed_url=normalized_seed,
        pages_crawled=pages_crawled,
        endpoints=list(endpoints.values()),
    )
