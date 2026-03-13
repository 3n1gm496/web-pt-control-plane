from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from checks.endpoint_inventory import InventoryEndpoint, InventoryReport, crawl_inventory

OBJECT_REFERENCE_SEGMENTS = {'user', 'users', 'order', 'orders', 'account', 'accounts'}
DEFAULT_BODY_MARKERS = ['login', 'sign in', 'unauthorized', 'forbidden', 'access denied', 'admin', 'dashboard']


@dataclass(frozen=True)
class RoleProfile:
    name: str
    headers: dict[str, str]
    cookies: dict[str, str]


@dataclass(frozen=True)
class EndpointClassification:
    category: str
    tags: list[str]
    rationale: list[str]


@dataclass(frozen=True)
class ProfileObservation:
    profile: str
    status_code: int
    redirect_location: str | None
    content_length: int
    selected_headers: dict[str, str | None]
    body_markers: dict[str, bool]


@dataclass(frozen=True)
class AuthzFinding:
    severity: str
    title: str
    detail: str
    endpoint: str
    profiles: list[str]


@dataclass(frozen=True)
class EndpointAuthzReport:
    endpoint: str
    requested_url: str
    classification: EndpointClassification
    observations: list[ProfileObservation]
    findings: list[AuthzFinding]


@dataclass(frozen=True)
class AuthorizationMatrixReport:
    seed_url: str
    inventory: InventoryReport
    profiles: list[str]
    endpoints_analyzed: int
    findings: list[AuthzFinding]
    endpoints: list[EndpointAuthzReport]

    def to_dict(self) -> dict[str, Any]:
        return {
            'seed_url': self.seed_url,
            'profiles': self.profiles,
            'endpoints_analyzed': self.endpoints_analyzed,
            'inventory': self.inventory.to_dict(),
            'findings': [asdict(finding) for finding in self.findings],
            'endpoints': [
                {
                    'endpoint': endpoint.endpoint,
                    'requested_url': endpoint.requested_url,
                    'classification': asdict(endpoint.classification),
                    'observations': [asdict(observation) for observation in endpoint.observations],
                    'findings': [asdict(finding) for finding in endpoint.findings],
                }
                for endpoint in self.endpoints
            ],
        }


def build_role_profiles(config: dict[str, Any] | None) -> list[RoleProfile]:
    config = config or {}
    profiles: list[RoleProfile] = []
    for name in ('guest', 'user', 'admin'):
        profile = config.get(name, {})
        profiles.append(
            RoleProfile(
                name=name,
                headers={str(key): str(value) for key, value in (profile.get('headers') or {}).items()},
                cookies={str(key): str(value) for key, value in (profile.get('cookies') or {}).items()},
            )
        )
    return profiles


def classify_endpoint(url: str) -> EndpointClassification:
    parsed = urlsplit(url)
    segments = [segment for segment in parsed.path.split('/') if segment]
    lowered_segments = [segment.lower() for segment in segments]
    tags: list[str] = []
    rationale: list[str] = []

    if not segments or parsed.path == '/':
        tags.append('likely_public')
        rationale.append('Root path is commonly public.')

    if any(segment == 'admin' for segment in lowered_segments):
        tags.append('privileged')
        rationale.append("Path contains 'admin'.")

    if lowered_segments and lowered_segments[0] == 'api':
        tags.append('api')
        rationale.append("Path begins with 'api'.")

    if any(segment in {'account', 'accounts', 'profile', 'settings'} for segment in lowered_segments):
        tags.append('authenticated')
        rationale.append('Path contains account-oriented keywords.')

    if any(segment in OBJECT_REFERENCE_SEGMENTS for segment in lowered_segments):
        tags.append('object-reference-candidate')
        rationale.append('Path suggests object-level access checks may be relevant.')

    if any(segment.isdigit() for segment in segments):
        tags.append('object-reference-candidate')
        rationale.append('Path contains a numeric identifier.')

    if any(len(segment) >= 8 and any(ch.isdigit() for ch in segment) for segment in segments):
        tags.append('object-reference-candidate')
        rationale.append('Path contains an identifier-like segment.')

    if not tags:
        tags.append('likely_public')
        rationale.append('No privileged or authenticated patterns were detected.')

    if 'privileged' in tags:
        category = 'privileged'
    elif 'authenticated' in tags:
        category = 'authenticated'
    elif 'object-reference-candidate' in tags:
        category = 'object-reference-candidate'
    else:
        category = 'public'

    return EndpointClassification(
        category=category,
        tags=list(dict.fromkeys(tags)),
        rationale=list(dict.fromkeys(rationale)),
    )


def fetch_profile_observation(
    client: httpx.Client,
    endpoint: InventoryEndpoint,
    profile: RoleProfile,
    compare_headers: list[str],
    body_markers: list[str],
) -> ProfileObservation:
    response = client.get(endpoint.url, headers=profile.headers, cookies=profile.cookies, follow_redirects=False)
    lowered_body = response.text.lower()
    return ProfileObservation(
        profile=profile.name,
        status_code=response.status_code,
        redirect_location=response.headers.get('Location'),
        content_length=len(response.text.encode('utf-8')),
        selected_headers={header: response.headers.get(header) for header in compare_headers},
        body_markers={marker: marker.lower() in lowered_body for marker in body_markers},
    )


def compare_observations(
    endpoint: InventoryEndpoint,
    classification: EndpointClassification,
    observations: list[ProfileObservation],
) -> list[AuthzFinding]:
    findings: list[AuthzFinding] = []
    by_profile = {observation.profile: observation for observation in observations}
    guest = by_profile.get('guest')
    user = by_profile.get('user')
    admin = by_profile.get('admin')

    if guest and admin and guest.status_code == admin.status_code and guest.redirect_location == admin.redirect_location:
        if 'privileged' in classification.tags:
            findings.append(
                AuthzFinding(
                    severity='medium',
                    title='Privileged endpoint looks equally reachable to guest',
                    detail='Guest and admin received the same status code and redirect behavior on a privileged endpoint.',
                    endpoint=endpoint.url,
                    profiles=['guest', 'admin'],
                )
            )

    if guest and user and guest.status_code == user.status_code and abs(guest.content_length - user.content_length) <= 32:
        if classification.category in {'authenticated', 'object-reference-candidate'}:
            findings.append(
                AuthzFinding(
                    severity='medium',
                    title='Authenticated-looking endpoint appears similar for guest and user',
                    detail='Guest and user responses are close in status and size for an endpoint that may require authentication.',
                    endpoint=endpoint.url,
                    profiles=['guest', 'user'],
                )
            )

    if 'object-reference-candidate' in classification.tags and guest and user:
        if guest.status_code != user.status_code or guest.body_markers != user.body_markers or guest.selected_headers != user.selected_headers:
            findings.append(
                AuthzFinding(
                    severity='medium',
                    title='Object-reference candidate varies across profiles',
                    detail='An object-like endpoint responded differently across profiles and may be worth manual IDOR review.',
                    endpoint=endpoint.url,
                    profiles=['guest', 'user'],
                )
            )

    if guest and user and admin:
        if len({guest.status_code, user.status_code, admin.status_code}) >= 2 or len({guest.redirect_location, user.redirect_location, admin.redirect_location}) >= 2:
            findings.append(
                AuthzFinding(
                    severity='info',
                    title='Endpoint response varies across profiles',
                    detail='Status code or redirect location differs across guest, user and admin.',
                    endpoint=endpoint.url,
                    profiles=['guest', 'user', 'admin'],
                )
            )

    return findings


def analyze_authorization_matrix(
    seed_url: str,
    *,
    allowed_hosts: set[str],
    timeout_seconds: float = 10.0,
    max_redirects: int = 5,
    user_agent: str = 'web-pt-control-plane/0.1',
    inventory_max_pages: int = 10,
    inventory_max_depth: int = 2,
    max_endpoints: int = 20,
    compare_headers: list[str] | None = None,
    body_markers: list[str] | None = None,
    profiles: dict[str, Any] | None = None,
) -> AuthorizationMatrixReport:
    inventory = crawl_inventory(
        seed_url,
        allowed_hosts=allowed_hosts,
        timeout_seconds=timeout_seconds,
        max_redirects=max_redirects,
        user_agent=user_agent,
        max_pages=inventory_max_pages,
        max_depth=inventory_max_depth,
    )

    role_profiles = build_role_profiles(profiles)
    headers_to_compare = compare_headers or ['cache-control', 'location', 'content-type']
    markers = body_markers or DEFAULT_BODY_MARKERS
    endpoints = inventory.endpoints[:max_endpoints]
    endpoint_reports: list[EndpointAuthzReport] = []
    all_findings: list[AuthzFinding] = []

    with httpx.Client(timeout=timeout_seconds, headers={'User-Agent': user_agent}) as client:
        for endpoint in endpoints:
            classification = classify_endpoint(endpoint.url)
            observations = [fetch_profile_observation(client, endpoint, profile, headers_to_compare, markers) for profile in role_profiles]
            findings = compare_observations(endpoint, classification, observations)
            all_findings.extend(findings)
            endpoint_reports.append(
                EndpointAuthzReport(
                    endpoint=endpoint.url,
                    requested_url=endpoint.requested_url,
                    classification=classification,
                    observations=observations,
                    findings=findings,
                )
            )

    return AuthorizationMatrixReport(
        seed_url=seed_url,
        inventory=inventory,
        profiles=[profile.name for profile in role_profiles],
        endpoints_analyzed=len(endpoint_reports),
        findings=all_findings,
        endpoints=endpoint_reports,
    )
