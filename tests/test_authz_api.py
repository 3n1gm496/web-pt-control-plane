from fastapi.testclient import TestClient

from api import main as app_main
from checks.authz_matrix import AuthorizationMatrixReport, AuthzFinding, EndpointAuthzReport, EndpointClassification, ProfileObservation
from checks.endpoint_inventory import InventoryEndpoint, InventoryReport

client = TestClient(app_main.app)


def fake_report(seed_url: str) -> AuthorizationMatrixReport:
    inventory = InventoryReport(
        seed_url=seed_url,
        pages_crawled=2,
        endpoints=[
            InventoryEndpoint(
                url='https://example.com/admin',
                requested_url='https://example.com/admin',
                status_code=200,
                content_type='text/html; charset=utf-8',
                title='Admin',
                depth=1,
            )
        ],
    )
    finding = AuthzFinding(
        severity='medium',
        title='Privileged endpoint looks equally reachable to guest',
        detail='Guest and admin received the same status code and redirect behavior on a privileged endpoint.',
        endpoint='https://example.com/admin',
        profiles=['guest', 'admin'],
    )
    endpoint = EndpointAuthzReport(
        endpoint='https://example.com/admin',
        requested_url='https://example.com/admin',
        classification=EndpointClassification(
            category='privileged',
            tags=['privileged'],
            rationale=["Path contains 'admin'."],
        ),
        observations=[
            ProfileObservation('guest', 200, None, 1200, {'location': None}, {'login': False}),
            ProfileObservation('user', 200, None, 1200, {'location': None}, {'login': False}),
            ProfileObservation('admin', 200, None, 1200, {'location': None}, {'login': False}),
        ],
        findings=[finding],
    )
    return AuthorizationMatrixReport(
        seed_url=seed_url,
        inventory=inventory,
        profiles=['guest', 'user', 'admin'],
        endpoints_analyzed=1,
        findings=[finding],
        endpoints=[endpoint],
    )


def test_authz_rejects_out_of_scope_host() -> None:
    response = client.get('/authz/analyze', params={'url': 'https://not-allowed.example/'})

    assert response.status_code == 403
    assert 'scope/production.yaml' in response.json()['detail']


def test_authz_returns_structured_results(monkeypatch) -> None:
    monkeypatch.setattr(app_main, 'analyze_authorization_matrix', lambda seed_url, **_: fake_report(seed_url))
    monkeypatch.setattr(
        app_main,
        'get_rate_limiter',
        lambda: app_main.InMemoryRateLimiter(limit=10, window_seconds=60, clock=lambda: 100.0),
    )

    response = client.get('/authz/analyze', params={'url': 'https://example.com/'})

    assert response.status_code == 200
    payload = response.json()
    assert payload['result']['profiles'] == ['guest', 'user', 'admin']
    assert payload['result']['endpoints_analyzed'] == 1
    assert payload['result']['findings'][0]['severity'] == 'medium'
    assert payload['policy']['authorization_matrix']['profiles'] == ['guest', 'user', 'admin']


def test_authz_applies_rate_limit(monkeypatch) -> None:
    limiter = app_main.InMemoryRateLimiter(limit=1, window_seconds=60, clock=lambda: 100.0)
    monkeypatch.setattr(app_main, 'get_rate_limiter', lambda: limiter)
    monkeypatch.setattr(app_main, 'analyze_authorization_matrix', lambda seed_url, **_: fake_report(seed_url))

    first = client.get('/authz/analyze', params={'url': 'https://example.com/'})
    second = client.get('/authz/analyze', params={'url': 'https://example.com/'})

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers['retry-after'] == '60'
