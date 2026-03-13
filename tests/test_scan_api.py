from fastapi.testclient import TestClient

from api import main as app_main
from checks.http_probe import ResponseSnapshot

client = TestClient(app_main.app)


def make_snapshot(
    requested_url: str,
    final_url: str,
    headers: dict[str, list[str]],
    *,
    status_code: int = 200,
    redirect_count: int = 0,
) -> ResponseSnapshot:
    return ResponseSnapshot(
        requested_url=requested_url,
        final_url=final_url,
        status_code=status_code,
        headers={key.lower(): value for key, value in headers.items()},
        redirect_count=redirect_count,
    )


def test_scan_rejects_out_of_scope_host() -> None:
    response = client.get('/scan', params={'url': 'https://not-allowed.example/'})

    assert response.status_code == 403
    assert 'scope/production.yaml' in response.json()['detail']


def test_scan_returns_all_passive_checks(monkeypatch) -> None:
    monkeypatch.setattr(
        app_main,
        'fetch_response_snapshot',
        lambda url, **_: make_snapshot(
            requested_url=url,
            final_url='https://example.com/',
            headers={
                'content-security-policy': ["default-src 'self'"],
                'x-frame-options': ['DENY'],
                'x-content-type-options': ['nosniff'],
                'strict-transport-security': ['max-age=63072000; includeSubDomains'],
                'referrer-policy': ['strict-origin-when-cross-origin'],
                'set-cookie': [
                    'sessionid=abc; Secure; HttpOnly; SameSite=Lax',
                    'prefs=dark; HttpOnly',
                ],
                'access-control-allow-origin': ['https://app.example.com'],
                'access-control-allow-credentials': ['true'],
            },
        ),
    )
    monkeypatch.setattr(
        app_main,
        'get_rate_limiter',
        lambda: app_main.InMemoryRateLimiter(limit=10, window_seconds=60, clock=lambda: 100.0),
    )

    response = client.get('/scan', params={'url': 'https://example.com/'})

    assert response.status_code == 200
    payload = response.json()
    assert payload['result']['security_headers']['passed'] is True
    assert payload['result']['cookie_security']['cookies_observed'] == 2
    assert payload['result']['cookie_security']['findings'][1]['missing_attributes'] == ['Secure', 'SameSite']
    assert payload['result']['cors']['enabled'] is True
    assert payload['result']['cors']['findings'][0]['level'] == 'warning'
    assert payload['result']['transport']['uses_https'] is True
    assert payload['result']['transport']['hsts']['present'] is True


def test_scan_reports_http_to_https_redirect(monkeypatch) -> None:
    monkeypatch.setattr(
        app_main,
        'fetch_response_snapshot',
        lambda url, **_: make_snapshot(
            requested_url=url,
            final_url='https://example.com/login',
            headers={
                'location': ['https://example.com/login'],
                'strict-transport-security': ['max-age=63072000'],
            },
            redirect_count=1,
        ),
    )
    monkeypatch.setattr(
        app_main,
        'get_rate_limiter',
        lambda: app_main.InMemoryRateLimiter(limit=10, window_seconds=60, clock=lambda: 100.0),
    )

    response = client.get('/scan', params={'url': 'http://example.com/'})

    assert response.status_code == 200
    transport = response.json()['result']['transport']
    assert transport['requested_scheme'] == 'http'
    assert transport['final_scheme'] == 'https'
    assert transport['redirects_to_https'] is True
    assert transport['hsts']['present'] is True


def test_scan_applies_rate_limit(monkeypatch) -> None:
    limiter = app_main.InMemoryRateLimiter(limit=1, window_seconds=60, clock=lambda: 100.0)
    monkeypatch.setattr(app_main, 'get_rate_limiter', lambda: limiter)
    monkeypatch.setattr(
        app_main,
        'fetch_response_snapshot',
        lambda url, **_: make_snapshot(
            requested_url=url,
            final_url=url,
            headers={'strict-transport-security': ['max-age=63072000']},
        ),
    )

    first = client.get('/scan', params={'url': 'https://example.com/'})
    second = client.get('/scan', params={'url': 'https://example.com/'})

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers['retry-after'] == '60'
