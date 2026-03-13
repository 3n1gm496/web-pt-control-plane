from fastapi.testclient import TestClient

from api import main as app_main
from checks.endpoint_inventory import InventoryEndpoint, InventoryReport

client = TestClient(app_main.app)


def fake_report(seed_url: str) -> InventoryReport:
    return InventoryReport(
        seed_url=seed_url,
        pages_crawled=2,
        endpoints=[
            InventoryEndpoint(
                url='https://example.com/',
                requested_url='https://example.com/',
                status_code=200,
                content_type='text/html; charset=utf-8',
                title='Home',
                depth=0,
            ),
            InventoryEndpoint(
                url='https://example.com/about',
                requested_url='https://example.com/about',
                status_code=200,
                content_type='text/html; charset=utf-8',
                title='About',
                depth=1,
            ),
        ],
    )


def test_inventory_rejects_out_of_scope_host() -> None:
    response = client.get('/inventory', params={'url': 'https://not-allowed.example/'})

    assert response.status_code == 403
    assert 'scope/production.yaml' in response.json()['detail']


def test_inventory_returns_structured_results(monkeypatch) -> None:
    monkeypatch.setattr(app_main, 'crawl_inventory', lambda url, **_: fake_report(url))
    monkeypatch.setattr(
        app_main,
        'get_rate_limiter',
        lambda: app_main.InMemoryRateLimiter(limit=10, window_seconds=60, clock=lambda: 100.0),
    )

    response = client.get('/inventory', params={'url': 'https://example.com/'})

    assert response.status_code == 200
    payload = response.json()
    assert payload['result']['pages_crawled'] == 2
    assert payload['result']['endpoints_discovered'] == 2
    assert payload['result']['endpoints'][0]['url'] == 'https://example.com/'
    assert payload['policy']['inventory_limits'] == {'max_pages': 10, 'max_depth': 2}


def test_inventory_applies_rate_limit(monkeypatch) -> None:
    limiter = app_main.InMemoryRateLimiter(limit=1, window_seconds=60, clock=lambda: 100.0)
    monkeypatch.setattr(app_main, 'get_rate_limiter', lambda: limiter)
    monkeypatch.setattr(app_main, 'crawl_inventory', lambda url, **_: fake_report(url))

    first = client.get('/inventory', params={'url': 'https://example.com/'})
    second = client.get('/inventory', params={'url': 'https://example.com/'})

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers['retry-after'] == '60'
