from fastapi.testclient import TestClient

from api import main as app_main
from checks.security_headers import HeaderCheckReport, HeaderFinding

client = TestClient(app_main.app)


def fake_report(url: str) -> HeaderCheckReport:
    return HeaderCheckReport(
        url=url,
        final_url=url,
        status_code=200,
        findings=[
            HeaderFinding(
                header="Content-Security-Policy",
                present=True,
                value="default-src 'self'",
                message="Content-Security-Policy is present.",
            ),
            HeaderFinding(
                header="X-Frame-Options",
                present=True,
                value="DENY",
                message="X-Frame-Options is present.",
            ),
            HeaderFinding(
                header="X-Content-Type-Options",
                present=True,
                value="nosniff",
                message="X-Content-Type-Options is present.",
            ),
            HeaderFinding(
                header="Strict-Transport-Security",
                present=True,
                value="max-age=63072000; includeSubDomains",
                message="Strict-Transport-Security is present.",
            ),
            HeaderFinding(
                header="Referrer-Policy",
                present=True,
                value="strict-origin-when-cross-origin",
                message="Referrer-Policy is present.",
            ),
        ],
    )


def test_scan_rejects_out_of_scope_host() -> None:
    response = client.get("/scan", params={"url": "https://not-allowed.example/"})

    assert response.status_code == 403
    assert "scope/production.yaml" in response.json()["detail"]


def test_scan_runs_header_check_for_allowed_host(monkeypatch) -> None:
    monkeypatch.setattr(
        app_main,
        "run_security_headers_check",
        lambda url, **_: fake_report(url),
    )

    response = client.get("/scan", params={"url": "https://example.com/"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["target"]["host"] == "example.com"
    assert payload["result"]["passed"] is True


def test_scan_applies_rate_limit(monkeypatch) -> None:
    limiter = app_main.InMemoryRateLimiter(limit=1, window_seconds=60, clock=lambda: 100.0)
    monkeypatch.setattr(app_main, "get_rate_limiter", lambda: limiter)
    monkeypatch.setattr(
        app_main,
        "run_security_headers_check",
        lambda url, **_: fake_report(url),
    )

    first = client.get("/scan", params={"url": "https://example.com/"})
    second = client.get("/scan", params={"url": "https://example.com/"})

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"] == "60"
