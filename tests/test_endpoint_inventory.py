from checks.endpoint_inventory import extract_in_scope_links, normalize_url
from checks.http_probe import ResponseSnapshot


def test_normalize_url_removes_fragment_and_default_port() -> None:
    assert normalize_url('HTTPS://Example.com:443/demo#section') == 'https://example.com/demo'


def test_extract_in_scope_links_normalizes_and_deduplicates() -> None:
    snapshot = ResponseSnapshot(
        requested_url='https://example.com/',
        final_url='https://example.com/',
        status_code=200,
        headers={'content-type': ['text/html; charset=utf-8']},
        redirect_count=0,
        body_text="""
            <html>
              <head><title>Demo</title></head>
              <body>
                <a href="/about#team">About</a>
                <a href="https://example.com:443/about">About again</a>
                <a href="https://cdn.example.com/app.js">Asset</a>
              </body>
            </html>
        """,
    )

    links = extract_in_scope_links(snapshot, allowed_hosts={'example.com'})

    assert links == ['https://example.com/about']
