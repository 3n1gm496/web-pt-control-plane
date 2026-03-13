from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class ResponseSnapshot:
    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, list[str]]
    redirect_count: int
    body_text: str | None = None

    def header_values(self, name: str) -> list[str]:
        return list(self.headers.get(name.lower(), []))

    def first_header(self, name: str) -> str | None:
        values = self.header_values(name)
        return values[0] if values else None


def validate_absolute_http_url(url: str) -> None:
    request = httpx.Request('GET', url)
    if request.url.scheme not in {'http', 'https'} or not request.url.host:
        raise ValueError('URL must be an absolute http:// or https:// target.')


def fetch_response_snapshot(
    url: str,
    *,
    timeout_seconds: float = 10.0,
    max_redirects: int = 5,
    user_agent: str = 'web-pt-control-plane/0.1',
    include_body: bool = False,
) -> ResponseSnapshot:
    validate_absolute_http_url(url)

    with httpx.Client(
        follow_redirects=True,
        headers={'User-Agent': user_agent},
        max_redirects=max_redirects,
        timeout=timeout_seconds,
    ) as client:
        response = client.get(url)

    headers: dict[str, list[str]] = defaultdict(list)
    for name, value in response.headers.multi_items():
        headers[name.lower()].append(value)

    body_text = response.text if include_body else None
    return ResponseSnapshot(
        requested_url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        headers=dict(headers),
        redirect_count=len(response.history),
        body_text=body_text,
    )
