from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

REQUIRED_HEADERS = (
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
)


@dataclass(frozen=True)
class HeaderFinding:
    header: str
    present: bool
    value: str | None
    message: str


@dataclass(frozen=True)
class HeaderCheckReport:
    url: str
    final_url: str
    status_code: int
    findings: list[HeaderFinding]

    @property
    def passed(self) -> bool:
        return all(finding.present for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "passed": self.passed,
            "findings": [asdict(finding) for finding in self.findings],
        }


def evaluate_security_headers(headers: Mapping[str, str]) -> list[HeaderFinding]:
    normalized = {key.lower(): value for key, value in headers.items()}
    findings: list[HeaderFinding] = []

    for header in REQUIRED_HEADERS:
        value = normalized.get(header.lower())
        findings.append(
            HeaderFinding(
                header=header,
                present=bool(value),
                value=value,
                message=(
                    f"{header} is present."
                    if value
                    else f"{header} is missing from the HTTP response."
                ),
            )
        )

    return findings


def run_security_headers_check(
    url: str,
    *,
    timeout_seconds: float = 10.0,
    max_redirects: int = 5,
    user_agent: str = "web-pt-control-plane/0.1",
) -> HeaderCheckReport:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must be an absolute http:// or https:// target.")

    with httpx.Client(
        follow_redirects=True,
        headers={"User-Agent": user_agent},
        max_redirects=max_redirects,
        timeout=timeout_seconds,
    ) as client:
        response = client.get(url)

    return HeaderCheckReport(
        url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        findings=evaluate_security_headers(response.headers),
    )
