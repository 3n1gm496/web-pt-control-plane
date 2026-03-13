from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from checks.http_probe import ResponseSnapshot

REQUIRED_HEADERS = (
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Strict-Transport-Security',
    'Referrer-Policy',
)


@dataclass(frozen=True)
class HeaderFinding:
    header: str
    present: bool
    value: str | None
    message: str


@dataclass(frozen=True)
class HeaderCheckReport:
    findings: list[HeaderFinding]

    @property
    def passed(self) -> bool:
        return all(finding.present for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        missing_headers = [finding.header for finding in self.findings if not finding.present]
        return {
            'passed': self.passed,
            'missing_headers': missing_headers,
            'findings': [asdict(finding) for finding in self.findings],
        }


def evaluate_security_headers(snapshot: ResponseSnapshot) -> HeaderCheckReport:
    findings: list[HeaderFinding] = []

    for header in REQUIRED_HEADERS:
        values = [value for value in snapshot.header_values(header) if value.strip()]
        findings.append(
            HeaderFinding(
                header=header,
                present=bool(values),
                value=', '.join(values) if values else None,
                message=(
                    f'{header} is present.'
                    if values
                    else f'{header} is missing from the HTTP response.'
                ),
            )
        )

    return HeaderCheckReport(findings=findings)
