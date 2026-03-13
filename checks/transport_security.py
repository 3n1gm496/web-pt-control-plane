from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import httpx

from checks.http_probe import ResponseSnapshot


@dataclass(frozen=True)
class TransportFinding:
    level: str
    message: str


@dataclass(frozen=True)
class TransportInspectionReport:
    requested_scheme: str
    final_scheme: str
    uses_https: bool
    redirects_to_https: bool
    redirect_count: int
    hsts_present: bool
    hsts_value: str | None
    findings: list[TransportFinding]

    def to_dict(self) -> dict[str, Any]:
        return {
            'requested_scheme': self.requested_scheme,
            'final_scheme': self.final_scheme,
            'uses_https': self.uses_https,
            'redirects_to_https': self.redirects_to_https,
            'redirect_count': self.redirect_count,
            'hsts': {
                'present': self.hsts_present,
                'value': self.hsts_value,
            },
            'findings': [asdict(finding) for finding in self.findings],
        }


def inspect_transport_security(snapshot: ResponseSnapshot) -> TransportInspectionReport:
    requested_scheme = httpx.URL(snapshot.requested_url).scheme
    final_scheme = httpx.URL(snapshot.final_url).scheme
    uses_https = final_scheme == 'https'
    redirects_to_https = requested_scheme == 'http' and final_scheme == 'https'
    hsts_value = snapshot.first_header('Strict-Transport-Security')
    findings: list[TransportFinding] = []

    if requested_scheme == 'http':
        if redirects_to_https:
            findings.append(
                TransportFinding(level='info', message='HTTP target redirected to HTTPS.')
            )
        else:
            findings.append(
                TransportFinding(level='warning', message='HTTP target did not redirect to HTTPS.')
            )

    if requested_scheme == 'https' and not uses_https:
        findings.append(
            TransportFinding(level='warning', message='HTTPS target resolved to a non-HTTPS final response.')
        )

    if uses_https and hsts_value:
        findings.append(
            TransportFinding(
                level='info',
                message='HTTPS response includes Strict-Transport-Security.',
            )
        )
    elif uses_https:
        findings.append(
            TransportFinding(
                level='warning',
                message='HTTPS response is missing Strict-Transport-Security.',
            )
        )

    return TransportInspectionReport(
        requested_scheme=requested_scheme,
        final_scheme=final_scheme,
        uses_https=uses_https,
        redirects_to_https=redirects_to_https,
        redirect_count=snapshot.redirect_count,
        hsts_present=hsts_value is not None,
        hsts_value=hsts_value,
        findings=findings,
    )
