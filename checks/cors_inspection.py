from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from checks.http_probe import ResponseSnapshot


@dataclass(frozen=True)
class CorsFinding:
    level: str
    message: str


@dataclass(frozen=True)
class CorsInspectionReport:
    access_control_allow_origin: str | None
    access_control_allow_credentials: str | None
    vary: list[str]
    findings: list[CorsFinding]

    @property
    def enabled(self) -> bool:
        return bool(self.access_control_allow_origin or self.access_control_allow_credentials)

    def to_dict(self) -> dict[str, Any]:
        return {
            'enabled': self.enabled,
            'access_control_allow_origin': self.access_control_allow_origin,
            'access_control_allow_credentials': self.access_control_allow_credentials,
            'vary': self.vary,
            'findings': [asdict(finding) for finding in self.findings],
        }


def inspect_cors_configuration(snapshot: ResponseSnapshot) -> CorsInspectionReport:
    allow_origin = snapshot.first_header('Access-Control-Allow-Origin')
    allow_credentials = snapshot.first_header('Access-Control-Allow-Credentials')
    vary_values: list[str] = []
    vary_lookup: set[str] = set()

    for header_value in snapshot.header_values('Vary'):
        for token in header_value.split(','):
            normalized = token.strip()
            if not normalized:
                continue
            vary_values.append(normalized)
            vary_lookup.add(normalized.lower())

    findings: list[CorsFinding] = []
    credentials_enabled = (allow_credentials or '').lower() == 'true'

    if not allow_origin and not allow_credentials:
        findings.append(CorsFinding(level='info', message='No CORS response headers were observed.'))

    if allow_origin == '*':
        findings.append(
            CorsFinding(
                level='warning',
                message="Access-Control-Allow-Origin is wildcard ('*'), which is broadly permissive.",
            )
        )

    if allow_origin == 'null':
        findings.append(
            CorsFinding(
                level='warning',
                message="Access-Control-Allow-Origin is 'null', which is unusual and often unintended.",
            )
        )

    if credentials_enabled and not allow_origin:
        findings.append(
            CorsFinding(
                level='warning',
                message='Access-Control-Allow-Credentials is true without Access-Control-Allow-Origin.',
            )
        )
    elif credentials_enabled and allow_origin == '*':
        findings.append(
            CorsFinding(
                level='warning',
                message='Credentials are allowed while Access-Control-Allow-Origin is wildcard.',
            )
        )
    elif credentials_enabled and allow_origin and 'origin' not in vary_lookup:
        findings.append(
            CorsFinding(
                level='warning',
                message="Credentialed CORS response is missing 'Vary: Origin'.",
            )
        )

    return CorsInspectionReport(
        access_control_allow_origin=allow_origin,
        access_control_allow_credentials=allow_credentials,
        vary=vary_values,
        findings=findings,
    )
