from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from checks.http_probe import ResponseSnapshot


@dataclass(frozen=True)
class CookieFinding:
    name: str
    secure: bool
    http_only: bool
    same_site: str | None
    missing_attributes: list[str]


@dataclass(frozen=True)
class CookieSecurityReport:
    findings: list[CookieFinding]

    @property
    def cookies_observed(self) -> int:
        return len(self.findings)

    @property
    def passed(self) -> bool:
        return all(not finding.missing_attributes for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            'cookies_observed': self.cookies_observed,
            'passed': self.passed,
            'findings': [asdict(finding) for finding in self.findings],
        }


def inspect_cookie_security(snapshot: ResponseSnapshot) -> CookieSecurityReport:
    findings: list[CookieFinding] = []

    for header_value in snapshot.header_values('Set-Cookie'):
        parts = [part.strip() for part in header_value.split(';') if part.strip()]
        if not parts:
            continue

        cookie_name = parts[0].split('=', 1)[0].strip()
        attributes: dict[str, str | bool] = {}
        for part in parts[1:]:
            if '=' in part:
                key, value = part.split('=', 1)
                attributes[key.strip().lower()] = value.strip()
            else:
                attributes[part.strip().lower()] = True

        same_site = attributes.get('samesite')
        same_site_value = str(same_site) if isinstance(same_site, str) else None
        missing_attributes: list[str] = []
        if 'secure' not in attributes:
            missing_attributes.append('Secure')
        if 'httponly' not in attributes:
            missing_attributes.append('HttpOnly')
        if same_site_value is None:
            missing_attributes.append('SameSite')

        findings.append(
            CookieFinding(
                name=cookie_name or '<unknown>',
                secure='secure' in attributes,
                http_only='httponly' in attributes,
                same_site=same_site_value,
                missing_attributes=missing_attributes,
            )
        )

    return CookieSecurityReport(findings=findings)
