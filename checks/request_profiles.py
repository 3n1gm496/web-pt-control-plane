from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ENV_PATTERN = re.compile(r'^\$\{([A-Z0-9_]+)(?::-([^}]*))?\}$')
EXPECTED_PROFILES = ('guest', 'user', 'admin')


@dataclass(frozen=True)
class RequestProfile:
    name: str
    headers: dict[str, str]
    cookies: dict[str, str]
    bearer_token: str | None
    loaded: bool
    source: str | None

    def to_headers(self) -> dict[str, str]:
        headers = dict(self.headers)
        if self.bearer_token and 'Authorization' not in headers:
            headers['Authorization'] = f'Bearer {self.bearer_token}'
        return headers


def substitute_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): substitute_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute_env(item) for item in value]
    if isinstance(value, str):
        match = ENV_PATTERN.match(value)
        if match:
            variable_name, default_value = match.groups()
            return os.getenv(variable_name, default_value or '')
    return value


def load_request_profile(path: Path, name: str) -> RequestProfile:
    if not path.exists():
        return RequestProfile(name=name, headers={}, cookies={}, bearer_token=None, loaded=False, source=None)

    raw_config = yaml.safe_load(path.read_text(encoding='utf-8')) or {}
    config = substitute_env(raw_config)
    return RequestProfile(
        name=name,
        headers={str(key): str(value) for key, value in (config.get('headers') or {}).items() if value != ''},
        cookies={str(key): str(value) for key, value in (config.get('cookies') or {}).items() if value != ''},
        bearer_token=str(config.get('bearer_token')) if config.get('bearer_token') else None,
        loaded=True,
        source=str(path.name),
    )


def load_request_profiles(directory: Path, expected_profiles: tuple[str, ...] = EXPECTED_PROFILES) -> list[RequestProfile]:
    return [load_request_profile(directory / f'{name}.yaml', name) for name in expected_profiles]
