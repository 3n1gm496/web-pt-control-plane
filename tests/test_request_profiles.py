from pathlib import Path

from checks.request_profiles import load_request_profile, load_request_profiles


def test_load_request_profile_substitutes_environment_variables(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv('ADMIN_BEARER_TOKEN', 'secret-token')
    monkeypatch.setenv('ADMIN_SESSION', 'cookie-value')
    profile_path = tmp_path / 'admin.yaml'
    dollar = '$'
    profile_path.write_text(
        (
            'headers:\n'
            '  X-Role: admin\n'
            'cookies:\n'
            f'  session: {dollar}{{ADMIN_SESSION:-}}\n'
            f'bearer_token: {dollar}{{ADMIN_BEARER_TOKEN:-}}\n'
        ),
        encoding='utf-8',
    )

    profile = load_request_profile(profile_path, 'admin')

    assert profile.loaded is True
    assert profile.cookies['session'] == 'cookie-value'
    assert profile.to_headers()['Authorization'] == 'Bearer secret-token'


def test_load_request_profiles_degrades_gracefully_for_missing_profile(tmp_path: Path) -> None:
    (tmp_path / 'guest.yaml').write_text('headers: {}\ncookies: {}\n', encoding='utf-8')

    profiles = load_request_profiles(tmp_path)
    by_name = {profile.name: profile for profile in profiles}

    assert by_name['guest'].loaded is True
    assert by_name['user'].loaded is False
    assert by_name['admin'].loaded is False
