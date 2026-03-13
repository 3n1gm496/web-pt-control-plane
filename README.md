# Web PT Control Plane

Minimal FastAPI control plane for safe, non-destructive checks against public websites you own.

## Safety model

- Targets must be explicitly listed in `scope/production.yaml`.
- The API enforces an in-memory rate limit from `policies/safe-production.yaml`.
- Only passive HTTP checks are enabled.
- No brute force, fuzzing, state-changing, or destructive tests are included.

## Passive checks

- Security headers: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`
- Cookie security: `Secure`, `HttpOnly`, `SameSite` on each `Set-Cookie`
- CORS inspection: `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Vary`
- Transport behavior: HTTPS usage, safe HTTP-to-HTTPS redirect detection, HSTS reporting

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn api.main:app --reload
```

## Example requests

HTTPS target:

```bash
curl 'http://127.0.0.1:8000/scan?url=https://example.com/'
```

HTTP target to verify redirect behavior safely:

```bash
curl 'http://127.0.0.1:8000/scan?url=http://example.com/'
```

Example response shape:

```json
{
  "target": {
    "url": "https://example.com/",
    "host": "example.com",
    "in_scope": true
  },
  "result": {
    "requested_url": "https://example.com/",
    "final_url": "https://example.com/",
    "status_code": 200,
    "security_headers": {
      "passed": true,
      "missing_headers": [],
      "findings": []
    },
    "cookie_security": {
      "cookies_observed": 2,
      "passed": false,
      "findings": [
        {
          "name": "sessionid",
          "secure": true,
          "http_only": true,
          "same_site": "Lax",
          "missing_attributes": []
        },
        {
          "name": "prefs",
          "secure": false,
          "http_only": true,
          "same_site": null,
          "missing_attributes": ["Secure", "SameSite"]
        }
      ]
    },
    "cors": {
      "enabled": true,
      "access_control_allow_origin": "https://app.example.com",
      "access_control_allow_credentials": "true",
      "vary": [],
      "findings": [
        {
          "level": "warning",
          "message": "Credentialed CORS response is missing 'Vary: Origin'."
        }
      ]
    },
    "transport": {
      "requested_scheme": "https",
      "final_scheme": "https",
      "uses_https": true,
      "redirects_to_https": false,
      "redirect_count": 0,
      "hsts": {
        "present": true,
        "value": "max-age=63072000; includeSubDomains"
      },
      "findings": []
    }
  }
}
```

Before using it on production, replace the placeholder hosts in `scope/production.yaml` with domains you control.
