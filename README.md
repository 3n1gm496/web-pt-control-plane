# Web PT Control Plane

Minimal FastAPI control plane for safe, non-destructive checks against public websites you own.

## Safety model

- Targets must be explicitly listed in `scope/production.yaml`.
- The API enforces an in-memory rate limit from `policies/safe-production.yaml`.
- Only passive HTTP checks are enabled.
- No brute force, fuzzing, login automation, form submission, state-changing, or destructive tests are included.

## Passive checks

- Security headers: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`
- Cookie security: `Secure`, `HttpOnly`, `SameSite` on each `Set-Cookie`
- CORS inspection: `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Vary`
- Transport behavior: HTTPS usage, safe HTTP-to-HTTPS redirect detection, HSTS reporting
- Endpoint inventory: lightweight in-scope crawling with normalized URL deduplication, status code, content type and page title where available
- Authorization matrix: passive-first profile comparison on in-scope inventory endpoints to highlight candidate broken access control and IDOR cases

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn api.main:app --reload
```

## Example requests

Passive scan:

```bash
curl 'http://127.0.0.1:8000/scan?url=https://example.com/'
```

Lightweight endpoint inventory:

```bash
curl 'http://127.0.0.1:8000/inventory?url=https://example.com/'
```

Authorization matrix analysis:

```bash
curl 'http://127.0.0.1:8000/authz/analyze?url=https://example.com/'
```

## Authorization matrix behavior

- Reuses only URLs already discovered by the in-scope inventory module.
- Supports configurable `guest`, `user` and `admin` profiles in `policies/safe-production.yaml`.
- Does not implement login automation; profile headers and cookies are placeholders for manual configuration.
- Compares status code, redirect location, content length, selected headers and simple body markers.
- Classifies endpoints into likely public, authenticated, privileged and object-reference candidates.
- Returns candidate findings to guide manual review for broken access control and IDOR.

Example authz response shape:

```json
{
  "target": {
    "url": "https://example.com/",
    "host": "example.com",
    "in_scope": true
  },
  "result": {
    "profiles": ["guest", "user", "admin"],
    "endpoints_analyzed": 1,
    "findings": [
      {
        "severity": "medium",
        "title": "Privileged endpoint looks equally reachable to guest",
        "detail": "Guest and admin received the same status code and redirect behavior on a privileged endpoint.",
        "endpoint": "https://example.com/admin",
        "profiles": ["guest", "admin"]
      }
    ],
    "endpoints": [
      {
        "endpoint": "https://example.com/admin",
        "classification": {
          "category": "privileged",
          "tags": ["privileged"],
          "rationale": ["Path contains 'admin'."]
        },
        "observations": []
      }
    ]
  }
}
```

Before using it on production, replace the placeholder hosts in `scope/production.yaml` with domains you control and populate any profile-specific headers or cookies you intend to compare.
