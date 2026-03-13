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

## Request profiles

`profiles/` contains one YAML file per role profile:

- `profiles/guest.yaml`
- `profiles/user.yaml`
- `profiles/admin.yaml`

Each profile supports:

- `headers`
- `cookies`
- `bearer_token`

Environment-variable substitution keeps secrets out of git. Example:

```yaml
headers:
  X-Debug-Role: admin
cookies:
  session: ${ADMIN_SESSION:-}
bearer_token: ${ADMIN_BEARER_TOKEN:-}
```

Missing profiles degrade gracefully: the authz layer still runs and marks that profile as not loaded in the policy summary and endpoint observations.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export USER_SESSION='...'
export ADMIN_BEARER_TOKEN='...'
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
- Loads configurable `guest`, `user` and `admin` profiles from `profiles/`.
- Does not implement login automation; profile headers, cookies and bearer tokens are manual inputs.
- Compares status code, redirect location, content length, selected headers and simple body markers.
- Classifies endpoints into likely public, authenticated, privileged and object-reference candidates.
- Returns candidate findings to guide manual review for broken access control and IDOR.
- Stays non-destructive by using safe GET requests only.

Before using it on production, replace the placeholder hosts in `scope/production.yaml` with domains you control and populate any profile-specific headers, cookies or bearer tokens you intend to compare.
