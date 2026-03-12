# Web PT Control Plane

Minimal FastAPI control plane for safe, non-destructive checks against public websites you own.

## Safety model

- Targets must be explicitly listed in `scope/production.yaml`.
- The API enforces an in-memory rate limit from `policies/safe-production.yaml`.
- Only passive HTTP header checks are enabled.
- No destructive or state-changing tests are included.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn api.main:app --reload
```

Example request:

```bash
curl 'http://127.0.0.1:8000/scan?url=https://example.com/'
```

Before using it on production, replace the placeholder hosts in `scope/production.yaml` with domains you control.
