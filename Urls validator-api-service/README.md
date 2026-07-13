# Social URL Status Checker — API-only build

Headless copy of the validation engine for server-to-server use (Java → this API).
Same detection logic as the full build; the web UI is removed.

## Run

```
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

## Primary endpoint (Java integration)

`POST /api/check/json`

```json
{ "urls": ["https://www.facebook.com/somepage", "https://t.me/somechannel"] }
```

Response:

```json
{
  "results": [
    {
      "url": "https://t.me/somechannel",
      "platform": "telegram",
      "status": "active | taken_down | uncertain",
      "reason": "human-readable explanation",
      "http_code": 200,
      "confidence": { "...optional..." },
      "signals": ["...optional..."],
      "metadata": { "...optional..." }
    }
  ]
}
```

**Integration notes for the Java side:**
- Max 500 URLs per request (HTTP 400 above that).
- Invalid URLs are dropped and duplicates collapsed before checking —
  **match results to inputs by `url`, not by index or count.**
- `uncertain` means the engine could not prove the status anonymously
  (usually a login wall); route those to manual review rather than
  treating them as active or taken down.
- Private/internal addresses are refused by the SSRF guard and return
  `uncertain` with an explanatory reason.

## Other endpoints

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Liveness + feature flags + circuit breaker state |
| `POST /api/check` | Same check as Server-Sent Events stream (progress events) |
| `GET /api/metrics` | Throughput, timing percentiles, status breakdown |
| `POST /api/export` | Turn a results array into a ZIP with report.csv |
| `GET/POST /api/cookies` | Read/save platform session cookies used by checkers |

## Configuration (environment variables)

- `URLCHECK_ALLOWED_ORIGINS` — comma-separated browser origins allowed via CORS
  (leave unset for server-to-server only; Java is unaffected by CORS).
- `URLCHECK_CONCURRENT`, `URLCHECK_TIMEOUT`, `URLCHECK_ENABLE_*` — see `backend/config.py`.

## Deployment notes

- Deploy from a normal folder (not OneDrive/Dropbox): `cookies.json` holds
  session tokens and must not sync to cloud storage.
- Restrict network access to the API to the Java service (firewall/security
  group); the API itself has no authentication.
