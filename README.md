# Central Security API

The single, controlled entry point for every business application that uses LLMs.

Applications never talk to an LLM provider directly. They call `POST /api/v1/llm/process`; this service
authenticates the caller, checks what it is allowed to do, validates the request against policy, calls
the provider, validates the response, and records audit metadata before returning the result.

- [Overview](#overview) · [Architecture](#architecture) · [Quick start](#quick-start-local) · [Docker](#docker)
- [Configuration](#configuration) · [Authentication and roles](#authentication-and-roles) · [Database](#database-and-migrations)
- [Testing](#testing-and-quality-gates) · [API reference](#api-reference-with-examples) · [Errors](#error-model)
- [Audit](#audit-and-security-events) · [Operations](#operations) · [Limitations](#limitations-and-assumptions)

## Overview

| Concern | How it is handled |
|---|---|
| Who is calling | JWT validated on every request (signature, issuer, audience, expiry, algorithm allow-list). |
| What may they do | The token's `client_id` must map to an **approved service identity** bound to one project; the project must be granted the requested **task** and **model**. Body fields like `projectId` never override this. |
| Is the request safe | Schema, payload-size, request-rule, prompt-injection and rate-limit/quota checks run before the provider is called. |
| Is the response safe | Output is checked against size limits, content-security patterns and JSON Schemas before it is returned. |
| What happened | Every processed request writes a metadata-only record (no prompt or response text) and a hash-chained audit entry; every denial writes a security event. |
| When things break | The service **fails closed**: unavailable signing keys, database or audit store produce 503, never an unchecked pass-through. |

Out of scope (stays in each business application): business validation, source-data permissions,
workflow logic and human review. Production use still needs a threat model, security and privacy review
and organizational approval.

## Architecture

```
HTTP ──► middleware ──► routers ──► services ──► repositories ──► SQLite
          │               │            │
          │               │            └─► policy engine, provider gateway, rate limiter,
          │               │                audit chain, security-event recorder
          │               └─► dependencies: auth, roles, pagination, DI
          └─► request id · security headers · body-size limit · metrics · error rendering
```

| Layer | Path | Responsibility |
|---|---|---|
| API | `app/api/` | HTTP only: parsing, status codes, dependency injection, response models. |
| Services | `app/services/` | Business rules, orchestration, transaction boundaries, audit. |
| Repositories | `app/repositories/` | All database access; generic base with pagination and soft delete. |
| Schemas | `app/schemas/` | Pydantic models per purpose (create / update / read). ORM objects are never returned. |
| Models | `app/models/` | SQLAlchemy 2.0 typed models. |
| Core | `app/core/` | Settings, JWT validation, logging, exceptions, middleware, metrics. |

Dependencies point inward: routers → services → repositories → models/core.

### The processing pipeline (`POST /api/v1/llm/process`)

Each step that fails returns a standard error and records a security event. Nothing reaches the provider
until every check passes.

1. **Authenticate** the bearer token (401). Repeated failures from one IP are throttled (429).
2. **Resolve identity**: registered, `approved`, holds the `service` role, project active (403).
3. **Reject identity override**: a `projectId`/`team` in the body that differs from the registered values (403, critical event).
4. **Recognise task and model**: unknown or disabled names are 400; known but not granted to the project are 403.
5. **Payload size** against the task limit, counted in bytes (413).
6. **Request rules** (length, allowed parameters) from policies (400).
7. **Rate limits and quotas** per caller, team, project and task (429 with `Retry-After`).
8. **Reserve `requestId`**, unique per project (409 on repeat).
9. **Prompt-injection screening** with built-in rules plus stored policies (400).
10. **Provider call** with a time budget, bounded retries and a concurrency cap (503 / 504).
11. **Response validation** (502 `response-validation-failed`).
12. **Audit** the outcome in the same transaction as the request record; if it cannot be persisted the call fails with 503 and the result is withheld.

## Quick start (local)

Requires Python 3.12+. No database server is needed: the service uses SQLite.

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env                 # Windows: copy .env.example .env
```

Create a development key pair and tell the API to trust it (tokens come from your identity provider in
production; the key pair below stands in for it locally):

```bash
python -m scripts.mint_dev_token --client-id demo-app      # creates data/dev-keys/ on first use
echo "CS_JWT_PUBLIC_KEY_PATH=data/dev-keys/public.pem" >> .env
```

Migrate, seed a demo project, and run:

```bash
python -m alembic upgrade head       # or: make migrate
python -m scripts.seed               # or: make seed
python -m uvicorn app.main:create_app --factory --reload    # or: make run
```

Open <http://localhost:8000/docs>, or:

```bash
TOKEN=$(python -m scripts.mint_dev_token --client-id demo-app | head -1)
curl -s localhost:8000/api/v1/llm/process \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"requestId":"first-call","task":"summarize_document","model":"local-echo","input":"Summarize this."}'
```

An administrator token for the management APIs:

```bash
ADMIN=$(python -m scripts.mint_dev_token --client-id admin --roles governance_admin audit_reviewer | head -1)
```

## Docker

```bash
docker compose up --build
```

The image is multi-stage, runs as a non-root user, and starts with `alembic upgrade head` followed by
uvicorn. The SQLite file lives on the `api_data` volume. The container runs in `production` mode, so you
must supply a signing-key source (for example `CS_JWT_JWKS_URL` in `.env`); `/docs` is disabled.

> The compose service is a **single instance**. SQLite and the SQLite-backed rate limiter are correct
> for one host only; do not scale the service horizontally.

## Configuration

All settings are environment variables with the `CS_` prefix (`.env` is read in development). Secrets
(`CS_JWT_PUBLIC_KEY`, `CS_METRICS_TOKEN`) should be injected by your secret vault; for a key file use
`CS_JWT_PUBLIC_KEY_PATH`. `.env.example` contains safe dummy values.

| Variable | Default | Purpose |
|---|---|---|
| `CS_ENVIRONMENT` | `development` | `development`, `test` or `production`. Production enforces the checks below. |
| `CS_LOG_LEVEL` | `INFO` | Log level. JSON logs outside development. |
| `CS_DOCS_ENABLED` | `true` | Serve `/docs`, `/redoc`, `/openapi.json`. Must be `false` in production. |
| `CS_APP_TITLE` | `Central Security API` | OpenAPI title. |
| `CS_APP_VERSION` | `1.0.0` | OpenAPI version. |
| `CS_DATABASE_URL` | `sqlite+aiosqlite:///./data/central_security.db` | SQLite file URL. In-memory and other databases are rejected. |
| `CS_DB_POOL_SIZE` | `5` | Connections per engine pool. |
| `CS_DB_MAX_OVERFLOW` | `5` | Extra connections beyond the pool size. |
| `CS_DB_POOL_TIMEOUT_SECONDS` | `30` | Wait for a free connection. |
| `CS_DB_BUSY_TIMEOUT_MS` | `5000` | How long a writer waits for SQLite's write lock. |
| `CS_JWT_ISSUER` | `https://idp.example.internal` | Required `iss`. |
| `CS_JWT_AUDIENCE` | `central-security` | Required `aud`. |
| `CS_JWT_ALGORITHMS` | `["RS256"]` | Accepted algorithms. `none` and HMAC are refused at startup. |
| `CS_JWT_JWKS_URL` | – | Identity provider JWKS (https required in production). |
| `CS_JWT_PUBLIC_KEY` | – | Static PEM public key (alternative to JWKS). |
| `CS_JWT_PUBLIC_KEY_PATH` | – | Path to a PEM public key file (alternative to the above). |
| `CS_JWT_CLIENT_ID_CLAIM` | `client_id` | Claim that identifies the calling application. |
| `CS_JWT_ROLES_CLAIM` | `roles` | Claim holding administrative roles. |
| `CS_JWT_LEEWAY_SECONDS` | `10` | Clock-skew tolerance for `exp`/`nbf`. |
| `CS_JWKS_CACHE_TTL_SECONDS` | `300` | How long fetched keys are trusted. |
| `CS_JWKS_TIMEOUT_SECONDS` | `3` | JWKS fetch timeout. |
| `CS_JWKS_MIN_REFRESH_INTERVAL_SECONDS` | `30` | Minimum gap between refreshes triggered by an unknown `kid`. |
| `CS_CORS_ORIGINS` | `[]` | Allowed origins. A wildcard is refused in production. |
| `CS_MAX_REQUEST_BODY_BYTES` | `1048576` | Hard cap on any request body (413). |
| `CS_AUTH_FAILURE_LIMIT_PER_MINUTE` | `20` | Failed authentications per source IP before 429. |
| `CS_DEFAULT_CALLER_RATE_LIMIT_PER_MINUTE` | `60` | Applied to callers with no caller-scoped rate quota. |
| `CS_PROVIDER_TIMEOUT_SECONDS` | `30` | Total provider time budget (slot wait, calls and backoff). |
| `CS_PROVIDER_MAX_RETRIES` | `2` | Retries for transient provider failures. |
| `CS_PROVIDER_BACKOFF_BASE_SECONDS` | `0.2` | First retry delay; doubles each retry. |
| `CS_PROVIDER_MAX_CONCURRENCY` | `16` | Concurrent provider calls per process. |
| `CS_MAX_RESPONSE_BYTES` | `262144` | Largest provider output accepted (502 beyond it). |
| `CS_METRICS_ENABLED` | `true` | Serve `/metrics`. |
| `CS_METRICS_TOKEN` | – | If set, `/metrics` requires `Authorization: Bearer <token>`. |

## Authentication and roles

Tokens are issued by your identity provider; this service only validates them. There are no local users,
passwords or refresh tokens.

| Role | Source | Grants |
|---|---|---|
| Business application | A registered, approved **service identity** (looked up by the token's `client_id`). | `POST /api/v1/llm/process` for its project's granted tasks and models; `GET /api/v1/me`. |
| `governance_admin` | `roles` claim | Manage projects, tasks, models, grants, service identities, policies and quotas; read security events. |
| `audit_reviewer` | `roles` claim | Read audit logs (including hash-chain verification) and security events. |

Revoking a service identity takes effect on the very next request because the registry is consulted on
every call. Rotate signing keys at the identity provider; the JWKS cache refreshes automatically.

## Database and migrations

SQLite in WAL mode with `PRAGMA foreign_keys=ON`. Reads use one engine; every write unit of work uses a
second engine whose transactions start with `BEGIN IMMEDIATE`, so concurrent writers queue instead of
failing with stale-snapshot errors. Audit logs and security events are protected by triggers that reject
`UPDATE` and `DELETE`.

```bash
python -m alembic upgrade head                      # apply
python -m alembic downgrade base                    # roll back everything
python -m alembic revision --autogenerate -m "..."  # new migration (review it by hand)
```

Back up the `.db` file with SQLite's online backup (`sqlite3 file ".backup out.db"`), not by copying it
while the service is writing.

## Testing and quality gates

| Task | `make` target | Equivalent without `make` |
|---|---|---|
| Install | `make install` | `pip install -r requirements-dev.txt` |
| Tests + coverage (fails under 85%) | `make test` | `python -m pytest` |
| Lint + format check | `make lint` | `python -m ruff check . && python -m ruff format --check .` |
| Type check (mypy strict) | `make typecheck` | `python -m mypy` |
| Format | `make format` | `python -m ruff check --fix . && python -m ruff format .` |

Tests run against real SQLite files in temporary directories; each test gets a fresh database, so none
depends on another. Pre-commit hooks are configured in `.pre-commit-config.yaml` (`pre-commit install`
inside a git checkout). Dependencies are pinned in `requirements.txt` (runtime) and
`requirements-dev.txt`; `pyproject.toml` holds the compatible ranges.

## API reference with examples

Interactive docs: `/docs` (development). All bodies and query parameters are camelCase. Lists return
`{items, total, limit, offset}` and accept `limit` (1–200), `offset`, `sort` and `order=asc|desc`.
Updates are `PATCH` with only the changed fields. Set `TOKEN`/`ADMIN` as shown in the quick start and
`B=http://localhost:8000`.

**Process an LLM request**

```bash
curl -s $B/api/v1/llm/process -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"requestId":"wf-42-step-3","task":"summarize_document","model":"local-echo",
       "input":"Summarize this paragraph.","parameters":{"temperature":0.2,"maxTokens":200}}'
```

**Who am I** — `curl -s $B/api/v1/me -H "Authorization: Bearer $TOKEN"`

**Projects** (`/api/v1/projects`, admin)

```bash
curl -s $B/api/v1/projects -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"projectKey":"COE_1","name":"Center of Excellence","team":"COE"}'
curl -s "$B/api/v1/projects?team=COE&sort=name" -H "Authorization: Bearer $ADMIN"
curl -s -X PATCH $B/api/v1/projects/$PROJECT_ID -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" -d '{"status":"suspended"}'
curl -s -X DELETE $B/api/v1/projects/$PROJECT_ID -H "Authorization: Bearer $ADMIN"   # soft delete
```

**Task and model grants** (`/api/v1/projects/{id}/tasks`, `/models`)

```bash
curl -s $B/api/v1/projects/$PROJECT_ID/tasks -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" -d "{\"taskId\":\"$TASK_ID\"}"
curl -s $B/api/v1/projects/$PROJECT_ID/models -H "Authorization: Bearer $ADMIN"
curl -s -X DELETE $B/api/v1/projects/$PROJECT_ID/models/$MODEL_ID -H "Authorization: Bearer $ADMIN"
```

**Tasks** (`/api/v1/tasks`) and **models** (`/api/v1/models`), admin

```bash
curl -s $B/api/v1/tasks -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"name":"summarize_document","description":"Summaries","maxPayloadBytes":65536}'
curl -s $B/api/v1/models -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"name":"gpt-4o","provider":"openai"}'
```

**Service identities** (`/api/v1/service-identities`, admin) — register, approve, revoke

```bash
curl -s $B/api/v1/service-identities -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d "{\"projectId\":\"$PROJECT_ID\",\"clientId\":\"billing-app\",\"displayName\":\"Billing\"}"
curl -s -X POST $B/api/v1/service-identities/$IDENTITY_ID/approve -H "Authorization: Bearer $ADMIN"
curl -s -X POST $B/api/v1/service-identities/$IDENTITY_ID/revoke -H "Authorization: Bearer $ADMIN" \
  -H "Content-Type: application/json" -d '{"reason":"annual access review"}'
```

New identities are `pending` and cannot call the gateway until approved. A revoked identity cannot be
re-approved; register a new one.

**Policies** (`/api/v1/policies`, admin). Kinds and their `definition`:

| Kind | Definition |
|---|---|
| `prompt_injection` | `{"rules":[{"id":"x","pattern":"regex","description":"…"}]}`, added to the built-in rules |
| `request_rule` | `{"minInputLength":5,"maxInputLength":4000,"maxTokensLimit":512,"allowedParameters":["temperature"]}` |
| `response_schema` | `{"schema": { …JSON Schema… }}`; output must be JSON matching it |
| `content_security` | `{"denyPatterns":[{"id":"ssn","pattern":"\\d{3}-\\d{2}-\\d{4}"}],"maxOutputChars":20000}` |

```bash
curl -s $B/api/v1/policies -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"name":"no-ssn","kind":"content_security","definition":{"denyPatterns":[{"id":"ssn","pattern":"\\d{3}-\\d{2}-\\d{4}"}]}}'
```

Add `"scopeTaskId":"<task id>"` to scope a policy to one task. Changing a definition bumps `version`.

**Quotas** (`/api/v1/quotas`, admin)

```bash
curl -s $B/api/v1/quotas -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"scopeType":"project","scopeRef":"COE_1","kind":"quota","limitValue":10000,"windowSeconds":86400}'
```

`scopeType` is `caller` (client id), `team`, `project` (key) or `task` (name); `kind` is `rate` or `quota`
(both are fixed-window counters).

**Security events** (`/api/v1/security-events`, auditor or admin)

```bash
curl -s "$B/api/v1/security-events?eventType=prompt_injection&severity=critical" -H "Authorization: Bearer $ADMIN"
```

**Audit logs** (`/api/v1/audit-logs`, auditor only)

```bash
curl -s "$B/api/v1/audit-logs?actor=sub-admin&occurredFrom=2026-01-01T00:00:00Z" -H "Authorization: Bearer $ADMIN"
curl -s $B/api/v1/audit-logs/verify -H "Authorization: Bearer $ADMIN"
```

## Error model

All errors are RFC 9457 `application/problem+json`:

```json
{"type":"urn:central-security:problem:rate-limit-exceeded","title":"Too Many Requests","status":429,
 "detail":"Rate limit or quota exceeded.","instance":"/api/v1/llm/process","requestId":"…",
 "errors":[{"field":"input","message":"…","code":"…"}]}
```

`errors` appears for validation failures and never echoes submitted values. Stack traces and internal
messages are never returned.

| Status | Meaning |
|---|---|
| 400 | Malformed request, schema failure, unknown task or model, or policy violation (`policy-violation`). |
| 401 | Missing, invalid or expired credentials. |
| 403 | Authenticated but not authorized (role, identity status, project, task or model grant, identity override). |
| 404 | Resource not found. |
| 409 | Conflict: duplicate unique value, duplicate `requestId`, invalid state transition. |
| 413 | Body or input over its limit. |
| 429 | Rate limit or quota exceeded (`Retry-After` set). |
| 502 | Provider output failed validation. |
| 503 | A required dependency (signing keys, database, provider) is unavailable. |
| 504 | The provider timed out. |

Every response carries `X-Request-ID`. Send your own (`[A-Za-z0-9._-]{1,128}`) to correlate calls; it is
bound to all logs, audit entries and security events. It is distinct from the body's `requestId`, which
identifies one agentic step and must be unique per project.

## Audit and security events

- **`llm_requests`** stores metadata only: project, identity, task, model, status, byte sizes, SHA-256
  of the input and output, latency, attempts. Prompt and response text are never stored or logged.
- **`audit_logs`** is an append-only hash chain (each row commits to the previous row's hash). Every
  administrative change, every processed request and every read of the audit trail is recorded in the
  same transaction as the action. `GET /api/v1/audit-logs/verify` recomputes the chain and reports the
  first broken entry. Triggers block `UPDATE`/`DELETE`; someone with file-system access who drops the
  triggers is still detected by verification.
- **`security_events`** is append-only and records denied access, invalid requests, oversize payloads,
  prompt-injection hits, identity overrides, duplicates, rate limits, response failures and provider
  failures.
- **Retention**: the application never deletes audit data. Apply your retention policy with a privileged
  archival job that exports and then removes old rows (this requires dropping and re-creating the
  append-only triggers, which should itself be a controlled, logged change).

## Operations

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness. |
| `GET /ready` | Readiness: database and identity-provider keys. 503 if either is unavailable. |
| `GET /metrics` | Prometheus: request counts and latency, `llm_requests_total`, `security_events_total`, `provider_call_duration_seconds`. |

- Logs are structured (structlog): JSON outside development. Each request logs method, path, status,
  duration, request id and (when authenticated) the user. Keys such as `password`, `token`,
  `authorization`, `input` and `output` are masked.
- Terminate TLS at your ingress or reverse proxy. Responses include HSTS in production. Run uvicorn
  with `--proxy-headers` (the Docker entrypoint does) so the real client IP is used for throttling.
- Restrict `/metrics` by network or set `CS_METRICS_TOKEN`.

## Limitations and assumptions

- **No real LLM provider is wired in.** The gateway calls an `LLMProvider` interface; the built-in
  `LocalProvider` returns the input as JSON and calls no external service. Add an adapter in
  `app/services/provider.py` and select it in `app/main.py`.
- **SQLite is single-node.** Rate limits, quotas and audit-chain serialization are correct on one host
  (any number of worker processes) and not across hosts.
- Rate limits and quotas are **fixed windows**: a burst can straddle a window boundary.
- **Prompt-injection detection is heuristic** (normalised pattern matching plus your own rules). It
  reduces risk and creates evidence; it cannot catch every attack. Treat model output as untrusted.
- Custom regex patterns are length-limited and screened for nested quantifiers, but you are responsible
  for the patterns you add.
- A `requestId` is consumed once the request passes authorization and rate limiting, including requests
  later rejected by the injection policy. Requests rejected earlier (413, 429, 403) do not consume it.
- Unknown task and model names return 400 while ungranted ones return 403, so a caller can learn which
  names exist.
- Formal certification, threat modelling and privacy review are still required before production use.
