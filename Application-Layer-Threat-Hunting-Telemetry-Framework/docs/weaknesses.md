# Intentional Weaknesses

The Target_API (`app/main.py`) is deliberately vulnerable. It must only run inside the lab, bound to loopback behind the gateway. Each weakness below is intentional.

| # | Weakness | Affected endpoint | OWASP API Security Top 10 |
|---|---|---|---|
| 1 | BOLA (broken object-level authorization) | `GET /api/v1/invoices/{id}` | API1:2023 Broken Object Level Authorization |
| 2 | JWT `alg=none` accepted | `GET /api/v1/admin/audit` | API2:2023 Broken Authentication |
| 3 | Expired-token replay accepted | `GET /api/v1/invoices/{id}` | API2:2023 Broken Authentication |
| 4 | SSRF | `POST /api/v1/webhooks/preview` | API7:2023 Server Side Request Forgery |

## 1. BOLA

`GET /api/v1/invoices/{id}` authenticates the caller but does not check that the invoice belongs to the caller's tenant. Any valid user can read invoices of other tenants by iterating ids. The app records `appsec.resource.tenant_id` and sets `appsec.authz.cross_tenant` when the owner differs from the caller, which is what the BOLA detections use. Simulator: `simulators/hunt_01_bola_enum.py`.

## 2. `alg=none`

`GET /api/v1/admin/audit` accepts tokens whose header says `alg: none` with an empty signature. The telemetry records `appsec.jwt.alg` and `appsec.jwt.verified=false`. Simulator: `simulators/hunt_02_jwt_abuse.py` (technique `alg_none`).

## 3. Expired-token replay

`GET /api/v1/invoices/{id}` accepts a validly signed token whose `exp` is in the past. The telemetry records `appsec.jwt.expired=true`. Simulator: `simulators/hunt_02_jwt_abuse.py` (technique `expired`).

## 4. SSRF

`POST /api/v1/webhooks/preview` fetches an attacker-supplied URL server-side without destination filtering. It can reach the simulated metadata service and the internal management app (`/internal/secret`) inside the lab network. Each fetch emits an `appsec.egress` event sharing the request's `trace.id`. Simulator: `simulators/hunt_03_ssrf_egress.py`.

## Related behavior (not a separate weakness)

The same JWT simulator also replays one valid token from two client IP/ASN pairs (technique `hijack`). This is token reuse against the invoices endpoint, detected through `appsec.jwt.jti`; the API does not bind tokens to a client. It is not counted as a fifth weakness.
