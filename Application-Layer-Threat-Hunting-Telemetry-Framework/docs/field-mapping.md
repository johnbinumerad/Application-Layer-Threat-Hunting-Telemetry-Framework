# Field Mapping

The lab uses one naming scheme: **ECS 8.x**. Where ECS has no suitable field, two custom namespaces are used: `appsec.*` (application semantics) and `lab.*` (simulator ground truth). OCSF is not used (design decision D1).

The source of truth is [`config/field_mapping.yaml`](../config/field_mapping.yaml). The event builders are in `labcommon/schema.py`. This page describes that file and must stay in step with it.

Presence: **R** = required (on every event of the dataset), **C** = conditional (omitted when the value is unavailable).

Three event datasets share the single `appsec-telemetry-*` index and are distinguished by `event.dataset`:

| `event.dataset` | Event | Emitted by |
|---|---|---|
| `appsec.api` | Telemetry_Event | Target_API, one per inbound request |
| `appsec.egress` | Egress_Event | Target_API, one per outbound fetch (SSRF preview) |
| `appsec.gateway` | Gateway event | Envoy access log |

## Supplied-design name to ECS name

| Supplied design name | ECS / lab name | Note |
|---|---|---|
| `http.method` | `http.request.method` | |
| `actor.user_id` | `user.id` | |
| `actor.token_jti_hash` | `appsec.jwt.jti` | Plain JTI is stored and never scrubbed (D2). A salted pivot `appsec.jwt.jti_hash` (first 16 hex chars of salted SHA-256) is kept as an extra. |
| (raw bearer token) | `appsec.jwt.token_hash` | Salted SHA-256. The raw token is never indexed. |
| tenant id | `organization.id` | |
| user agent | `user_agent.original` | Truncated to 512 chars |
| request time | `event.start` (`@timestamp` equals it) | |
| token algorithm / expiry | `appsec.jwt.alg`, `appsec.jwt.exp`, `appsec.jwt.expired` | |

## Telemetry_Event (`appsec.api`)

| Field | Type | Presence | Notes |
|---|---|---|---|
| `@timestamp` | date | R | UTC ISO 8601, ms; equals `event.start` |
| `event.id` | keyword | R | |
| `event.dataset` | keyword | R | `appsec.api` |
| `event.kind` | keyword | R | always `event` |
| `event.start` | date | R | |
| `event.duration` | long | R | nanoseconds |
| `appsec.latency_ms` | long | R | non-negative integer ms |
| `trace.id` | keyword | R | |
| `source.ip` | ip | R | |
| `user_agent.original` | keyword | C | truncated to 512 chars |
| `event.category` | keyword | R | |
| `event.action` | keyword | R | `api_request`, `auth_login`, or `jwt_validation_failed` |
| `event.outcome` | keyword | R | `success` or `failure` |
| `user.id` | keyword | C | |
| `user.roles` | keyword | C | |
| `organization.id` | keyword | C | caller tenant |
| `http.request.method` | keyword | R | |
| `http.response.status_code` | long | R | |
| `url.path` | text | R | not aggregatable; never aggregate on raw paths |
| `appsec.endpoint_template` | keyword | R | aggregation key, e.g. `/api/v1/invoices/{invoice_id}` |
| `appsec.resource_id` | keyword | C | |
| `appsec.jwt.jti` | keyword | C | |
| `appsec.jwt.jti_hash` | keyword | C | |
| `appsec.jwt.alg` | keyword | C | |
| `appsec.jwt.exp` | date | C | |
| `appsec.jwt.expired` | boolean | C | |
| `appsec.jwt.verified` | boolean | C | |
| `appsec.jwt.token_hash` | keyword | C | collector-derived |
| `appsec.client_pair` | keyword | C | collector-derived |
| `appsec.resource.tenant_id` | keyword | C | owner tenant of the requested object |
| `appsec.authz.cross_tenant` | boolean | C | resource owner differs from caller (D10) |
| `appsec.egress.count` | long | R | outbound fetches made by the request |

## Egress_Event (`appsec.egress`)

Common fields (`@timestamp`, `event.id`, `event.dataset`, `event.kind`, `event.start`, `event.duration`, `appsec.latency_ms`, `trace.id`, `source.ip`) are present as above. In addition:

| Field | Type | Presence | Notes |
|---|---|---|---|
| `event.outcome` | keyword | R | |
| `destination.address` | keyword | R | |
| `destination.domain` | keyword | C | |
| `destination.port` | long | C | |
| `destination.ip` | ip | C | omitted on DNS failure |
| `url.full` | keyword | R | scrubbed by the pipeline |
| `http.response.status_code` | long | C | omitted on failure |
| `error.type` | keyword | C | `dns_failure`, `connection_refused`, `timeout`, `invalid_url`, `other` |
| `user.id` | keyword | C | denormalized inbound context (D11) |
| `organization.id` | keyword | C | denormalized inbound context |
| `appsec.endpoint_template` | keyword | C | denormalized inbound context |

## Gateway event (`appsec.gateway`)

Common fields as above, plus:

| Field | Type | Presence | Notes |
|---|---|---|---|
| `user_agent.original` | keyword | C | |
| `http.request.method` | keyword | R | |
| `http.response.status_code` | long | R | |
| `url.path` | text | R | not aggregatable |
| `appsec.upstream_latency_ms` | long | C | |
| `appsec.gateway.route` | keyword | C | Envoy route name |
| `appsec.gateway.upstream_cluster` | keyword | C | |
| `appsec.gateway.response_flags` | keyword | C | |

## Ground truth (`lab.*`, all datasets, all C)

Set from the `X-Lab-*` request headers. Detections, Sigma rules, and monitors never reference these fields; only the validator and notebooks do.

| Field | Type | Values |
|---|---|---|
| `lab.ground_truth.label` | keyword | `baseline`, `attack` |
| `lab.ground_truth.scenario` | keyword | `baseline`, `bola`, `jwt`, `ssrf` |
| `lab.ground_truth.technique` | keyword | simulator technique name |
| `lab.ground_truth.run_id` | keyword | |
| `lab.ground_truth.role` | keyword | `attack_action`, `setup` |

## Enrichment and pipeline fields

| Field | Type | Presence | Stage |
|---|---|---|---|
| `source.as.number` | long | C | enrichment (SIEM ingest pipeline) |
| `source.as.organization.name` | keyword | C | enrichment |
| `source.geo.country_iso_code` | keyword | C | enrichment |
| `appsec.scrub.status` | keyword | R | pipeline; always `ok` for indexed records |

## Removed before indexing

Sent by the app to the Collector, then dropped; never present in the SIEM:

- `http.request.headers.authorization`
- `appsec.credentials.password`
