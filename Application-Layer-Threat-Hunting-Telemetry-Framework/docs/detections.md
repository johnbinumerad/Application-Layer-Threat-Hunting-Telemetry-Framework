# Detections

This document describes the three detection scenarios (BOLA, JWT abuse, SSRF). Each has Sigma rules in `detections/sigma/` and one OpenSearch monitor in `opensearch/monitors/`. Thresholds come from `config/detections.yaml`, the single source of truth. The monitors and Sigma rules mirror it.

| Scenario | Sigma file | Monitor file | Monitor type |
|---|---|---|---|
| BOLA | `detections/sigma/bola_enumeration.yml` | `opensearch/monitors/bola_enumeration.json` | bucket-level |
| JWT abuse | `detections/sigma/jwt_abuse.yml` | `opensearch/monitors/jwt_abuse.json` | query-level (3 triggers) |
| SSRF | `detections/sigma/ssrf_egress.yml` | `opensearch/monitors/ssrf_egress.json` | query-level |

All monitors run every 1 minute against `appsec-telemetry-*`. Each trigger has severity 2 and no actions, so alerts are visible in the Alerting UI only.

## Threshold summary (`config/detections.yaml`)

| Key | Value | Meaning |
|---|---|---|
| `bola.window_minutes` | 10 | Aggregation window per user and endpoint template |
| `bola.lookback_minutes` | 20 | Monitor query range (`now-20m`) |
| `bola.distinct_ids_threshold` | 25 | Alert when distinct `appsec.resource_id` is greater than 25 |
| `bola.error_ratio_threshold` | 0.6 | Alert when (403 + 404 + cross-tenant 2xx) / total is greater than 0.6 |
| `bola.retry_suppression_max_ids` | 3 | 3 or fewer distinct ids is treated as retry noise |
| `bola.excluded_roles` | `batch_worker` | Role excluded from the detection |
| `jwt.hijack_window_minutes` | 5 | Window for JTI reuse |
| `jwt.min_distinct_client_pairs` | 2 | Same JTI from 2 or more distinct (`source.ip`, user agent) pairs |
| `ssrf.internal_cidrs` | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8 | Internal destination ranges |
| `ssrf.internal_hostnames` | localhost, metadata.internal, metadata.google.internal, target-api, gateway, opensearch, dashboards, otel-collector, jupyter | Internal destination names |
| `ssrf.allowed_destination_hosts` | empty | Allowlist, nothing is allowed by default |

## 1. BOLA enumeration (ATT&CK T1087, T1213; OWASP API1:2023)

### Sigma rules (`bola_enumeration.yml`, two documents)

1. `bola_enumeration_events` (level `low`). Selects `appsec.api` events on `/api/v1/invoices/{invoice_id}` that returned 403 or 404, or that have `appsec.authz.cross_tenant: true`. It excludes `user.roles: batch_worker`. This is the building block for the correlation rule.
2. BOLA distinct-ID correlation (level `high`). A `value_count` correlation over `bola_enumeration_events`, grouped by `user.id`, with `timespan: 10m` and condition `appsec.resource_id` count greater than 25.

### Monitor (`bola_enumeration`)

- Bucket-level monitor with a composite aggregation by `user.id`, `appsec.endpoint_template`, and a 10-minute date histogram. Lookback is `now-20m`.
- It computes `distinct_ids` as a `cardinality` aggregation on `appsec.resource_id` with `precision_threshold: 3000`.
- The trigger fires per bucket when all of these hold:
  - `distinct_ids > 25`
  - `distinct_ids > 3` (retry suppression)
  - `total > 0`
  - `(c403 + c404 + c_xtenant) / total > 0.6`
- Events from `batch_worker` are excluded with a `must_not` clause.

### Expected false positives

- Mobile client retries. A flaky mobile client re-requests a handful of invoices. These stay at 3 or fewer distinct ids, well under 25, so they never fire.
- Shared NAT or corporate proxy. Several users behind one IP can look like one scanner in IP-based views. The detection groups by `user.id`, not by IP, so this mostly does not apply. It can still matter if an upstream gateway collapses identities into a shared service account.
- Support staff or auditors who legitimately view many customers' invoices. They produce many distinct ids and cross-tenant 2xx responses. Exclude their roles through `bola.excluded_roles`.
- Batch or reporting jobs. These are excluded through `batch_worker`.

### Sensitivity versus false-positive trade-off

- Lowering the 25-id threshold catches slower enumeration (low-and-slow mode). It also raises the chance that a legitimate user with a busy 10-minute window crosses it.
- Raising it reduces noise but lets an attacker stay under the threshold, for example by probing 20 ids per window. Widening the window catches that pacing at the cost of more memory and more overlap with normal activity.
- The 0.6 error ratio keeps legitimate users who mostly hit their own, successful objects from alerting, even at high volume. A very low ratio would catch an attacker who mixes in valid requests, but it also flags heavy but legitimate use.
- The 3-id retry floor is the cheapest noise filter. It is redundant with the 25 threshold today but protects the monitor if the threshold is lowered.

### Monitor-only ratio note

The error-ratio condition (0.6) is enforced only by the OpenSearch monitor. Sigma cannot express a ratio of two counts. The Sigma correlation rule therefore applies only the distinct-ID count over events that are already denied or cross-tenant. A converted Sigma rule will not apply the ratio check. Treat the monitor as the reference implementation of the BOLA logic.

## 2. JWT abuse (ATT&CK T1550.001, T1078; OWASP API2:2023)

### Sigma rules (`jwt_abuse.yml`, three documents)

1. `jwt_unverified_or_expired_accepted` (level `high`). An `appsec.api` event with a 2xx response (200 up to but excluding 300) where `appsec.jwt.alg` is `none` or `appsec.jwt.expired` is true. It has no count threshold, because a single accepted forged or expired token is an attack.
2. `jwt_jti_events` (level `informational`). A helper rule that selects events where `appsec.jwt.jti_hash` and `appsec.client_pair` exist.
3. Same-JTI hijack correlation (level `high`). A `value_count` correlation over `jwt_jti_events`, grouped by `appsec.jwt.jti_hash`, with `timespan: 5m` and condition `appsec.client_pair` count of 2 or more (`gte: 2`).

### Monitor (`jwt_abuse`)

A query-level monitor with a `now-5m` lookback and three triggers:

| Trigger | Condition |
|---|---|
| `jwt-alg-none-or-validation-failed` | More than 0 events with `appsec.jwt.alg: none` or `event.action: jwt_validation_failed` |
| `jwt-expired-accepted` | More than 0 events with `appsec.jwt.expired: true` and a 2xx status |
| `jwt-jti-multi-client` | Any `appsec.jwt.jti` bucket (terms, size 1000) with `client_pairs` cardinality of 2 or more |

Note the differences from Sigma. The monitor's first trigger also fires on `jwt_validation_failed` events, so it matches rejected tokens too, not only accepted ones. The monitor aggregates on `appsec.jwt.jti`, while the Sigma rule uses `appsec.jwt.jti_hash`. Check `config/field_mapping.yaml` for the stored field if you adapt either one.

### Expected false positives

- Network switches. A user moving between Wi-Fi and cellular mid-session keeps the same JTI but changes `source.ip`, and often the user agent as well. This is the main source of false positives for the hijack rule.
- Shared NAT or proxy pools. Egress addresses can rotate between requests, so one client can appear as several IPs under one JTI.
- Mobile retries. Retries that cross a network change or a proxy failover produce the same effect as a network switch.
- Clock skew near the expiry boundary. A token that is expired by a second at the API but valid at the issuer can trigger the expired-accepted rule.
- Unsigned test tokens in non-lab environments.

### Sensitivity versus false-positive trade-off

- Requiring 2 distinct client pairs catches any replay from a second device, but it also flags every legitimate roaming user. Requiring 3 or more would cut roaming noise at the cost of missing a single-attacker replay.
- A 5-minute window limits false positives from long-lived sessions that roam over hours. A shorter window misses slower replay. A longer window raises noise.
- Counting the client pair (IP plus user agent) is stricter than counting IPs alone. IP-only counting would fire on every NAT rotation. Counting user agent too means a switch of IP alone still counts, because the pair changes.
- The `alg=none` and expired-accepted conditions have no tolerance and effectively no false positives in the lab. In production, add a small grace period for clock skew if it causes noise.

### Conversion caveat

The JTI hijack rule is a Sigma correlation rule (`value_count` correlation). See the correlation-rule conversion caveat below.

## 3. SSRF (ATT&CK T1190, T1552.005; OWASP API7:2023)

### Sigma rules (`ssrf_egress.yml`, three documents)

1. `ssrf_internal_egress` (level `high`). An `appsec.egress` event whose `destination.ip` is in one of the 5 internal CIDRs, or whose `destination.domain` is one of the 9 internal hostnames (see the summary table). No count or window applies, and a single event matches.
2. `ssrf_preview_request` (level `informational`). A helper rule for `appsec.api` events on `/api/v1/webhooks/preview`.
3. Preview-plus-egress correlation (level `high`). A `temporal` correlation over the two rules above, grouped by `trace.id`, with `timespan: 5s`.

### Monitor (`ssrf_egress`)

A query-level monitor with a `now-5m` lookback. It matches `appsec.egress` events whose `destination.ip` falls within the same 5 CIDRs or whose `destination.domain` is in the same 9 hostnames. It triggers (`ssrf-internal-egress`) when the hit count is greater than 0 and returns up to 10 sample hits. The monitor does not do the API-to-egress join. It evaluates the egress event on its own, which already carries `trace.id` for pivoting in the notebooks.

### Expected false positives

- Legitimate integrations or health checks that call internal services such as `gateway` or `opensearch`. Add approved destinations to `ssrf.allowed_destination_hosts` (empty by default). Note that the current Sigma and monitor files list the CIDRs and hostnames explicitly and do not read the allowlist, so an allowlist entry needs a matching edit to the rule.
- Webhook targets on private addresses in an RFC 1918 network that are approved for the tenant.
- Shared NAT is not relevant here, because the detection looks at the destination, not the source.

### Sensitivity versus false-positive trade-off

- The rule has no count threshold. This gives maximum sensitivity: one internal request is enough. Metadata-service access is rarely legitimate, so false positives stay low in the lab.
- Adding more internal hostnames raises coverage of DNS-based SSRF but also adds noise if those names are used by approved integrations.
- Matching on the resolved `destination.ip` catches alternate encodings (decimal, octal, hex, IPv6-mapped) that hide the internal address in the URL. A rule on the requested hostname alone would miss them.
- The 5-second correlation window ties the egress to the triggering request. A longer window would match unrelated traffic on a busy trace. A shorter window can miss slow redirects.

## Correlation-rule conversion caveat

Three of the Sigma documents are Sigma correlation rules (`correlation:` with `value_count` or `temporal`): the BOLA distinct-ID rule, the JWT JTI hijack rule, and the SSRF preview-plus-egress rule. Many Sigma converters, including the common `sigma-cli` OpenSearch backends, do not support correlation rules or support only part of them. Specifically:

- Converting the rule files that contain only `detection` blocks works as normal. Converting correlation documents may fail, skip the correlation, or emit only the base rule.
- Where the correlation is dropped, the converted query loses its count and window, so it would match every single event. For example, the converted BOLA base rule would alert on any single 403 or 404.
- The BOLA error ratio cannot be expressed in Sigma at all (see the monitor-only ratio note).
- The SSRF api/egress join cannot be run by an OpenSearch monitor. The monitor uses the denormalized egress event instead.

Use the OpenSearch monitors as the reference implementations of the thresholds. Use the Sigma files as portable documentation of the detection logic.

## Tuning

Change a threshold in `config/detections.yaml` first. Then update the matching monitor JSON and Sigma file so all three stay aligned. The documentation consistency tests compare the numbers in this document with the config file, so update this document too.
