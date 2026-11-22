# Application-Layer Threat Hunting & Telemetry Framework

A self-contained Purple Team lab. It runs a deliberately vulnerable API behind an Envoy gateway and ships scrubbed ECS telemetry through an OpenTelemetry Collector into OpenSearch. Attack simulators exercise three weaknesses, and Sigma rules, OpenSearch monitors, dashboards and Jupyter notebooks hunt for them.

The lab is local only. It needs no cloud credentials and binds every published port to `127.0.0.1`.

## Status and verification (read this first)

Docker was not available while this was built. What that means:

- **Verified:** the Python code was exercised by the unit and property tests in `tests/` (`make test`). At the last run, 58 tests passed. Many of the optional property tests listed in the spec (`tasks.md`) were not written, so coverage is partial. `tests/integration/` is empty.
- **Not verified against a live stack:** `docker-compose.yml`, the Envoy, Collector and OpenSearch configuration, the `lab-setup` job, the generated monitors and dashboards, `labctl validate` and `labctl cleanup` against a real OpenSearch, the notebooks, and the end-to-end detection results. None of these have been run. Expect to debug first-boot issues.
- **No measured results.** The README contains no real alert counts or precision figures. The validation table below shows the output layout only.
- Open questions about the Collector's `opensearch` exporter and OTTL behaviour are recorded in `infra/otel/SPIKE.md`.

## Architecture

```
 simulators (host)                      lab_internal (internal: true, 172.28.0.0/16)
 traffic_baseline / hunt_01..03         ┌────────────────────────────────────────────────────┐
        │ HTTP 127.0.0.1:8080           │                                                    │
        ▼                               │  gateway (Envoy) ──► target-api (FastAPI :8000)    │
   [lab_edge] gateway ──────────────────┼────┐  │ OTLP gRPC       │ OTLP HTTP   ▲ mgmt :8001 │
                                        │    ▼  ▼                 ▼             │           │
                                        │  otel-collector: enrich → scrub → seal → route     │
                                        │    │ sealed                  │ unsealed            │
                                        │    ▼                         ▼                     │
                                        │  opensearch (appsec-telemetry-*)   debug log only  │
                                        └────┬───────────────────────────────────────────────┘
                     [lab_edge] opensearch :9200 · dashboards :5601 · jupyter :8888
```

- `gateway` (Envoy): routes `/api/*`, injects and preserves `x-request-id` (the Trace_ID), sets `x-lab-client-ip`, rate limits, and emits `appsec.gateway` access logs.
- `target-api`: the vulnerable FastAPI app, plus a management app on `:8001` and a simulated cloud metadata service at `169.254.169.254` inside its own container.
- `otel-collector`: salted hashing, scrubbing and fail-closed routing (see below).
- `opensearch` and `dashboards`: storage, monitors and dashboards.
- `jupyter`: the hunting notebooks.
- `lab-setup`: a one-shot job that loads the ingest pipeline, index template, dashboards and monitors.

Five logical services: gateway, Target_API, Collector, SIEM (OpenSearch plus Dashboards, two containers), and notebooks (Jupyter). `lab-setup` is a one-shot helper and is not counted. Compose therefore runs six long-running containers plus the setup job.

## Decisions

- **ECS, not OCSF.** Telemetry uses ECS 8.x field names, plus `appsec.*` and `lab.*` namespaces. See `docs/field-mapping.md`.
- **Ground truth is separate from detection.** Simulators tag requests with `X-Lab-*` headers, stored as `lab.ground_truth.*`. No monitor or dashboard query may reference these fields. They exist only to score detections.

## Host requirements

These figures are recommended minimums based on the configuration (OpenSearch is set to a 512 MB heap). They were not measured on a running stack.

| Resource | Minimum |
|---|---|
| CPU cores | 4 |
| Memory | 8 GB available to Docker |
| Free disk | 10 GB |
| Docker Engine | 24.0 |
| Docker Compose | v2.20 (the `docker compose` plugin) |
| Python (host tooling) | 3.12 |

## Quickstart

```bash
cp .env.example .env            # set SCRUB_SALT and LAB_JWT_SECRET (lab-only values)
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt

make up        # preflight (loopback-only, free ports), then docker compose up -d
make setup     # load pipeline, index template, dashboards, monitors
```

Run simulators from the host. All take `--mode {low-and-slow,noisy}` (default `low-and-slow`), `--target` (default `http://127.0.0.1:8080`) and `--seed`. The mode only selects default pacing and rate presets. Explicit parameters override it and are still range-checked.

```bash
python -m simulators.traffic_baseline --duration 300 --rate 5
python -m simulators.hunt_01_bola_enum --mode low-and-slow            # or: --rate 0.5 --start-id 1011 --count 80
python -m simulators.hunt_02_jwt_abuse --mode noisy                   # --alg-none-count / --expired-count / --hijack-count
python -m simulators.hunt_03_ssrf_egress --mode low-and-slow
```

Then:

```bash
make validate [SEED=1337]   # baseline -> BOLA -> JWT -> SSRF, in order; scores TP/FP/FN/precision
make cleanup                # delete lab-labelled documents and alerts, clear the local ledger
make down
python -m tools.labctl sigma-check          # lint Sigma rules against config/field_mapping.yaml
python -m tools.labctl verify-no-secrets    # search the SIEM for ledgered raw tokens and passwords
make test
```

Endpoints on the host: gateway `127.0.0.1:8080`, OpenSearch `127.0.0.1:9200`, Dashboards `127.0.0.1:5601`, Jupyter `127.0.0.1:8888`.

## Scenarios

| Scenario | Endpoint | OWASP | Simulator |
|---|---|---|---|
| BOLA enumeration | `GET /api/v1/invoices/{id}` | API1:2023 | `hunt_01_bola_enum` |
| JWT `alg=none`, expired replay, same-JTI hijack | `GET /api/v1/admin/audit`, `GET /api/v1/invoices/{id}` | API2:2023 | `hunt_02_jwt_abuse` |
| SSRF to metadata and internal services | `POST /api/v1/webhooks/preview` | API7:2023 | `hunt_03_ssrf_egress` |

See `docs/weaknesses.md` and `docs/attack-mapping.md` (ATT&CK IDs).

## Detections

One Sigma file and one OpenSearch monitor per scenario (`detections/sigma/`, `opensearch/monitors/`). Thresholds live in `config/detections.yaml`. Full details and tuning are in `docs/detections.md`.

| Scenario | Rule logic |
|---|---|
| BOLA | Per user and endpoint template in 10 min: more than 25 distinct `appsec.resource_id`, and (403 + 404 + cross-tenant 2xx) / total above 0.6. `batch_worker` excluded. 3 or fewer distinct ids suppressed. |
| JWT | `alg=none`, validation failure, or expired token accepted; or one JTI seen from 2 or more distinct client pairs in 5 min. |
| SSRF | Egress event whose `destination.ip` is in an internal CIDR or whose `destination.domain` is a listed internal host. |

The tests include a pure-Python reference evaluator (`labcommon/evaluator.py`) that mirrors this logic. Whether the live monitors agree with it has not been checked.

### Validation table layout

`make validate` prints a table in this layout and writes `reports/validation-<run_id>.json`. No real values are shown because the command has not been run against a live stack.

```
detection  TP  FP  FN  precision %  live alert
bola       …   …   …   …            yes/NO
jwt        …   …   …   …            yes/NO
ssrf       …   …   …   …            yes/NO
```

## PII and secret scrubbing

- The app deliberately forwards the raw `Authorization` header and login password to the Collector, so that scrubbing is a real control rather than an absence of data. The app's own stdout copy contains no sensitive fields.
- The Collector computes a salted SHA-256 `appsec.jwt.token_hash`, deletes the authorization header and password attributes, regex-redacts Bearer and JWT-shaped strings in other attributes, and clears the body. `appsec.jwt.jti` is kept in plain form for correlation.
- **Seal and fail closed.** A record gets `appsec.scrub.status=ok` only after scrubbing is verified. Sealed records go to OpenSearch. Unsealed records are reduced to `event.id` and `trace.id`, counted in `appsec.scrub_failures`, and logged to the debug exporter. They are never indexed.
- **Salt guard.** If `SCRUB_SALT` is unset or empty, `infra/otel/entrypoint.sh` logs "SCRUB_SALT is not configured" and starts `otel-config.nosalt.yaml`. That config has no OpenSearch exporter and an unhealthy health check, so nothing is forwarded.
- `labcommon/scrub_model.py` is a Python model of this logic. `labctl verify-no-secrets` searches OpenSearch for the raw secrets that simulators wrote to the gitignored `.lab/ledger.jsonl`.
- The Collector config itself has not been run. The model is tested, but the Collector's behaviour is unconfirmed (see `infra/otel/SPIKE.md`).

## Cardinality cost control

BOLA detection counts distinct resource ids, which is the expensive part:

- The monitor uses a `cardinality` aggregation with `precision_threshold: 3000`. Counts are approximate but memory use is bounded.
- `appsec.endpoint_template` (for example `/api/v1/invoices/{invoice_id}`) is a `keyword`. The raw `appsec.resource_id` is stored as a separate field, so aggregations group by template and never by raw path. `url.path` is mapped as `text` with no fielddata and is not aggregated.
- The index template sets `dynamic: false`, which stops unmapped fields from creating new mappings.
- Composite aggregation with a 10 minute histogram keeps buckets bounded per user and template.

## False-positive tuning

Documented in `docs/detections.md`: mobile retries, shared NAT, network-switch JTI changes, and the sensitivity versus false-positive trade-off for each threshold. To tune, edit `config/detections.yaml`, then update the matching monitor JSON and Sigma file.

## Known issues

These three inconsistencies are listed in `docs/detections.md` and are not fixed:

1. **JWT trigger scope differs.** The monitor's first trigger also fires on `jwt_validation_failed` (rejected tokens). The Sigma rule matches only accepted forged or expired tokens.
2. **JTI field differs.** The monitor aggregates on `appsec.jwt.jti`. The Sigma correlation uses `appsec.jwt.jti_hash`.
3. **SSRF allowlist is not wired.** `ssrf.allowed_destination_hosts` is empty by default and neither the Sigma rule nor the monitor reads it. Adding an allowed host requires editing both files by hand.

Related limits:

- The BOLA error ratio is enforced only by the monitor. Sigma cannot express it.
- Three Sigma documents are correlation rules. Many converters, including `sigma-cli` backends, do not support them, and a dropped correlation matches every single event. Treat the monitors as the reference and the Sigma files as portable documentation.
- The SSRF monitor does not join the API and egress events. It evaluates the egress event alone, and the `trace.id` is used for pivoting.

## Safety

- Every published port is bound to `127.0.0.1`. `make up` checks this and checks that ports are free, and runs `docker compose down` on a violation.
- `lab_internal` is `internal: true`, so containers have no route to the internet. `target-api` and `otel-collector` are on `lab_internal` only.
- The SSRF "metadata service" is simulated inside the `target-api` container (`LAB-METADATA-CANARY`). `target-api` needs `NET_ADMIN` to add that address to its loopback, then drops privileges.
- Simulators refuse any target other than the loopback gateway: scheme `http`, the configured port, and every resolved address equal to the bind address. Otherwise they print an "outside the Lab" message and exit 2 without sending a request.
- OpenSearch runs with the security plugin disabled. Do not expose it beyond the host.
- The target app is intentionally vulnerable. Do not deploy it anywhere.

## Layout

```
app/            vulnerable FastAPI target, telemetry middleware, metadata simulator
infra/          envoy, otel collector, opensearch template and pipeline
config/         lab.toml, detections.yaml, field_mapping.yaml, ip_enrichment.yaml
detections/     Sigma rules          opensearch/   monitors and dashboards
labcommon/      pure logic (schema, scrubber model, evaluator, metrics, safety)
simulators/     baseline and attack simulators
tools/labctl/   up, setup, validate, cleanup, sigma-check, verify-no-secrets
notebooks/      01 BOLA, 02 JWT, 03 SSRF hunting notebooks
docs/           field mapping, weaknesses, attack mapping, detections
tests/          unit, property, integration
```
