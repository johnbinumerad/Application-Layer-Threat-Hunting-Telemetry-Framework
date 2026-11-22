# Collector spike checks

Status: configuration authored but NOT yet run against a live Collector (not verified in this task). Verify with `docker build infra/otel` and `otelcol-contrib validate --config=...`.

## Checks to confirm

1. **opensearch exporter output**: confirm `mapping.mode: flatten_attributes` writes `@timestamp` and flat dotted ECS attribute keys into `appsec-telemetry-YYYY.MM.DD`. If it nests or renames them, use the fallback below.
2. **OTTL behaviour**: `SHA256(Concat([salt, value], ""))` is deterministic; `replace_pattern`/`replace_all_patterns` redact Bearer and JWT strings; `String(attributes)` in the seal step serializes the attribute map to JSON so the regexes can scan all values.
3. **Routing connector**: `context: log` conditions with `default_pipelines` send unsealed records to `logs/scrub_failed`. Syntax differs across Collector versions (image pinned to 0.104.0).
4. **No-salt mode**: the `nop` exporter plus `filter/drop_all` guarantee no export. The health_check unhealthy reporting may need a different mechanism if `check_collector_pipeline` does not trip with the nop exporter; alternative is making the entrypoint skip starting health_check (Compose then marks it unhealthy because :13133 is not listening).
5. **Pinned image tags**: `otel/opentelemetry-collector-contrib:0.104.0`, `busybox:1.36.1-musl` should be confirmed to exist.

## Fallback decision

If the exporter cannot write `@timestamp` and flat ECS attributes, replace the `opensearch` exporter with a `file` exporter and add a small Python bulk shipper in the image that tails the file and calls the OpenSearch `_bulk` API. Scrub stages are unchanged.
