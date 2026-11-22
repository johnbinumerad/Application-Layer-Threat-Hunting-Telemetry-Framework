#!/bin/sh
# Salt guard (Req 4.7): refuse to forward records when SCRUB_SALT is unset or empty.
set -eu

if [ -z "${SCRUB_SALT:-}" ]; then
  echo "FATAL: SCRUB_SALT is not configured; refusing to forward records" >&2
  exec /otelcol-contrib --config=/etc/otelcol/otel-config.nosalt.yaml
fi

exec /otelcol-contrib --config=/etc/otelcol/otel-config.yaml
