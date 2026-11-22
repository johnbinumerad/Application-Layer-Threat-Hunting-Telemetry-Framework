# Contrib Collector plus a static busybox sh so entrypoint.sh can run (the base image has no shell).
FROM busybox:1.36.1-musl AS busybox

FROM otel/opentelemetry-collector-contrib:0.104.0

COPY --from=busybox /bin/busybox /busybox/busybox
COPY --from=busybox /bin/busybox /bin/sh
COPY otel-config.yaml /etc/otelcol/otel-config.yaml
COPY otel-config.nosalt.yaml /etc/otelcol/otel-config.nosalt.yaml
COPY --chmod=0755 entrypoint.sh /entrypoint.sh

EXPOSE 4317 4318 13133
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
