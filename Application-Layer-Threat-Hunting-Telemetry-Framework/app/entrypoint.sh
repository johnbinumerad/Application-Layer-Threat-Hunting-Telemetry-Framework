#!/bin/sh
# Container entrypoint: runs as root only long enough to add the simulated
# metadata address to the loopback interface (needs NET_ADMIN), then drops to an
# unprivileged user with setpriv and starts the app (which also starts the
# metadata simulator on 169.254.169.254:80).
set -eu

META_IP="${LAB_METADATA_IP:-169.254.169.254}"

if [ "$(id -u)" = "0" ]; then
    # Idempotent: ignore "already exists" on container restart.
    ip addr add "${META_IP}/32" dev lo 2>/dev/null || ip addr show dev lo | grep -q "${META_IP}" || {
        echo "entrypoint: failed to add ${META_IP} to lo (NET_ADMIN missing?)" >&2
    }
    exec setpriv --reuid=10001 --regid=10001 --clear-groups \
        --inh-caps=-all --bounding-set=-all --no-new-privs -- "$@"
fi

exec "$@"
