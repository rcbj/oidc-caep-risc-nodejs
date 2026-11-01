#!/bin/sh
# Refresh the listener CA trust chain named by tlsCa, then start whatever was asked (the demo).
# A provider that is down, or a read-only mount, leaves the file as it is and the demo still starts.
node /app/scripts/trust-chain.mjs --config "${OIDC_CONFIG:-/app/demo/oidc.json}" || true
exec "$@"
