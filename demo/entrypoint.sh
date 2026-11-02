#!/bin/sh
# The image carries the listener CA trust chain tlsCa names, from build time. Refresh it from the
# provider at start (a development iya-sts makes a new CA when it restarts), unless
# TLS_CA_REFRESH=0, then start whatever was asked (the demo). A provider that is down, or a
# read-only file, leaves the file as it is and the demo still starts.
if [ "${TLS_CA_REFRESH:-1}" != "0" ]; then
  node /app/scripts/trust-chain.mjs --config "${OIDC_CONFIG:-/app/demo/oidc.json}" || true
fi
exec "$@"
