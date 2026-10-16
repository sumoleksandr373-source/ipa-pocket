#!/bin/sh
set -eu

# Run the Anisette V3 server locally inside the same container. This avoids
# depending on externally hosted Anisette endpoints while keeping TLS verification
# enabled for normal HTTPS requests.
export HOME="${ANISETTE_HOME:-/home/Alcoholic}"
mkdir -p "$HOME/.config/anisette-v3/lib" "$HOME/.config/anisette-v3/provisioning" /opt/anisette-v3/provisioning

/usr/local/bin/anisette-v3-server &
ANIS_PID=$!

# Wait up to 45 seconds for the local HTTP endpoint. A 404 is still a response,
# so curl is intentionally not invoked with --fail.
ready=0
i=0
while [ "$i" -lt 45 ]; do
  if ! kill -0 "$ANIS_PID" 2>/dev/null; then
    echo "[IPA Pocket] Local Anisette V3 server stopped during startup." >&2
    exit 1
  fi
  if curl --silent --show-error --max-time 2 http://127.0.0.1:6969/ -o /dev/null 2>/dev/null; then
    ready=1
    break
  fi
  i=$((i + 1))
  sleep 1
done

if [ "$ready" -ne 1 ]; then
  echo "[IPA Pocket] Local Anisette V3 server did not become ready on 127.0.0.1:6969." >&2
  exit 1
fi

echo "[IPA Pocket] Local Anisette V3 server is ready on loopback."
exec npm start
