#!/bin/bash
# start.sh — build (if needed) then start the capture engine on the ids_net bridge.
# Note: no set -e — capture_engine exits with non-zero when killed for rebuild;
# the restart loop handles this gracefully rather than aborting the script.

BUILD_DIR="/app/capture/build"
BINARY="$BUILD_DIR/capture_engine"

# Always rebuild — source is bind-mounted so the binary must be compiled
# inside the container (correct architecture/libs). Rebuilding on every
# container start ensures source changes are always picked up.
echo "[monitor] Building capture engine..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-march=native" -Wno-dev
make -j"$(nproc)"
echo "[monitor] Build complete."

# Determine capture interface.
# CAPTURE_INTERFACE env var takes precedence — set it in .env for physical
# deployments (SPAN/TAP port, e.g. CAPTURE_INTERFACE=ens3).
# If unset, auto-detect the bridge carrying ids_net traffic (172.20.0.0/24).
if [ -n "$CAPTURE_INTERFACE" ]; then
    IFACE="$CAPTURE_INTERFACE"
    echo "[monitor] Using configured interface: $IFACE"
else
    IFACE=$(ip route show 172.20.0.0/24 2>/dev/null | awk '{print $3}' | head -1)
    if [ -z "$IFACE" ]; then
        echo "[monitor] ERROR: could not determine bridge interface for 172.20.0.0/24"
        echo "[monitor] Set CAPTURE_INTERFACE in .env to specify the interface manually."
        echo "[monitor] Available interfaces:"
        ip link show
        exit 1
    fi
    echo "[monitor] Auto-detected interface: $IFACE"
fi

# Optional BPF filter — restrict capture to a subnet or exclude management traffic.
# Example: CAPTURE_FILTER="ip and not host 192.168.1.1"
FILTER_ARGS=""
if [ -n "$CAPTURE_FILTER" ]; then
    echo "[monitor] BPF filter: $CAPTURE_FILTER"
    FILTER_ARGS="-f $CAPTURE_FILTER"
fi

# Restart loop — if capture_engine exits for any reason (killed for rebuild,
# crash, signal) the container stays alive and restarts it automatically.
while true; do
    "$BINARY" -i "$IFACE" $FILTER_ARGS
    EXIT_CODE=$?
    echo "[monitor] capture_engine exited (code $EXIT_CODE), restarting in 2s..."
    sleep 2
done
