#!/bin/bash
# start.sh — build (if needed) then start the capture engine on the ids_net bridge.
set -e

BUILD_DIR="/app/capture/build"
BINARY="$BUILD_DIR/capture_engine"

# Build if the binary doesn't exist yet
if [ ! -f "$BINARY" ]; then
    echo "[monitor] Binary not found — building capture engine..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-march=native"
    make -j"$(nproc)"
    echo "[monitor] Build complete."
fi

# Find the bridge interface that carries ids_net traffic (172.20.0.0/24).
# ip route shows the outgoing interface for a given destination prefix.
IFACE=$(ip route show 172.20.0.0/24 2>/dev/null | awk '{print $3}' | head -1)

if [ -z "$IFACE" ]; then
    echo "[monitor] ERROR: could not determine bridge interface for 172.20.0.0/24"
    echo "[monitor] Available interfaces:"
    ip link show type bridge
    exit 1
fi

echo "[monitor] Capturing on interface: $IFACE"
exec "$BINARY" -i "$IFACE"
