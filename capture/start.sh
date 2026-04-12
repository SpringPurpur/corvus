#!/bin/bash
# start.sh — build the capture engine then start it on the selected interface.
#
# Interface selection — three modes evaluated in priority order:
#
#   1. Explicit      CAPTURE_INTERFACE=eth0 in .env (or compose environment).
#                    Use for SPAN/TAP port deployments or any fixed interface.
#
#   2. Promiscuous   Any UP interface already in PROMISC mode is used
#                    automatically. Set the interface before starting:
#                      ip link set <iface> promisc on
#                    Matches both physical NICs and Docker bridges, so this
#                    also covers the testbed case when Docker sets PROMISC
#                    on the bridge automatically.
#
#   3. Testbed       Auto-detect the Docker bridge for 172.20.0.0/24 via the
#                    routing table. Fallback so the demo works with no config.
#
# On restart the interface is re-selected, so an interface put into PROMISC
# after the first failed attempt is picked up without manual intervention.

BUILD_DIR="/app/capture/build"
BINARY="$BUILD_DIR/capture_engine"

# ── Build ─────────────────────────────────────────────────────────────────────

echo "[monitor] Building capture engine..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-march=native" -Wno-dev 2>&1 | tail -2
make -j"$(nproc)" 2>&1 | tail -2
echo "[monitor] Build complete."

# ── Interface selection ───────────────────────────────────────────────────────

select_interface() {

    # Mode 1 — explicit env var
    if [ -n "${CAPTURE_INTERFACE:-}" ]; then
        if ! ip link show "$CAPTURE_INTERFACE" &>/dev/null; then
            echo "[monitor] ERROR: interface '$CAPTURE_INTERFACE' not found."
            echo "[monitor] Available interfaces:"
            ip -o link show | awk -F': ' '{printf "  %-16s %s\n", $2, $3}'
            return 1
        fi
        echo "[monitor] Mode 1 — explicit interface: $CAPTURE_INTERFACE"
        echo "$CAPTURE_INTERFACE"
        return 0
    fi

    # Mode 2 — first UP+PROMISC interface (not loopback or veth pairs)
    PROMISC=$(ip -o link show | \
        awk '/PROMISC/ && /[,<]UP[,>]/ { gsub(/:/, "", $2); print $2 }' | \
        grep -v -E '^(lo|veth)' | \
        head -1)

    if [ -n "$PROMISC" ]; then
        echo "[monitor] Mode 2 — promiscuous interface: $PROMISC"
        echo "$PROMISC"
        return 0
    fi

    # Mode 3 — Docker bridge for the testbed subnet
    BRIDGE=$(ip route show 172.20.0.0/24 2>/dev/null | awk '{print $3}' | head -1)
    if [ -n "$BRIDGE" ]; then
        echo "[monitor] Mode 3 — testbed bridge: $BRIDGE"
        echo "$BRIDGE"
        return 0
    fi

    # Nothing found — print guidance and fail
    echo "[monitor] ERROR: no suitable capture interface found."
    echo "[monitor]"
    echo "[monitor] To resolve:"
    echo "[monitor]   A) Set CAPTURE_INTERFACE=<iface> in .env and restart."
    echo "[monitor]   B) Put an interface into promiscuous mode and restart:"
    echo "[monitor]        ip link set <iface> promisc on"
    echo "[monitor]"
    echo "[monitor] Available interfaces:"
    ip -o link show | awk -F': ' '{printf "  %-16s %s\n", $2, $3}'
    return 1
}

# ── BPF filter ────────────────────────────────────────────────────────────────

FILTER_ARGS=""
if [ -n "${CAPTURE_FILTER:-}" ]; then
    echo "[monitor] BPF filter: $CAPTURE_FILTER"
    FILTER_ARGS="-f ${CAPTURE_FILTER}"
fi

# ── Restart loop ──────────────────────────────────────────────────────────────
# Keeps the container alive after any exit. Interface is re-selected on each
# restart so mode-2 detection picks up an interface set promiscuous after
# the initial start.

while true; do
    IFACE=$(select_interface) || { sleep 5; continue; }
    echo "[monitor] Starting capture on $IFACE..."
    "$BINARY" -i "$IFACE" $FILTER_ARGS
    echo "[monitor] capture_engine exited (code $?), restarting in 3s..."
    sleep 3
done
