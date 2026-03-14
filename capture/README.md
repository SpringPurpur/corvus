# ids_capture — C Capture Engine

Real-time libpcap flow tracker for the Corvus IDS.

## Build (inside monitor container)

```bash
cd /app/capture
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

## Run

```bash
# Start IPC listener in one terminal
./build/inspect_ipc

# Start capture in another (requires NET_RAW / NET_ADMIN)
./build/capture_engine -i eth0
```

## Test

```bash
./build/test_features    # all PASS = AVX2 assembly correct
```

## File layout

```
src/
  flow_types.h        — flow_key_t and flow_record_t struct definitions
  packet_parser.h/.c  — Ethernet/IP/TCP/UDP zero-copy parser
  flow_table.h/.c     — FNV-1a hash map, 65536 slots, linear probe
  features.h/.c       — per-packet accumulation + AVX2 finalisation
  ipc_writer.h/.c     — Unix domain socket client with ring buffer
  main.c              — libpcap loop and pcap callback

asm/
  features_avx2.asm   — AVX2 mean/std and flag-count routines

tests/
  test_features.c     — unit tests (no network required)
  inspect_ipc.c       — debug: binds socket, prints flows as JSON
```
