FROM nginx:alpine

# Generate content files of different sizes so client downloads produce
# varied pkt_len_mean, flow_duration_s, and down_up_ratio in the IF baseline.
#   index.html  ~400B  — tiny response, quick flows
#   medium.bin  100KB  — moderate duration, mid pkt_len_mean
#   large.bin     1MB  — longer flow, high pkt_len_mean, high down/up ratio
RUN dd if=/dev/urandom of=/usr/share/nginx/html/medium.bin bs=1024 count=100 2>/dev/null \
 && dd if=/dev/urandom of=/usr/share/nginx/html/large.bin  bs=1024 count=1024 2>/dev/null \
 && printf '<html><body><h1>Corvus IDS — victim web</h1><p>Normal traffic target.</p></body></html>\n' \
        > /usr/share/nginx/html/index.html
