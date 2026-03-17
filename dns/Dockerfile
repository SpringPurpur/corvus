FROM alpine:3.19

RUN apk add --no-cache dnsmasq

# Serve DNS for the ids_net (172.20.0.0/24).
# Resolves internal hostnames and forwards everything else to 8.8.8.8.
COPY dnsmasq.conf /etc/dnsmasq.conf

EXPOSE 53/udp

CMD ["dnsmasq", "--no-daemon", "--log-queries"]
