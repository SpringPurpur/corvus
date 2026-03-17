FROM alpine:3.19

RUN apk add --no-cache chrony

COPY chrony.conf /etc/chrony/chrony.conf

EXPOSE 123/udp

# -x: don't adjust the system clock (container doesn't need real timekeeping,
# just needs to respond to NTP queries so clients generate UDP flows)
CMD ["chronyd", "-d", "-x", "-f", "/etc/chrony/chrony.conf"]
