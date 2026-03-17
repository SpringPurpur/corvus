FROM alpine:3.19

# curl/wget — HTTP flows of varied sizes
# openssh-client + sshpass — legitimate SSH sessions
# bind-tools — dig for UDP DNS flows
# bash — scripts use bash arithmetic and $RANDOM
RUN apk add --no-cache \
    bash \
    curl \
    wget \
    openssh-client \
    sshpass \
    bind-tools \
    busybox-extras

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

CMD ["/bin/bash", "/scripts/normal_traffic.sh"]
