FROM debian:12-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        postfix \
        dovecot-core \
        dovecot-imapd \
        dovecot-lmtpd \
        dovecot-sieve \
        dovecot-managesieved \
        opendkim \
        opendkim-tools \
        openssl \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 25 143 993 4190

ENTRYPOINT ["/entrypoint.sh"]
