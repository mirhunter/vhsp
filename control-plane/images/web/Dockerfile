FROM alpine:3.19

RUN apk add --no-cache \
        nginx \
        php83-fpm \
        php83-mysqli \
        php83-pdo \
        php83-pdo_mysql \
        php83-mbstring \
        php83-session \
        php83-opcache \
        php83-json \
        php83-fileinfo \
        php83-xml \
        php83-curl \
        php83-gd \
        php83-zip \
    && ln -sf /usr/bin/php83 /usr/bin/php

# expose_php is PHP_INI_SYSTEM-only -- can't be set via php_admin_value in
# www.conf (that's PHP_INI_ALL/PERDIR territory), only via a real php.ini
# file. Off by default, platform-wide, same as nginx's own server_tokens
# already being off -- no tenant has a legitimate reason to want their
# PHP version fingerprinted in every response header.
RUN echo 'expose_php = Off' > /etc/php83/conf.d/99-vhsp-security.ini

COPY nginx.conf /etc/nginx/http.d/default.conf
COPY www.conf /etc/php83/php-fpm.d/www.conf
COPY maintenance.html /usr/share/vhsp/maintenance.html
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
