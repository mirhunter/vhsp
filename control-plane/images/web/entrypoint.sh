#!/bin/sh
set -eu

mkdir -p /run/nginx
mkdir -p /var/www/html
mkdir -p /var/log/vhsp

# Recovers the real client IP into nginx's $remote_addr (see nginx.conf's
# vhsp-realip.conf include) instead of every access-log line showing the
# immediate proxy hop's own address. Resolved by container name via
# Docker's own embedded DNS, not a hardcoded IP -- same "trust the name,
# not a snapshot of the address" pattern already used for mail's
# bracket-notation nexthops, since a plain IP would go stale the moment
# that container is ever recreated.
#
# Two dynamic hops now, not one: the Coraza WAF sidecar
# (provisioner.py's _create_waf_container) sits directly in front of
# this container as of that feature shipping -- Traefik -> WAF -> here,
# not Traefik -> here directly -- so the WAF container's own address is
# now the actual immediate peer nginx sees, with Traefik one hop further
# back. WAF_CONTAINER_NAME (set by _create_web_container, deterministic
# from this tenant's own slug) is resolved the same way `traefik` always
# was. Confirmed directly (not assumed) that the WAF image's own reverse
# proxy correctly *appends* to X-Forwarded-For via
# $proxy_add_x_forwarded_for rather than overwriting it, so both hops
# need trusting for real_ip_recursive to walk all the way back to the
# genuine client entry: WAF (immediate peer) -> Traefik (next entry in
# the chain) -> real client. Anything further upstream still (e.g. this
# deployment's swarm Traefik) remains a platform-topology fact this
# container can't discover on its own, so it still comes in via
# VHSP_TRUSTED_PROXY_CIDRS (config.py's WEB_TRUSTED_PROXY_CIDRS) same as
# before. If DNS resolution fails for either name, fall back to trusting
# nothing rather than blocking startup or guessing -- $remote_addr just
# stays the raw TCP peer, same as before either of these existed, not
# worse.
traefik_ip="$(getent hosts traefik 2>/dev/null | awk '{print $1; exit}')"
waf_ip="$(getent hosts "${WAF_CONTAINER_NAME:-}" 2>/dev/null | awk '{print $1; exit}')"
{
    if [ -n "$traefik_ip" ]; then
        echo "set_real_ip_from $traefik_ip/32;"
    fi
    if [ -n "$waf_ip" ]; then
        echo "set_real_ip_from $waf_ip/32;"
    fi
    old_ifs="$IFS"
    IFS=','
    for cidr in ${VHSP_TRUSTED_PROXY_CIDRS:-}; do
        [ -n "$cidr" ] && echo "set_real_ip_from $cidr;"
    done
    IFS="$old_ifs"
    echo 'real_ip_header X-Forwarded-For;'
    echo 'real_ip_recursive on;'
} > /etc/nginx/vhsp-realip.conf

# php-fpm.conf has no [global] error_log directive baked in by default
# (falls back to a compiled-in path inside the container's own
# filesystem, invisible to the tenant-admin container). Insert one
# pointing at the shared logs volume -- guarded so a container restart
# (not recreate) doesn't duplicate the line on re-run.
if ! grep -q '^error_log = /var/log/vhsp/php-error.log' /etc/php83/php-fpm.conf; then
    sed -i '/^\[global\]/a error_log = /var/log/vhsp/php-error.log' /etc/php83/php-fpm.conf
fi
# php-fpm creates this with its own restrictive umask (verified: root:root
# 600) regardless of the directory's mode -- same issue and same fix as
# images/mail/entrypoint.sh's mail.log.
touch /var/log/vhsp/php-error.log
chmod 666 /var/log/vhsp/php-error.log

# All PHP functions a tenant is allowed to self-service re-enable (see
# images/tenant-admin/). Fixed list, not tenant-configurable which
# functions exist in the set -- only which of these are currently on.
ALL_TOGGLEABLE="exec shell_exec system passthru proc_open popen proc_close proc_get_status proc_nice proc_terminate pcntl_exec"

ENABLED_FILE=/data/enabled_functions.txt
TENANT_CONF=/etc/php83/php-fpm.d/zz-tenant.conf

write_tenant_conf() {
    enabled="$(cat "$ENABLED_FILE" 2>/dev/null || true)"
    disabled=""
    for fn in $ALL_TOGGLEABLE; do
        if ! printf '%s\n' "$enabled" | grep -qx "$fn"; then
            disabled="${disabled}${disabled:+,}${fn}"
        fi
    done
    printf '[www]\nphp_admin_value[disable_functions] = %s\n' "$disabled" > "$TENANT_CONF"
}

NGINX_TENANT_CONF=/etc/nginx/vhsp-tenant.conf
NGINX_HTPASSWD=/etc/nginx/htpasswd
BASIC_AUTH_FILE=/data/basic_auth.txt
ERROR_PAGES_FILE=/data/error_pages.txt
REDIRECTS_FILE=/data/redirects.txt
IP_ACL_FILE=/data/ip_acl.txt
NOEXEC_DIRS_FILE=/data/noexec_dirs.txt

# Regenerates $NGINX_TENANT_CONF from the tenant-admin-writable data files
# above (password protection, custom error pages, IP allow/deny,
# redirects, no-exec directories -- images/tenant-admin/'s nginx-config
# self-service pages),
# tests it with the real `nginx -t` (there's no way to test an include
# fragment in isolation), and only replaces the live file / reloads if
# it's valid. tenant-admin already validates each field before writing
# these files, but this is the actual trust boundary -- it's the code
# that decides what becomes real nginx syntax -- so every value is
# re-validated here too rather than trusted blindly. A tenant can only
# ever break their OWN site this way (each tenant is a fully separate
# nginx process/container, no shared config with anyone else), but
# "reload into a config that won't parse and take the whole site down"
# is still a real, avoidable failure mode worth guarding against.
write_tenant_nginx_conf() {
    tmp="$(mktemp)"

    if [ -s "$BASIC_AUTH_FILE" ] && grep -q ':' "$BASIC_AUTH_FILE"; then
        head -n1 "$BASIC_AUTH_FILE" > "$NGINX_HTPASSWD"
        {
            echo 'auth_basic "Restricted";'
            echo "auth_basic_user_file $NGINX_HTPASSWD;"
        } >> "$tmp"
    fi

    if [ -s "$ERROR_PAGES_FILE" ]; then
        while IFS=' ' read -r code path; do
            case "$code" in
                [0-9][0-9][0-9]) ;;
                *) continue ;;
            esac
            case "$path" in
                /*) ;;
                *) continue ;;
            esac
            case "$path" in
                *[\;\{\}\"\'\\\$\ ]*) continue ;;
            esac
            echo "error_page $code $path;" >> "$tmp"
        done < "$ERROR_PAGES_FILE"
    fi

    if [ -s "$IP_ACL_FILE" ]; then
        mode="$(head -n1 "$IP_ACL_FILE")"
        case "$mode" in
            allow|deny)
                tail -n +2 "$IP_ACL_FILE" | while IFS= read -r ip; do
                    [ -n "$ip" ] || continue
                    case "$ip" in
                        *[\;\{\}\"\'\\\$\ ]*) continue ;;
                    esac
                    echo "$mode $ip;" >> "$tmp"
                done
                if [ "$mode" = "allow" ]; then
                    echo "deny all;" >> "$tmp"
                else
                    echo "allow all;" >> "$tmp"
                fi
                ;;
        esac
    fi

    if [ -s "$REDIRECTS_FILE" ]; then
        while IFS=' ' read -r from to; do
            case "$from" in
                /*) ;;
                *) continue ;;
            esac
            case "$from" in
                *[\;\{\}\"\'\\\$\ ]*) continue ;;
            esac
            case "$to" in
                http://*|https://*|/*) ;;
                *) continue ;;
            esac
            case "$to" in
                *[\;\{\}\"\'\\\$\ ]*) continue ;;
            esac
            printf 'location = %s { return 301 %s; }\n' "$from" "$to" >> "$tmp"
        done < "$REDIRECTS_FILE"
    fi

    # Denies PHP execution under tenant-declared writable/upload
    # directories regardless of what ends up in them -- see
    # nginx-tenant-hardening.md. This location is emitted into
    # $NGINX_TENANT_CONF, which the static nginx.conf `include`s *before*
    # its own generic `location ~ \.php$` block, so nginx's regex-location
    # matching (evaluated in file order, first match wins) checks this one
    # first. tenant-admin already validates each line before writing this
    # file, but -- same reasoning as every other section above -- this is
    # the actual trust boundary that turns tenant data into real nginx
    # regex syntax, so every entry is re-validated here too.
    if [ -s "$NOEXEC_DIRS_FILE" ]; then
        dirs_pattern=""
        while IFS= read -r dir; do
            [ -n "$dir" ] || continue
            case "$dir" in
                /*) continue ;;   # no leading slash
                */) continue ;;   # no trailing slash
                *..*) continue ;; # no path traversal
            esac
            case "$dir" in
                *[!A-Za-z0-9_./-]*) continue ;;
            esac
            # Escape the one regex-special character this charset allows
            # ('.') so it means a literal dot, not "any character" --
            # letters/digits/_/-// are already regex-safe as-is.
            escaped="$(printf '%s' "$dir" | sed 's/\./\\./g')"
            dirs_pattern="${dirs_pattern}${dirs_pattern:+|}${escaped}"
        done < "$NOEXEC_DIRS_FILE"
        if [ -n "$dirs_pattern" ]; then
            printf 'location ~* ^/(%s)/.*\\.php$ {\n  deny all;\n}\n' "$dirs_pattern" >> "$tmp"
        fi
    fi

    [ -f "$NGINX_TENANT_CONF" ] && cp "$NGINX_TENANT_CONF" "$NGINX_TENANT_CONF.bak"
    mv "$tmp" "$NGINX_TENANT_CONF"

    if nginx -t 2>/tmp/vhsp-nginx-test-err; then
        rm -f "$NGINX_TENANT_CONF.bak"
        # -s (non-empty), not -f: `nginx -t` itself creates an empty
        # placeholder pid file as a side effect even though it never starts
        # a master process -- verified `-f` alone false-positives on that
        # and fires a premature `nginx -s reload` against a pid file with
        # no actual number in it, which fails loudly enough to abort this
        # whole script under `set -e` and crash-loop the container. kill -0
        # additionally confirms it's a real, running process, not just a
        # stale non-empty pid file left over from an unclean exit. `|| true`
        # matches the existing php-fpm reload guard below -- a reload
        # failure should never be allowed to take down an already-running
        # site.
        if [ -s /run/nginx/nginx.pid ] && kill -0 "$(cat /run/nginx/nginx.pid)" 2>/dev/null; then
            nginx -s reload || true
        fi
    else
        {
            echo "vhsp: generated $NGINX_TENANT_CONF failed nginx -t, reverting to last-known-good:"
            cat /tmp/vhsp-nginx-test-err
        } >> /var/log/vhsp/web-error.log
        if [ -f "$NGINX_TENANT_CONF.bak" ]; then
            mv "$NGINX_TENANT_CONF.bak" "$NGINX_TENANT_CONF"
        else
            : > "$NGINX_TENANT_CONF"
        fi
    fi
}

mkdir -p /data
write_tenant_conf
write_tenant_nginx_conf

php-fpm83 -D -g /run/php-fpm.pid

# Self-contained by design (see architecture.md's tenant-self-service
# note: no call back into the control plane). The tenant-admin container
# only ever writes $ENABLED_FILE on a shared volume; this loop -- running
# inside the web container's own process boundary -- is what actually
# regenerates the pool config and reloads php-fpm. SIGUSR2 triggers a
# graceful reload: verified this spawns genuinely new worker processes
# that pick up the new disable_functions value, not just a config re-read
# that leaves old workers (and their process-start-time ini values) running.
(
    last_mtime=""
    last_nginx_mtime=""
    while true; do
        sleep 3
        mtime="$(stat -c %Y "$ENABLED_FILE" 2>/dev/null || echo "")"
        if [ "$mtime" != "$last_mtime" ]; then
            last_mtime="$mtime"
            write_tenant_conf
            if [ -f /run/php-fpm.pid ]; then
                kill -USR2 "$(cat /run/php-fpm.pid)" 2>/dev/null || true
            fi
        fi

        # Combined fingerprint of all four nginx-self-service data files --
        # any one changing regenerates/reloads together rather than
        # tracking each individually, matching the PHP-toggle loop's own
        # "poll and diff a fingerprint" style above.
        nginx_mtime="$(stat -c %Y "$BASIC_AUTH_FILE" "$ERROR_PAGES_FILE" "$REDIRECTS_FILE" "$IP_ACL_FILE" "$NOEXEC_DIRS_FILE" 2>/dev/null | tr '\n' ',' || true)"
        if [ "$nginx_mtime" != "$last_nginx_mtime" ]; then
            last_nginx_mtime="$nginx_mtime"
            write_tenant_nginx_conf
        fi
    done
) &

exec nginx -g "daemon off;"
