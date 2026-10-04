"""
nginx remediation. Configuration changes are "NGX:" edits (see edit.py):
whole-line directives on the files nginx reads, backed up, tested with
nginx -t and rolled back on failure, then a reload. File ownership, modes
and the worker account are changed with ordinary commands. Every fix is
verified by re-running the benchmark rule on a fresh collection.

Settings made in http with "set" replace the same setting in server and
location blocks (they are commented out, marked "disabled by ngcorion"), so
the whole configuration follows the hardened value; client_max_body_size
and large_client_header_buffers are set in http only, leaving site-specific
values alone.
"""

from app.modules.benchmark.templates import HardeningTemplate, ParamMeta, TemplateSet

from . import rules as R
from .edit import CSP_POLICIES

TEMPLATES = TemplateSet()
TEMPLATES.param(ParamMeta(
    name="CONFIRM", input_type="select", label="Confirm the change",
    description="This change has side effects described in the check's warning. Choose 'yes' to apply it.",
    required=True, options=["yes"]))
TEMPLATES.param(ParamMeta(
    name="MAX_BODY_SIZE", input_type="text", label="Maximum request body size",
    description="client_max_body_size for the whole server: a number with k, m or g (CIS suggests 100k; uploads "
                "need more).", required=True, validation=r"[1-9][0-9]{0,5}[kKmMgG]?", placeholder="1m"))
TEMPLATES.param(ParamMeta(
    name="HEADER_BUFFERS", input_type="text", label="Large header buffers",
    description="large_client_header_buffers: number and size (CIS suggests 2 1k; sites with large cookies need "
                "4 8k).", required=True, validation=r"[1-9][0-9]? [1-9][0-9]{0,3}[kK]", placeholder="2 1k"))
TEMPLATES.param(ParamMeta(
    name="CONN_PER_IP", input_type="number", label="Connections per address",
    description="Simultaneous connections allowed from one client address.", required=True,
    min_value=1, max_value=10000, placeholder="10"))
TEMPLATES.param(ParamMeta(
    name="REQ_RATE", input_type="number", label="Requests per second per address",
    description="Sustained request rate allowed from one client address.", required=True,
    min_value=1, max_value=10000, placeholder="10"))
TEMPLATES.param(ParamMeta(
    name="REQ_BURST", input_type="number", label="Request burst",
    description="Requests above the rate accepted at once before nginx answers 503.", required=True,
    min_value=0, max_value=100000, placeholder="20"))
TEMPLATES.param(ParamMeta(
    name="CSP_POLICY", input_type="select", label="Content Security Policy",
    description="default-src-self: content only from the site itself; -no-framing also forbids embedding the "
                "site in frames.", required=True, options=sorted(CSP_POLICIES)))
TEMPLATES.param(ParamMeta(
    name="REFERRER_POLICY", input_type="select", label="Referrer policy",
    description="What browsers send in the Referer header when leaving the site.", required=True,
    options=list(R.SAFE_REFERRER)))

# The worker account named by the user directive (nobody when unset).
WORKER = ("u=$(nginx -T 2>/dev/null | awk '$1 == \"user\" { v = $2; sub(/;$/, \"\", v); print v; exit }'); "
          "[ -n \"$u\" ] || u=nobody; [ \"$u\" != root ] || { echo 'nginx workers run as root (2.2.1)'; exit 1; }; ")


def _add(sec, description, statements, warning=None, params=(), restart=False):
    TEMPLATES.add(HardeningTemplate(
        check_id=f"NGINX-{sec}", description=description, statements=statements,
        verify_statements=[f"NGX:check NGINX-{sec}"], parameters=list(params), warning=warning,
        requires_restart=restart))


# 2.1 Modules
_add("2.1.3", "Turn gzip compression off", ["NGX:set http gzip off", "NGX:comment gzip_static on",
                                             "NGX:comment gzip_static always"],
     warning="Responses are no longer compressed: more bandwidth for text content.", params=["CONFIRM"])
_add("2.1.4", "Turn directory listings off", ["NGX:comment autoindex on"],
     warning="Locations that relied on directory listings (download folders) show 403 instead.", params=["CONFIRM"])

# 2.2 Account
_add("2.2.2", "Lock the nginx worker account", [WORKER + "passwd -l \"$u\" >/dev/null 2>&1 || usermod -L \"$u\""])
_add("2.2.3", "Give the nginx worker account a no-login shell",
     [WORKER + "s=$(command -v nologin || echo /sbin/nologin); usermod -s \"$s\" \"$u\""])

# 2.3 Permissions
_add("2.3.1", "Make root the owner of /etc/nginx", ["chown -R root:root /etc/nginx"])
_add("2.3.2", "Restrict access to /etc/nginx",
     ["find /etc/nginx -type d -exec chmod go-w {} + && find /etc/nginx -type f -exec chmod ug-x,o-rwx {} +"],
     warning="Files under /etc/nginx become unreadable to other users. Files nginx workers read at request time "
             "(auth_basic_user_file, njs scripts) must then live elsewhere or be group-readable by the worker.",
     params=["CONFIRM"])
_add("2.3.3", "Secure the PID file",
     ["p=$(nginx -T 2>/dev/null | awk '$1 == \"pid\" { v = $2; sub(/;$/, \"\", v); print v; exit }'); "
      "[ -n \"$p\" ] || p=$(nginx -V 2>&1 | sed -n 's/.*--pid-path=\\([^ ]*\\).*/\\1/p'); [ -n \"$p\" ] || p=/run/nginx.pid; "
      "chown root:root \"$p\" && chmod u-x,go-wx \"$p\""])

# 2.4 Network
_add("2.4.2", "Reject requests for unknown host names (catch-all default server)", ["NGX:catchall"],
     warning="Requests by IP address or for names no server block lists get no answer (444), and TLS handshakes "
             "for unknown names are refused. Health checks and clients that connect by address must use a server "
             "name.", params=["CONFIRM"])
_add("2.4.3", "Close idle keep-alive connections after 10 seconds", ["NGX:set http keepalive_timeout 10"],
     warning="Replaces keepalive_timeout set in server and location blocks.")
_add("2.4.4", "Time out stalled responses after 10 seconds", ["NGX:set http send_timeout 10"],
     warning="Clients that read a response slower than one write per 10 seconds are disconnected.")

# 2.5 Information disclosure
_add("2.5.1", "Hide the nginx version (server_tokens off)", ["NGX:set http server_tokens off"])
_add("2.5.2", "Replace the stock nginx index and error pages",
     ["mkdir -p /var/backups/ngcorion-nginx/pages && chmod 700 /var/backups/ngcorion-nginx; "
      "for d in $(nginx -T 2>/dev/null | awk '$1 == \"root\" { v = $2; sub(/;$/, \"\", v); print v }' | sort -u) "
      "/usr/share/nginx/html /var/www/html; do for f in index.html index.htm index.nginx-debian.html 50x.html; do "
      "p=\"$d/$f\"; [ -f \"$p\" ] || continue; grep -qiE 'Welcome to nginx|nginx\\.org|An error occurred' \"$p\" "
      "|| continue; cp -p \"$p\" \"/var/backups/ngcorion-nginx/pages/$(echo \"$p\" | tr / _)\" && "
      "case \"$f\" in 50x.html) t='Service temporarily unavailable';; *) t='Service';; esac && "
      "printf '<!DOCTYPE html>\\n<html><head><meta charset=\"utf-8\"><title>%s</title></head>"
      "<body><p>%s</p></body></html>\\n' \"$t\" \"$t\" > \"$p\" || exit 1; done; done"],
     warning="The stock welcome and 50x pages are replaced by plain pages (originals kept in "
             "/var/backups/ngcorion-nginx/pages). Pages of real sites are left alone.", params=["CONFIRM"])
_add("2.5.4", "Hide X-Powered-By and Server from proxied responses",
     ["NGX:array proxy_hide_header X-Powered-By", "NGX:array proxy_hide_header Server"])

# 3 Logging
_add("3.2", "Turn access logging back on", ["NGX:comment access_log off --levels=http,server"])
_add("3.3", "Log errors at the info level", ["NGX:error-level info"],
     warning="The error log grows faster at info level.")
_add("3.4", "Rotate the nginx logs with logrotate",
     ["[ -d /etc/logrotate.d ] && command -v logrotate >/dev/null 2>&1 || { echo 'logrotate is not installed'; "
      "exit 1; }; [ -f /etc/logrotate.d/nginx ] || printf '%s\\n' '/var/log/nginx/*.log {' '    weekly' "
      "'    rotate 13' '    missingok' '    notifempty' '    compress' '    delaycompress' '    sharedscripts' "
      "'    postrotate' '        nginx -s reopen >/dev/null 2>&1 || true' '    endscript' '}' "
      "> /etc/logrotate.d/nginx"])
_add("3.7", "Pass the client address to proxied applications",
     ["NGX:array proxy_set_header X-Real-IP $remote_addr",
      "NGX:array proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for"])

# 4 TLS
_add("4.1.3", "Restrict the private keys to root",
     ["nginx -T 2>/dev/null | awk '$1 == \"ssl_certificate_key\" { v = $2; sub(/;$/, \"\", v); gsub(/\"/, \"\", v); "
      "print v }' | sort -u | while read -r k; do case \"$k\" in *'$'*|data:*|engine:*) continue;; esac; "
      "chown root:root \"$k\" && chmod 400 \"$k\" || exit 1; done"])
_add("4.1.4", "Allow only TLS 1.2 and 1.3", ["NGX:set http ssl_protocols TLSv1.2 TLSv1.3"],
     warning="Clients without TLS 1.2 (very old browsers, Android 4.3 and older, Java 6) can no longer connect. "
             "Replaces ssl_protocols set in server blocks.", params=["CONFIRM"])
_add("4.1.6", "Use generated Diffie-Hellman parameters",
     ["f=/etc/nginx/dhparam.pem; [ -s \"$f\" ] || openssl dhparam -out \"$f\" 2048 2>/dev/null || exit 1; "
      "chown root:root \"$f\" && chmod 400 \"$f\"", "NGX:set http ssl_dhparam /etc/nginx/dhparam.pem"],
     warning="Generates 2048-bit parameters with openssl (a few seconds to a minute).")
_add("4.1.7", "Turn on OCSP stapling", ["NGX:set http ssl_stapling on", "NGX:set http ssl_stapling_verify on"],
     warning="Stapling needs a resolver directive and the issuer's certificate in the chain; without them nginx "
             "logs a warning and serves without stapling.")
_add("4.1.8", "Send HSTS (Strict-Transport-Security)",
     ["NGX:array add_header Strict-Transport-Security max-age=31536000 always"],
     warning="Browsers that receive the header refuse plain HTTP for the site for a year; every name it serves "
             "must keep a valid certificate.", params=["CONFIRM"])
_add("4.1.12", "Turn TLS session tickets off", ["NGX:set http ssl_session_tickets off"])
_add("4.1.13", "Enable HTTP/2 on HTTPS servers", ["NGX:http2"])

# 5 Requests
_add("5.2.1", "Time out slow request headers and bodies after 10 seconds",
     ["NGX:set http client_body_timeout 10", "NGX:set http client_header_timeout 10"],
     warning="Clients that send a request slower than one read per 10 seconds get 408.")
_add("5.2.2", "Set the maximum request body size", ["NGX:set http client_max_body_size {MAX_BODY_SIZE} --top-only"],
     warning="Larger uploads get 413 unless a server or location sets its own limit.", params=["MAX_BODY_SIZE"])
_add("5.2.3", "Set the header buffer limit",
     ["NGX:set http large_client_header_buffers {HEADER_BUFFERS} --top-only"],
     warning="Requests with longer URLs or headers (large cookies) get 414 or 400.", params=["HEADER_BUFFERS"])
_add("5.2.4", "Limit connections per client address",
     ["NGX:add limit_conn_zone $binary_remote_addr zone=ngcorion_perip:10m --match=zone=ngcorion_perip:",
      "NGX:add limit_conn ngcorion_perip {CONN_PER_IP} --match=ngcorion_perip"],
     warning="Behind a load balancer or NAT, many users share one address; set the real client address "
             "(set_real_ip_from) first.", params=["CONN_PER_IP"])
_add("5.2.5", "Rate-limit requests per client address",
     ["NGX:add limit_req_zone $binary_remote_addr zone=ngcorion_req:10m rate={REQ_RATE}r/s "
      "--match=zone=ngcorion_req:",
      "NGX:add limit_req zone=ngcorion_req burst={REQ_BURST} nodelay --match=zone=ngcorion_req"],
     warning="Clients above the rate get 503. Behind a load balancer or NAT, set the real client address first.",
     params=["REQ_RATE", "REQ_BURST"])
_add("5.3.1", "Send X-Content-Type-Options: nosniff", ["NGX:array add_header X-Content-Type-Options nosniff always"])
_add("5.3.2", "Send a Content Security Policy", ["NGX:csp {CSP_POLICY}"],
     warning="Scripts, styles, images and frames from other origins stop loading; test the sites first.",
     params=["CSP_POLICY", "CONFIRM"])
_add("5.3.3", "Send a Referrer-Policy", ["NGX:array add_header Referrer-Policy {REFERRER_POLICY} always"],
     params=["REFERRER_POLICY"])

# Guidance only
_GUIDANCE = {
    "2.1.2": "Use an nginx build without the WebDAV module (--with-http_dav_module); meanwhile keep dav_methods off.",
    "2.2.1": "Create a dedicated system account (useradd -r -s /sbin/nologin nginx) and set 'user nginx;'.",
    "2.3.4": "Move working_directory outside the document roots: owned by root, group of the worker, mode 750.",
    "2.4.1": "Remove listen directives for ports that are not needed and close them in the firewall.",
    "2.5.3": "In each server: location ~ /\\.(?!well-known) { deny all; return 404; }",
    "4.1.1": "In each plain-HTTP server: return 301 https://$host$request_uri;",
    "6.1": "Enable SELinux in enforcing mode (nginx runs as httpd_t) or load and enforce an AppArmor profile for "
           "nginx.",
}
for _r in R.all_rules():
    if _r.id not in TEMPLATES.templates:
        TEMPLATES.manual(_r.id, _GUIDANCE.get(_r.section, _r.remediation))
