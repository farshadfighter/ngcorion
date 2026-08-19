#!/usr/bin/env python3
"""
Diagnose the "Forgot Password" email pipeline on the deploy server.

Run it FROM THE REPO ROOT so it loads the same .env the app does:

    cd ~/netease
    .venv/bin/python scripts/diagnose_email.py you@gmail.com

It walks the whole pipeline and prints a clear PASS/FAIL at each stage:
  1. SMTP config the app actually loaded from .env
  2. DNS resolution + TCP reachability of the SMTP host
  3. SMTP STARTTLS handshake + login (authentication)
  4. Sending a real test message (captures the server's accept/queue response)
  5. Sending through the app's own code path (catches "console mode")
  6. Domain auth DNS records (MX / SPF / DMARC / DKIM)

Flags:
    --no-send   run everything except actually sending mail (stages 4 & 5)

The SMTP password is never printed.
"""
import os
import sys
import ssl
import socket
import smtplib
import logging
import subprocess
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

logging.basicConfig(level=logging.INFO, format="    %(levelname)s %(name)s: %(message)s")


def hr(title):
    print("\n" + "=" * 64)
    print(title)
    print("=" * 64)


def ok(msg):   print("  [PASS]", msg)
def bad(msg):  print("  [FAIL]", msg)
def warn(msg): print("  [WARN]", msg)
def info(msg): print("  -", msg)


NO_SEND = "--no-send" in sys.argv
args = [a for a in sys.argv[1:] if not a.startswith("-")]

# Make the app importable when run from the repo root.
sys.path.insert(0, os.getcwd())
try:
    from app.core.config import settings
except Exception as exc:  # pragma: no cover
    print("Could not import app.core.config.")
    print("Run this from the repo root, e.g.:  cd ~/netease && .venv/bin/python scripts/diagnose_email.py you@gmail.com")
    print("Error:", exc)
    sys.exit(1)

recipient = args[0] if args else settings.SMTP_USERNAME
results = {}

# ----------------------------------------------------------------------------
hr("1. SMTP configuration loaded from .env")
info(f"working directory : {os.getcwd()}")
info(f".env present here : {os.path.exists('.env')}")
info(f"SMTP_HOST         : {settings.SMTP_HOST!r}")
info(f"SMTP_PORT         : {settings.SMTP_PORT}")
info(f"SMTP_USE_TLS      : {settings.SMTP_USE_TLS}")
info(f"SMTP_USERNAME     : {settings.SMTP_USERNAME!r}")
info(f"SMTP_PASSWORD     : {'set (%d chars)' % len(settings.SMTP_PASSWORD) if settings.SMTP_PASSWORD else 'EMPTY'}")
info(f"SMTP_FROM_EMAIL   : {settings.SMTP_FROM_EMAIL!r}")
info(f"recipient (test)  : {recipient!r}")

if not settings.SMTP_HOST:
    bad("SMTP_HOST is EMPTY -> the app is in CONSOLE mode and will NOT send real email.")
    info("Set the SMTP_* values in ~/netease/.env, then restart the backend, then re-run this.")
    results["config"] = False
    # Nothing else can pass; stop here.
    print("\nRESULT: config missing — fix .env and restart, then re-run.")
    sys.exit(1)
if settings.SMTP_FROM_EMAIL and settings.SMTP_USERNAME and \
        settings.SMTP_FROM_EMAIL.lower() != settings.SMTP_USERNAME.lower():
    warn(f"SMTP_FROM_EMAIL ({settings.SMTP_FROM_EMAIL}) != SMTP_USERNAME ({settings.SMTP_USERNAME}); "
         "some servers reject a From that isn't the authenticated mailbox.")
ok("SMTP_HOST is set (not console mode).")
results["config"] = True

# ----------------------------------------------------------------------------
hr("2. DNS resolution + TCP reachability")
host, port = settings.SMTP_HOST, settings.SMTP_PORT
try:
    addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)})
    ok(f"{host} resolves to: {', '.join(addrs)}")
    results["dns"] = True
except Exception as exc:
    bad(f"cannot resolve {host}: {exc}")
    results["dns"] = False

try:
    with socket.create_connection((host, port), timeout=10):
        ok(f"TCP connect to {host}:{port} succeeded")
    results["tcp"] = True
except Exception as exc:
    bad(f"cannot connect to {host}:{port}: {exc}  (firewall? wrong port?)")
    results["tcp"] = False

# ----------------------------------------------------------------------------
hr("3. SMTP STARTTLS + login")
server = None
try:
    server = smtplib.SMTP(host, port, timeout=20)
    server.ehlo()
    if settings.SMTP_USE_TLS:
        server.starttls(context=ssl.create_default_context())
        server.ehlo()
        ok("STARTTLS negotiated (TLS certificate valid)")
    if settings.SMTP_USERNAME:
        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        ok("authentication succeeded")
    else:
        warn("no SMTP_USERNAME set; skipping login")
    results["login"] = True
except smtplib.SMTPAuthenticationError as exc:
    bad(f"authentication FAILED: {exc.smtp_code} {exc.smtp_error!r}  (wrong username/password?)")
    results["login"] = False
except ssl.SSLCertVerificationError as exc:
    bad(f"TLS certificate verification FAILED: {exc}")
    info("The mail server's certificate is self-signed or doesn't match its hostname.")
    results["login"] = False
except Exception as exc:
    bad(f"SMTP handshake/login error: {type(exc).__name__}: {exc}")
    results["login"] = False

# ----------------------------------------------------------------------------
hr("4. Send a real test message (raw SMTP)")
if NO_SEND:
    info("skipped (--no-send)")
elif server is not None and results.get("login"):
    try:
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        msg = EmailMessage()
        msg["From"] = formataddr((settings.SMTP_FROM_NAME, settings.SMTP_FROM_EMAIL))
        msg["To"] = recipient
        msg["Subject"] = f"NGcorion email diagnostic {stamp}"
        msg["Message-ID"] = make_msgid(domain=settings.SMTP_FROM_EMAIL.split("@")[-1])
        msg.set_content(f"Diagnostic test sent {stamp} from scripts/diagnose_email.py")
        # Debug AFTER login so credentials are never printed; this shows the
        # server's 250 acceptance line / queue id, which proves it was accepted.
        server.set_debuglevel(1)
        refused = server.send_message(msg)
        server.set_debuglevel(0)
        if not refused:
            ok(f"server ACCEPTED the message for {recipient} (see the '250 ... queued' line above)")
            info("If it still doesn't arrive, the mail server accepted but couldn't deliver -> stage 6 / bounce.")
            results["send_raw"] = True
        else:
            bad(f"server refused recipients: {refused}")
            results["send_raw"] = False
    except Exception as exc:
        bad(f"send failed: {type(exc).__name__}: {exc}")
        results["send_raw"] = False
    finally:
        try:
            server.quit()
        except Exception as e:
            print(f"[Warning] SMTP quit failed: {e}", file=sys.stderr)
else:
    warn("skipped (login did not pass)")

# ----------------------------------------------------------------------------
hr("5. Send via the app's own code path (send_password_reset_otp)")
if NO_SEND:
    info("skipped (--no-send)")
else:
    try:
        from app.core.email import send_password_reset_otp
        info("calling send_password_reset_otp(...) — watch for 'Sent email to' vs 'Failed to send' below:")
        send_password_reset_otp(recipient, "000000")
        ok("call completed (check the log line above for the real result)")
        results["send_app"] = True
    except Exception as exc:
        bad(f"app send path error: {type(exc).__name__}: {exc}")
        results["send_app"] = False

# ----------------------------------------------------------------------------
hr("6. Domain authentication DNS records")
domain = (settings.SMTP_FROM_EMAIL.split("@")[-1] or "").strip() or "ngcorion.com"

def dig(record, name):
    try:
        out = subprocess.run(["dig", "+short", record, name],
                             capture_output=True, text=True, timeout=15)
        return [l for l in out.stdout.splitlines() if l.strip()]
    except FileNotFoundError:
        return None
    except Exception:
        return []

mx = dig("MX", domain)
if mx is None:
    warn("`dig` not installed — check DNS manually (MX, TXT/SPF, _dmarc, DKIM).")
else:
    print(f"  MX   {domain}:", mx or "(none)")
    spf = [l for l in (dig('TXT', domain) or []) if 'spf1' in l.lower()]
    print(f"  SPF  {domain}:", spf or "(none)")
    if not spf:
        warn("no SPF record — add: v=spf1 a mx ... ~all")
    dmarc = dig("TXT", f"_dmarc.{domain}")
    print(f"  DMARC _dmarc.{domain}:", dmarc or "(none)")
    if not dmarc:
        warn(f"no DMARC record — add TXT _dmarc.{domain}: v=DMARC1; p=none; rua=mailto:postmaster@{domain}")
    found = [s for s in ("default", "mail", "dkim", "google", "selector1", "selector2", "s1", "s2")
             if dig("TXT", f"{s}._domainkey.{domain}")]
    print("  DKIM selectors found:", found or "(none of the common ones)")
    if not found:
        warn("no DKIM found at common selectors — enable DKIM at your mail host (axspace) and publish its selector.")

# ----------------------------------------------------------------------------
hr("SUMMARY")
order = [("config", "1 config loaded"), ("dns", "2a DNS resolves"), ("tcp", "2b TCP reachable"),
         ("login", "3 STARTTLS + auth"), ("send_raw", "4 raw send accepted"), ("send_app", "5 app send ran")]
for key, label in order:
    if key in results:
        print(("  PASS  " if results[key] else "  FAIL  ") + label)
print()
if results.get("login") and results.get("send_raw", True):
    print("App-side sending works. If mail still doesn't arrive, it's DELIVERY (stage 6):")
    print("  - check Gmail Spam, and the support@ mailbox for a bounce from Google,")
    print("  - add DMARC + enable DKIM, then retest at https://www.mail-tester.com")
else:
    print("App-side sending is failing — fix the first FAIL above and re-run.")
