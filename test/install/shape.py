#!/usr/bin/env python3
"""The shape of a node's rendered configuration and subscription payload,
values aside: what test/install/upgrade.sh compares between a node updated
from the previous release and one installed afresh.

    shape.py RENDERED_DIR PAYLOAD_JSON

Each JSON file and the payload become their key paths with the kind of
each value. Strings that read as an enum (short, lower case: modes, names
the test gives) and small numbers (counts, limits) stay; keys, ports,
addresses and times become their kind. A list's elements merge into one
shape, with the list's length. Links become their scheme and parameter
names, with the parameters' values as for strings.
"""
import json
import os
import re
import sys
from urllib.parse import parse_qsl, urlsplit

ENUM = re.compile(r"^[a-z][a-z0-9_.-]{0,23}$")
# A name with random labels (zones, SNI): its first label goes.
NAME = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


def scalar(v):
    if isinstance(v, bool):
        return f"bool:{v}"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        # Small numbers are settings (MTU, limits, counts); others are
        # ports, IDs, times and sizes that differ from node to node.
        return f"num:{v}" if isinstance(v, int) and 0 <= v < 1024 else "num"
    if isinstance(v, str):
        if "://" in v:
            return link(v)
        if NAME.match(v):
            return "name:*." + v.split(".", 1)[1]
        return f"str:{v}" if ENUM.match(v) else ("str:" if v == "" else "str")
    return type(v).__name__


def link(v):
    u = urlsplit(v)
    params = sorted(f"{k}={scalar(x)}" for k, x in parse_qsl(u.query, keep_blank_values=True))
    return f"link:{u.scheme}?{'&'.join(params)}"


# Fields that count requests, not configuration: the updated node was asked
# more often.
VOLATILE = {".seq"}


def walk(v, path, out):
    if path in VOLATILE:
        out.add(f"{path} = {type(v).__name__}")
        return
    if isinstance(v, dict):
        if not v:
            out.add(f"{path} {{}}")
        for k, x in v.items():
            walk(x, f"{path}.{k}", out)
    elif isinstance(v, list):
        out.add(f"{path} [{len(v)}]")
        for x in v:
            walk(x, f"{path}[]", out)
    else:
        out.add(f"{path} = {scalar(v)}")


def shape(name, v):
    out = set()
    walk(v, "", out)
    print(f"== {name}")
    for line in sorted(out):
        print(line)


def main():
    rendered, payload = sys.argv[1], sys.argv[2]
    for root, _, files in sorted(os.walk(rendered)):
        for f in sorted(files):
            if not f.endswith(".json"):
                continue
            p = os.path.join(root, f)
            with open(p, encoding="utf-8") as fh:
                shape(os.path.relpath(p, rendered), json.load(fh))
    with open(payload, encoding="utf-8") as fh:
        shape("payload", json.load(fh))


if __name__ == "__main__":
    main()
