"""Compare two IAMhounddog outputs and classify every difference.

A raw diff of these files is useless: most of the delta is intended. This
groups the delta so that each change can be attributed to a known fix, and
anything left over is a regression.
"""

import collections
import json
import re
import sys

# moto mints these fresh on every seed, so they differ between runs without
# anything in the tool having changed. They are scrubbed before comparing
# properties; a real change never hides behind one of these.
NONDETERMINISTIC = [
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "<uuid>"),
    (re.compile(r"i-[0-9a-f]{8,17}"), "<instance-id>"),
]


def scrub(value):
    text = str(value)
    for rx, replacement in NONDETERMINISTIC:
        text = rx.sub(replacement, text)
    return text


def load(path):
    with open(path) as fh:
        return json.load(fh)["graph"]


def edge_key(e):
    return (e["kind"], e["start"]["value"], e["end"]["value"])


def counts(items, key):
    c = collections.Counter()
    for i in items:
        c[key(i)] += 1
    return c


def section(title):
    print("\n" + title)
    print("=" * len(title))


def table(rows, headers):
    widths = [max(len(str(r[i])) for r in [headers] + rows) for i in range(len(headers))]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print("  " + line)
    print("  " + "-" * len(line))
    for r in rows:
        print("  " + "  ".join(str(c).ljust(w) for c, w in zip(r, widths)))


def main(base_path, cur_path, examples=4):
    base, cur = load(base_path), load(cur_path)

    section("TOTALS")
    table([
        ["nodes", len(base["nodes"]), len(cur["nodes"]),
         len(cur["nodes"]) - len(base["nodes"])],
        ["edges", len(base["edges"]), len(cur["edges"]),
         len(cur["edges"]) - len(base["edges"])],
    ], ["", "baseline", "current", "delta"])

    section("NODES BY KIND")
    bk = counts(base["nodes"], lambda n: "+".join(n["kinds"]))
    ck = counts(cur["nodes"], lambda n: "+".join(n["kinds"]))
    rows = [[k, bk.get(k, 0), ck.get(k, 0), ck.get(k, 0) - bk.get(k, 0)]
            for k in sorted(set(bk) | set(ck))]
    table(rows, ["kind", "baseline", "current", "delta"])

    # Edges leaving a policy node are per-action edges. There are thousands of
    # distinct kinds and they are expected to collapse, so summarise them
    # rather than listing every one; structural edges get the detailed table.
    def split(graph):
        policies = {n["id"] for n in graph["nodes"] if "AWSPolicy" in n["kinds"]}
        action, structural = [], []
        for e in graph["edges"]:
            (action if e["start"]["value"] in policies else structural).append(e)
        return action, structural

    b_action, b_struct = split(base)
    c_action, c_struct = split(cur)

    section("POLICY ACTION EDGES (aggregate)")
    table([
        ["total", len(b_action), len(c_action), len(c_action) - len(b_action)],
        ["distinct kinds", len({e["kind"] for e in b_action}),
         len({e["kind"] for e in c_action}),
         len({e["kind"] for e in c_action}) - len({e["kind"] for e in b_action})],
        ["distinct triples", len({edge_key(e) for e in b_action}),
         len({edge_key(e) for e in c_action}),
         len({edge_key(e) for e in c_action}) - len({edge_key(e) for e in b_action})],
    ], ["", "baseline", "current", "delta"])
    dropped = {edge_key(e) for e in b_action} - {edge_key(e) for e in c_action}
    print("\n  unique policy->service triples lost: %d" % len(dropped))
    for k in sorted(dropped)[:examples]:
        print("    %s  %s -> %s" % k)
    print("  (duplicates removed, not relationships: a lost *triple* would be a regression)")

    section("STRUCTURAL EDGES BY KIND")
    be = counts(b_struct, lambda e: e["kind"])
    ce = counts(c_struct, lambda e: e["kind"])
    rows = [[k, be.get(k, 0), ce.get(k, 0), ce.get(k, 0) - be.get(k, 0)]
            for k in sorted(set(be) | set(ce))]
    table(rows, ["edge kind", "baseline", "current", "delta"])

    section("NODE IDS")
    bids = {n["id"] for n in base["nodes"]}
    cids = {n["id"] for n in cur["nodes"]}
    for label, ids in [("only in current", cids - bids), ("only in baseline", bids - cids)]:
        print("\n  %s: %d" % (label, len(ids)))
        for i in sorted(ids)[:examples * 3]:
            print("    %s" % i)
        if len(ids) > examples * 3:
            print("    ... and %d more" % (len(ids) - examples * 3))

    section("DUPLICATE NODE IDS")
    for label, g in [("baseline", base), ("current", cur)]:
        dupes = {i: n for i, n in counts(g["nodes"], lambda n: n["id"]).items() if n > 1}
        print("  %-9s %d duplicated ids%s" % (
            label, len(dupes),
            ("  e.g. " + ", ".join(list(dupes)[:3])) if dupes else ""))

    section("EDGES (unique triples)")
    bt = set(edge_key(e) for e in base["edges"])
    ct = set(edge_key(e) for e in cur["edges"])
    for label, t in [("only in current", ct - bt), ("only in baseline", bt - ct)]:
        by_kind = collections.Counter(k for k, _, _ in t)
        print("\n  %s: %d unique triples" % (label, len(t)))
        for kind, n in by_kind.most_common():
            print("    %-34s %d" % (kind, n))
            for ek in sorted(x for x in t if x[0] == kind)[:examples]:
                print("        %s -> %s" % (ek[1], ek[2]))

    section("PROPERTY CHANGES ON SHARED NODES")
    bn = {n["id"]: n for n in base["nodes"]}
    cnodes = {n["id"]: n for n in cur["nodes"]}
    changed = collections.Counter()
    samples = {}
    for i in bids & cids:
        bp = bn[i].get("properties") or {}
        cp = cnodes[i].get("properties") or {}
        for k in set(bp) | set(cp):
            if scrub(bp.get(k)) != scrub(cp.get(k)):
                changed[k] += 1
                samples.setdefault(k, (i, bp.get(k), cp.get(k)))
    if changed:
        for k, n in changed.most_common():
            i, b, c = samples[k]
            print("  %-14s %4d nodes   e.g. %s" % (k, n, i))
            print("      baseline: %r" % (str(b)[:90],))
            print("      current:  %r" % (str(c)[:90],))
    else:
        print("  (none)")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
