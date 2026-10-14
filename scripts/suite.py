#!/usr/bin/env python3
"""Score CBOMs against ground-truth labels written from source before any tool run.

usage: suite.py OUT_DIR PROGRAM_DIR... [--json]
Each PROGRAM_DIR holds `labels.toml` (one [[site]] per operation call site: file, line, callee,
function, must, may, params) and its CBOM is OUT_DIR/<dirname>.cbom.json. Program ids are
`<what>-<how>`; scores are given per site, per what, per how and overall.

Per labelled site, S is the set of algorithm assets the CBOM cites with a reachable call
occurrence at that file and line (on a line holding two labelled calls, the occurrence whose
code is that callee). A site the CBOM cites only as present (not reachable) is correct when the
labels make it dead, and a miss when they make it live. Names compare as the registry writes
them: a name with numeric parameter parts (`PBKDF2-SHA-256-600000-32`, `Argon2id-19456-2-1`) is
the labelled name when the parts are the labelled parameters, or when the label fixes none; a
family name (`Argon2`, the asset's algorithmFamily) of a labelled algorithm is less specific.
Reporting only algorithms outside `must` while missing it, or a reachable `unknown` at a dead
site, is wrong. A correct site whose reported use differs from the labelled function is counted
in `function_mismatches`.
  correct          must <= S <= must | may, no `unknown`
  wrong            a member outside must | may: a misclassification (any report at a dead site)
  less-specific    a less specific name of a labelled one (`RSA-PKCS1-1.5` for
                   `RSA-PKCS1-1.5-SHA-384`), nothing wrong
  honest-unknown   `unknown` reported, nothing wrong
  miss             a `must` algorithm not reported, nothing wrong
Also counted: uses the CBOM reports in the program's own files at lines with no labelled site
(`unlabelled`), for review; and sites where several algorithms are reported but one of them is
labelled as the only one (`algorithm from X ..`, not `one of N`, `possibly` or `possible`):
`label_mismatches`.
"""
import collections, json, pathlib, re, sys, tomllib

VERDICTS = ["correct", "wrong", "less-specific", "honest-unknown", "miss"]


def occurrences(cbom):
    """(file, line) -> [(asset name, code, has use, reachable, family name)] for call occurrences in
    the program's files."""
    at = collections.defaultdict(list)
    for c in cbom["components"]:
        if c["type"] != "cryptographic-asset" or c["cryptoProperties"]["assetType"] != "algorithm":
            continue
        family = c["cryptoProperties"]["algorithmProperties"].get("algorithmFamily")
        for o in c["evidence"]["occurrences"]:
            ctx = o["additionalContext"]
            # dependency sources are cited under their package directory (`ring-0.17.14/..`)
            if "[call]" not in ctx or re.match(r"^[\w.-]+-\d+\.\d+\.\d+[^/]*/", o["location"]):
                continue
            code = re.search(r"; code: `([^`]*)`", ctx)
            use = re.search(r"; use: ([^;]+)", ctx)
            at[(o["location"], o["line"])].append(
                (c["name"], code.group(1) if code else o["symbol"], "; use: " in ctx,
                 ctx.startswith("[reachable]"), c["name"] == family,
                 use.group(1) if use else None, ctx))
    return at


def verdict(site, occ):
    """occ: [(name, code, has use, reachable, family name)] cited at the site."""
    must, may = set(site["must"]), set(site.get("may", []))
    params = {str(v) for v in site.get("params", {}).values()}
    reachable = [o for o in occ if o[3]]
    if not reachable:
        # cited only as present: right for a dead site, a reachability miss for a live one
        return "correct" if not must and occ else ("miss" if must else "correct")
    names = {o[0] for o in reachable}
    families = {o[0] for o in reachable if o[4]}

    # the registry's full name carries parameters the labels keep apart
    # (`PBKDF2-SHA-256-600000-32` is PBKDF2-SHA-256 with 600000 iterations, 32 bytes)
    def base(n):
        for lab in must | may:
            parts = n[len(lab) + 1:].split("-") if n.startswith(lab + "-") else None
            if parts and (all(p in params for p in parts)
                          or (not params and all(p.isdigit() for p in parts))):
                return lab
        return n

    known = {base(n) for n in names} - {"unknown"}
    general = {n for n in known - must - may
               if any(m.startswith(n + "-") or (n in families and m.startswith(n))
                      for m in must | may)}
    if known - must - may - general:
        return "wrong"
    # a reachable operation where none runs
    if not must and "unknown" in names:
        return "wrong"
    if general:
        return "less-specific"
    if "unknown" in names:
        return "honest-unknown"
    # only what may also reach it, none of what does: the report names the wrong algorithm
    if must and known and not (known & must):
        return "wrong"
    if must - known:
        return "miss"
    return "correct"


def exact_among_several(occ):
    """The reachable algorithms labelled as the only one where the call may use several: several
    algorithms reported for one instance of the call (occurrences grouped by their `instantiated
    by` chain), or one beside an `unknown` (others may reach it). Only occurrences with a use
    count (a constructor on the same line is no site)."""
    groups = collections.defaultdict(list)
    for o in occ:
        if not (o[3] and o[2]):
            continue
        chain = re.findall(r"; instantiated by [^;]*", o[6])
        groups[tuple(chain)].append(o)
    out = set()
    for group in groups.values():
        names = {o[0] for o in group if o[0] != "unknown"}
        unknown = any(o[0] == "unknown" for o in group)
        if len(names) < 2 and not (names and unknown):
            continue
        for o in group:
            if o[0] == "unknown":
                continue
            m = re.search(r"; (algorithm [^;]*)", o[6])
            sentence = m.group(1) if m else ""
            if not re.search(r"one of|possibl|selector", sentence):
                out.add(o[0])
    return sorted(out)


def function_matches(site, occ):
    """Does a reported use of a reachable occurrence agree with the labelled function?"""
    uses = {u for o in occ if o[3] and o[5] for u in o[5].split(" or ")}
    return not uses or site["function"] in uses


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    out_dir, programs = pathlib.Path(args[0]), [pathlib.Path(p) for p in args[1:]]
    total = collections.Counter()
    by_what = collections.defaultdict(collections.Counter)
    by_how = collections.defaultdict(collections.Counter)
    details, unlabelled, function_mismatches, label_mismatches = [], 0, [], []
    for prog in sorted(programs):
        pid = prog.name
        what, _, how = pid.partition("-")
        sites = tomllib.load(open(prog / "labels.toml", "rb")).get("site", [])
        cbom_path = out_dir / f"{pid}.cbom.json"
        at = occurrences(json.load(open(cbom_path))) if cbom_path.exists() else {}
        labelled_lines = collections.Counter((s["file"], s["line"]) for s in sites)
        for s in sites:
            occ = at.get((s["file"], s["line"]), [])
            # two labelled calls on one line: only the occurrences naming this callee
            if labelled_lines[(s["file"], s["line"])] > 1:
                occ = [o for o in occ if o[1].endswith(s["callee"])]
            v = verdict(s, occ) if cbom_path.exists() else "miss"
            exact = exact_among_several(occ)
            if exact:
                label_mismatches.append(f"{pid}:{s['line']} {s['callee']}: {exact} labelled as the"
                                        f" only algorithm among several")
            if v == "correct" and not function_matches(s, occ):
                function_mismatches.append(f"{pid}:{s['line']} {s['callee']}: labelled {s['function']},"
                                           f" reported {sorted({o[5] for o in occ if o[5]})}")
            total[v] += 1
            by_what[what][v] += 1
            by_how[how][v] += 1
            if v != "correct":
                details.append({"program": pid, "line": s["line"], "callee": s["callee"],
                                "verdict": v, "reported": sorted({o[0] for o in occ}),
                                "must": sorted(s["must"]), "may": sorted(s.get("may", []))})
        for key, occ in at.items():
            if key not in labelled_lines and any(o[2] and o[3] for o in occ):
                unlabelled += 1
    result = {
        "sites": sum(total.values()),
        "verdicts": {v: total[v] for v in VERDICTS},
        "by_what": {w: {v: c[v] for v in VERDICTS if c[v]} for w, c in sorted(by_what.items())},
        "by_how": {h: {v: c[v] for v in VERDICTS if c[v]} for h, c in sorted(by_how.items())},
        "unlabelled_uses": unlabelled,
        "function_mismatches": function_mismatches,
        "label_mismatches": label_mismatches,
        "not_correct": details,
    }
    if "--json" in sys.argv:
        print(json.dumps(result, indent=1, sort_keys=True))
    else:
        print(f"{result['sites']} sites: " + ", ".join(f"{v} {total[v]}" for v in VERDICTS)
              + f"; unlabelled uses {unlabelled}; function mismatches {len(function_mismatches)}"
              + f"; label mismatches {len(label_mismatches)}")
        for m in function_mismatches:
            print(f"  function: {m}")
        for m in label_mismatches:
            print(f"  label: {m}")
        for d in details:
            print(f"  {d['program']}:{d['line']} {d['callee']}: {d['verdict']}: reported {d['reported']},"
                  f" must {d['must']}, may {d['may']}")


if __name__ == "__main__":
    main()
