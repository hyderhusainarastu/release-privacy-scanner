"""Command line entry point: leakscan."""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, OrderedDict

from . import __version__
from .core import (INFO, LEAK, PROFILES, SANCTIONED, SEVERITY_ORDER, WARN, Matcher, PatternError,
                   parse_allow, parse_pattern_file, parse_private_file)
from .pack import lint_pack
from .sources import (git, is_git_repo, run_gitleaks, scan_archive, scan_history, scan_tree)

DEFAULT_PRIVATE = ".leakscan.local.txt"


def build_parser():
    p = argparse.ArgumentParser(
        prog="leakscan",
        description="Scan for publication leaks (paths, identities, emails, hostnames, AI fingerprints, secret shapes).",
        epilog="Exit codes: 0 no LEAK findings, 1 at least one LEAK, 2 usage or input error.",
    )
    p.add_argument("paths", nargs="*", metavar="PATH", help="files or directories (default: .)")
    p.add_argument("--profile", choices=PROFILES, default="public-release")
    p.add_argument("--patterns", action="append", default=[], metavar="FILE", help="extra pattern file (repeatable)")
    p.add_argument("--private-patterns", metavar="FILE", help=f"owner-specific regexes kept outside the repo (default: ./{DEFAULT_PRIVATE})")
    p.add_argument("--allow", action="append", default=[], metavar="FILE", help="narrow allowlist file (repeatable)")
    p.add_argument("--history", action="store_true", help="scan every blob, author identity and message reachable from all refs")
    p.add_argument("--archive", action="append", default=[], metavar="FILE", help="scan a .zip/.tar.gz archive in memory (repeatable)")
    p.add_argument("--pack", action="store_true", help="also lint the packaging standard (README, AGENTS.md, budgets)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--with-gitleaks", action="store_true", help="merge gitleaks results when it is on PATH")
    p.add_argument("--version", action="version", version=f"leakscan {__version__}")
    return p


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        raise PatternError(f"cannot read {path}: {e.strerror}") from None


def _private_file(args, roots):
    if args.private_patterns:
        return args.private_patterns
    for base in [os.getcwd()] + [r for r in roots if os.path.isdir(r)]:
        cand = os.path.join(base, DEFAULT_PRIVATE)
        if os.path.isfile(cand):
            return cand
    return None


def _ignored_warning(path):
    d = os.path.dirname(os.path.abspath(path))
    try:
        if not is_git_repo(d):
            return None
        rc = git(d, "check-ignore", "-q", "--", os.path.abspath(path)).returncode
    except OSError:
        return None
    if rc == 1:
        return f"{path} is not git-ignored: add it to .gitignore or .git/info/exclude so it is never published"
    return None


def run(argv):
    args = build_parser().parse_args(argv)
    roots = args.paths or ["."]
    for r in roots:
        if not os.path.exists(r):
            raise PatternError(f"path not found: {r}")
    for a in args.archive:
        if not os.path.isfile(a):
            raise PatternError(f"archive not found: {a}")

    extra = []
    for f in args.patterns:
        extra += parse_pattern_file(_read(f), f)
    allow = []
    for f in args.allow:
        allow += parse_allow(_read(f), f)
    private, warnings, pfile = [], [], _private_file(args, roots)
    if pfile:
        private = parse_private_file(_read(pfile), pfile)
        w = _ignored_warning(pfile)
        if w:
            warnings.append(w)
    matcher = Matcher(args.profile, extra, private, allow)
    pfile_real = os.path.realpath(pfile) if pfile else None

    stats = Counter()
    findings, notes = [], []
    for r in roots:
        findings += scan_tree(r, r, matcher, stats, pfile_real)
        if args.history:
            root = r if os.path.isdir(r) else os.path.dirname(os.path.abspath(r))
            if not is_git_repo(root):
                raise PatternError(f"--history needs a git repository: {r}")
            findings += scan_history(root, matcher, stats)
        if args.pack and os.path.isdir(r):
            findings += lint_pack(r, r)
        if args.with_gitleaks:
            f, note = run_gitleaks(r)
            findings += f
            notes.append(note)
    for a in args.archive:
        try:
            findings += scan_archive(a, matcher, stats)
        except Exception as e:  # corrupt archive
            raise PatternError(f"cannot read archive {a}: {e}") from None

    seen, uniq = set(), []
    for f in findings:
        if f.key() in seen:
            continue
        seen.add(f.key())
        uniq.append(f)
    findings = sorted(uniq, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.path, f.line, f.cls))
    counts = Counter(f.severity for f in findings)
    code = 1 if counts[LEAK] else 0
    report = format_json(args, findings, counts, stats, warnings, notes) if args.json \
        else format_text(args, findings, counts, stats, warnings, notes)
    sys.stdout.write(report)
    return code


def format_json(args, findings, counts, stats, warnings, notes):
    doc = OrderedDict(
        version=__version__, profile=args.profile,
        result="FAIL" if counts[LEAK] else "PASS",
        summary={s: counts[s] for s in SEVERITY_ORDER},
        stats=dict(stats), warnings=warnings, notes=notes,
        findings=[{"severity": f.severity, "class": f.cls, "path": f.path, "line": f.line,
                   "detail": f.detail, "commit": f.commit} for f in findings],
    )
    return json.dumps(doc, indent=2) + "\n"


def format_text(args, findings, counts, stats, warnings, notes):
    out = [f"leakscan {__version__}  profile={args.profile}  files={stats['files']} blobs={stats['blobs']} "
           f"commits={stats['commits']} skipped={stats['skipped']}"]
    for w in warnings:
        out.append(f"warning: {w}")
    for n in notes:
        out.append(f"note: {n}")
    for sev in (LEAK, WARN):
        group = [f for f in findings if f.severity == sev]
        if group:
            out.append(f"\n{sev} ({len(group)})")
            for f in group:
                loc = f"{f.path}:{f.line}" if f.line else f.path
                at = f" [commit {f.commit}]" if f.commit and "commit" not in f.path else ""
                out.append(f"  {loc}  {f.cls}  {f.detail}{at}")
    for sev, label in ((SANCTIONED, "SANCTIONED (counted, not failures)"), (INFO, "INFO (review by hand)")):
        group = [f for f in findings if f.severity == sev]
        if group:
            out.append(f"\n{label}: {len(group)}")
            tally = Counter((f.path, f.cls) for f in group)
            for (path, cls), n in sorted(tally.items()):
                out.append(f"  {path}  {cls} x{n}")
    result = "FAIL" if counts[LEAK] else "PASS"
    out.append(f"\nresult: {result}  ({counts[LEAK]} LEAK, {counts[WARN]} WARN, "
               f"{counts[SANCTIONED]} SANCTIONED, {counts[INFO]} INFO)")
    return "\n".join(out) + "\n"


def main(argv=None):
    try:
        return run(sys.argv[1:] if argv is None else argv)
    except PatternError as e:
        print(f"leakscan: {e}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
