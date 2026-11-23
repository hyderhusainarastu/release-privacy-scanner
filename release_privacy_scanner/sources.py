"""Where text comes from: working tree, git history, archives, gitleaks."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

from .core import INFO, LEAK, Finding, Matcher, redact

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache"}
SKIP_FILES = {".leakscan.local.txt"}
MAX_BYTES = 2 * 1024 * 1024


def looks_text(data: bytes) -> bool:
    return b"\0" not in data[:8192]


def decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def iter_files(root: str):
    if os.path.isfile(root):
        yield root, os.path.basename(root)
        return
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS)
        for fn in sorted(fns):
            full = os.path.join(dp, fn)
            if fn in SKIP_FILES or os.path.islink(full):
                continue
            yield full, os.path.relpath(full, root).replace(os.sep, "/")


def scan_tree(root: str, given: str, matcher: Matcher, stats: dict, private_file: str | None = None):
    out = []
    for full, rel in iter_files(root):
        if private_file and os.path.realpath(full) == private_file:
            continue
        display = os.path.normpath(os.path.join(given, rel)) if os.path.isdir(root) else given
        inst = matcher.instruction_file(rel, display)
        if inst:
            out.append(inst)
        try:
            if os.path.getsize(full) > MAX_BYTES:
                stats["skipped"] += 1
                continue
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            stats["skipped"] += 1
            continue
        if not looks_text(data):
            stats["skipped"] += 1
            continue
        stats["files"] += 1
        out += matcher.scan_text(decode(data), rel, display)
    return out


def git(root: str, *args: str, inp: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", root, *args], input=inp, capture_output=True)


def is_git_repo(root: str) -> bool:
    try:
        return git(root, "rev-parse", "--git-dir").returncode == 0
    except OSError:
        return False


def scan_history(root: str, matcher: Matcher, stats: dict):
    out = []
    # Which commit first introduced each blob, and under which path.
    log = git(root, "log", "--all", "--root", "--no-renames", "--raw", "--no-abbrev", "--format=C %H").stdout
    origin = {}
    commit = ""
    for line in decode(log).splitlines():
        if line.startswith("C "):
            commit = line[2:]
        elif line.startswith(":"):
            meta, _, path = line.partition("\t")
            parts = meta.split()
            if len(parts) >= 5 and not set(parts[3]) <= {"0"}:
                origin[parts[3]] = (commit, path)  # later (older) commits overwrite
    objs = decode(git(root, "rev-list", "--all", "--objects").stdout).splitlines()
    shas, paths = [], {}
    for o in objs:
        sha, _, path = o.partition(" ")
        if path:
            shas.append(sha)
            paths.setdefault(sha, path)
    if shas:
        raw = git(root, "cat-file", "--batch", inp=("\n".join(shas) + "\n").encode()).stdout
        pos = 0
        while pos < len(raw):
            end = raw.find(b"\n", pos)
            if end < 0:
                break
            head = raw[pos:end].split()
            if len(head) < 3 or head[1] == b"missing":
                pos = end + 1
                continue
            size = int(head[2])
            data = raw[end + 1:end + 1 + size]
            pos = end + 1 + size + 1
            if head[1] != b"blob" or size > MAX_BYTES or not looks_text(data):
                continue
            sha = head[0].decode()
            c, p = origin.get(sha, ("", paths.get(sha, "?")))
            if any(part in SKIP_DIRS for part in p.split("/")):
                continue
            stats["blobs"] += 1
            out += matcher.scan_text(decode(data), p, p, commit=c[:8])
    # Identities and messages.
    fmt = "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e"
    seen = set()
    for rec in decode(git(root, "log", "--all", fmt).stdout).split("\x1e"):
        rec = rec.strip("\n")
        if "\x1f" not in rec:
            continue
        h, an, ae, cn, ce, body = rec.split("\x1f", 5)
        h8 = h[:8]
        stats["commits"] += 1
        for name in {an, cn}:
            if name and name not in seen:
                seen.add(name)
                sev = INFO if matcher.profile == "public-release" else LEAK
                out.append(Finding(sev, "IDENTITY", f"commit {h8}", 0, f"git author/committer name: {redact(name)}", "", h8))
        for mail in {ae, ce}:
            if mail and mail not in seen:
                seen.add(mail)
                out += matcher.scan_text(f"<{mail}>", "", f"commit {h8} identity", commit=h8)
        out += matcher.scan_text(body, "", f"commit {h8} message", commit=h8)
    return out


def scan_archive(path: str, matcher: Matcher, stats: dict):
    out = []

    def handle(name: str, data: bytes):
        if len(data) > MAX_BYTES or not looks_text(data):
            stats["skipped"] += 1
            return
        stats["files"] += 1
        rel = name.lstrip("./")
        inst = matcher.instruction_file(rel, f"{path}!{name}")
        if inst:
            out.append(inst)
        out.extend(matcher.scan_text(decode(data), rel, f"{path}!{name}"))

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if not info.is_dir() and info.file_size <= MAX_BYTES:
                    handle(info.filename, z.read(info))
    else:
        with tarfile.open(path, "r:*") as t:
            for m in t:
                if m.isfile() and m.size <= MAX_BYTES:
                    f = t.extractfile(m)
                    if f:
                        handle(m.name, f.read())
    return out


def run_gitleaks(root: str):
    """Returns (findings, note). Skipped quietly when gitleaks is not installed."""
    exe = shutil.which("gitleaks")
    if not exe:
        return [], "gitleaks not found on PATH: skipped"
    with tempfile.TemporaryDirectory() as td:
        rep = os.path.join(td, "r.json")
        cmd = [exe, "detect", "--no-banner", "--report-format", "json", "--report-path", rep,
               "--redact", "--source", root, "--no-git"]
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode not in (0, 1) or not os.path.exists(rep):
            return [], f"gitleaks exited {r.returncode}: results not merged"
        try:
            data = json.load(open(rep)) or []
        except ValueError:
            return [], "gitleaks report unreadable: results not merged"
    out = []
    for d in data:
        f = d.get("File", "?")
        rel = os.path.relpath(f, root) if os.path.isabs(f) else f
        out.append(Finding(LEAK, "SECRET", rel, int(d.get("StartLine") or 0), f"gitleaks rule {d.get('RuleID', '?')}", rel))
    return out, f"gitleaks: {len(out)} finding(s) merged"
