"""--pack: lint a repository against the shared packaging standard."""
from __future__ import annotations

import os
import re

from .core import LEAK, Finding

CC_ONLY = re.compile(r"(?i:subagent)|Task tool|~/\.claude|SubagentStop|PreToolUse|CLAUDE_")
NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def frontmatter(text: str):
    """Return (dict, body_lines) for a simple YAML frontmatter block, or (None, lines)."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, lines
    try:
        end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
    except StopIteration:
        return None, lines
    meta, key = {}, None
    for ln in lines[1:end]:
        m = re.match(r"^([A-Za-z_-]+)\s*:\s*(.*)$", ln)
        if m and not ln.startswith(" "):
            key, val = m.group(1), m.group(2).strip()
            meta[key] = "" if val in (">", "|", ">-", "|-") else val.strip("\"'")
        elif key and ln.startswith((" ", "\t")):
            meta[key] = (meta[key] + " " + ln.strip()).strip()
    return meta, lines[end + 1:]


def lint_pack(root: str, display: str):
    out = []

    def bad(name, line, detail):
        out.append(Finding(LEAK, "PACK", os.path.normpath(os.path.join(display, name)) if name else display, line, detail, name))

    for req in ("README.md", "AGENTS.md", "LICENSE"):
        if not os.path.isfile(os.path.join(root, req)):
            bad(req, 0, "required file is missing")
    for name, limit in (("PROMPT.md", 6000), ("PROMPT.short.md", 1400)):
        p = os.path.join(root, name)
        if os.path.isfile(p):
            n = len(_read(p))
            if n > limit:
                bad(name, 0, f"{n} chars exceeds the {limit} char budget")
    sk = os.path.join(root, "SKILL.md")
    if os.path.isfile(sk):
        meta, body = frontmatter(_read(sk))
        if meta is None:
            bad("SKILL.md", 1, "missing frontmatter")
        else:
            nm = meta.get("name", "")
            if not nm or len(nm) > 64 or not NAME_RE.fullmatch(nm):
                bad("SKILL.md", 1, "frontmatter name must be lowercase-hyphen, at most 64 chars")
            ds = meta.get("description", "")
            if not ds or len(ds) > 1024:
                bad("SKILL.md", 1, "frontmatter description must be 1-1024 chars")
        if len(body) > 500:
            bad("SKILL.md", 0, f"body is {len(body)} lines, budget is 500")
    for name in ("AGENTS.md", "PROMPT.md"):
        p = os.path.join(root, name)
        if not os.path.isfile(p):
            continue
        fenced = False
        for n, ln in enumerate(_read(p).splitlines(), 1):
            if "<!-- cc-only -->" in ln:
                fenced = True
                continue
            if "<!-- /cc-only -->" in ln:
                fenced = False
                continue
            if not fenced and CC_ONLY.search(ln):
                bad(name, n, "Claude Code specific term outside a cc-only fence")
    rd = os.path.join(root, "README.md")
    if os.path.isfile(rd):
        text = _read(rd).splitlines()
        idx = next((i for i, ln in enumerate(text) if re.search(r"(?i)works with", ln)), None)
        if idx is None or not any(re.match(r"^\s*\|\s*:?-{3,}", ln) for ln in text[idx:]):
            bad("README.md", 0, "no 'Works with' table")
    return out
