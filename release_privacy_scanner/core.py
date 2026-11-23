"""Pattern classes, severities and the per-line matcher."""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Iterable, Iterator

PROFILES = ("public-release", "anonymous-submission")

LEAK, WARN, SANCTIONED, INFO = "LEAK", "WARN", "SANCTIONED", "INFO"
SEVERITY_ORDER = (LEAK, WARN, SANCTIONED, INFO)

# Files that exist to instruct AI coding tools. Sanctioned in public releases,
# a leak in anonymous submissions.
INSTRUCTION_FILES = (
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "SKILL.md",
    ".github/copilot-instructions.md",
    ".cursorrules",
)


def redact(text: str) -> str:
    """First two characters plus the length. Never the full value."""
    return f"{text[:2]}*** (len {len(text)})"


@dataclass(frozen=True)
class Finding:
    severity: str
    cls: str
    path: str  # display path
    line: int
    detail: str
    rel: str = ""  # path relative to the scan root (used by the allowlist)
    commit: str = ""

    def key(self):
        return (self.cls, self.path, self.line, self.detail)


@dataclass(frozen=True)
class Rule:
    cls: str
    regex: re.Pattern
    detail: str
    public: str = LEAK
    anonymous: str = LEAK
    redact: bool = False
    files: tuple = ()  # fnmatch globs on the base name; empty = all files


def _c(p: str, flags: int = 0) -> re.Pattern:
    return re.compile(p, flags)


_TOOLS = r"(?:claude|chatgpt|gpt-?\d*|codex|gemini|copilot|cursor|anthropic|openai)"

SECRET_RULES = [
    Rule("SECRET", _c(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"), "api key shape (sk-)", redact=True),
    Rule("SECRET", _c(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "cloud access key id", redact=True),
    Rule("SECRET", _c(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "git host token", redact=True),
    Rule("SECRET", _c(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "git host fine-grained token", redact=True),
    Rule("SECRET", _c(r"\bAIza[0-9A-Za-z_-]{35}\b"), "cloud api key shape", redact=True),
    Rule("SECRET", _c(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "chat token shape", redact=True),
    Rule("SECRET", _c(r"\b[sr]k_live_[0-9A-Za-z]{20,}"), "payment key shape", redact=True),
    Rule("SECRET", _c(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----"), "private key header", redact=True),
    Rule(
        "SECRET",
        _c(r"(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d)\b[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-+/=.]{16,}[\"']"),
        "secret-like assignment",
        public=WARN,
        anonymous=WARN,
        redact=True,
    ),
]

FINGERPRINT_RULES = [
    Rule(
        "AI_FINGERPRINT",
        _c(r"(?i)\bco-authored[-]by\s*:.*\b" + _TOOLS + r"\b"),
        "AI attribution trailer",
    ),
    Rule(
        "AI_FINGERPRINT",
        _c(r"(?i)\b(?:generated|built|made|written|created)\s+(?:with|by|using)\s+\[?(?:" + _TOOLS + r"|an?\s+ai\b)"),
        "AI authorship phrasing",
    ),
    Rule(
        "AI_FINGERPRINT",
        _c(
            r"(?i)\b(?:claude\.ai/(?:share|chat|code)|chatgpt\.com/share|chat\.openai\.com/share"
            r"|gemini\.google\.com/share|g\.co/gemini/share)\b"
        ),
        "AI chat or session share URL",
    ),
    Rule("AI_FINGERPRINT", _c(r"(?i)\bclaude-session\s*:"), "AI session trailer"),
    Rule("AI_FINGERPRINT", _c(r"(?i)\bas an ai (?:language )?model\b"), "assistant boilerplate"),
]

TOOL_NAME_RULE = Rule(
    "AI_TOOL",
    _c(r"\b(?:ChatGPT|Codex|Claude(?: Code)?|Cursor|Gemini(?: CLI)?|Copilot|Anthropic|OpenAI)\b"),
    "AI tool name",
    public=SANCTIONED,
    anonymous=LEAK,
)

HOSTNAME_RULE = Rule(
    "HOSTNAME",
    _c(r"(?i)\b[a-z0-9][a-z0-9-]*\.(?:local|lan)\b(?![.\w-])"),
    "private hostname (.local/.lan)",
    public=WARN,
    anonymous=LEAK,
)

IDENTITY_RULES = [
    Rule(
        "IDENTITY",
        _c(r"(?i)^\s*copyright\s*(?:\(c\)|©)?\s*\d{4}(?:\s*[-–]\s*\d{4})?\s+(?P<who>\S.*)$"),
        "copyright holder",
        public=INFO,
        anonymous=LEAK,
        redact=True,
        files=("LICENSE*", "COPYING*", "NOTICE*"),
    ),
    Rule(
        "IDENTITY",
        _c(r"(?i)^\s*(?:author|authors|maintainer)\s*:\s*(?P<who>\S.*)$"),
        "author line",
        public=INFO,
        anonymous=LEAK,
        redact=True,
    ),
    Rule(
        "IDENTITY",
        _c(r"^\s*[-*_>~\s]*(?:written|created|maintained|authored|made|built) by\s+(?P<who>\S.*)$", re.I),
        "author footer",
        public=INFO,
        anonymous=LEAK,
        redact=True,
        files=("README*", "*.md", "*.rst", "*.txt"),
    ),
    Rule(
        "IDENTITY",
        _c(r"(?i)(?:__author__\s*=|\"author\"\s*:|^\s*authors?\s*=)\s*(?P<who>\S.*)$"),
        "package author metadata",
        public=INFO,
        anonymous=LEAK,
        redact=True,
        files=("*.py", "pyproject.toml", "setup.cfg", "package.json", "Cargo.toml"),
    ),
]

PATH_RULES = [
    ("/Users/", _c(r"(?<![\w.~-])/(?:Users|home|Volumes)/(?P<n>[A-Za-z0-9._-]+)/")),
    ("win", _c(r"(?i)\b[A-Z]:\\{1,2}Users\\{1,2}(?P<n>[A-Za-z0-9._ -]+?)\\")),
]
PATH_PLACEHOLDERS = {
    "user", "username", "you", "name", "me", "example", "yourname", "your-name", "someone",
    "runner", "vscode", "ubuntu", "shared", "public", "default", "all users", "foo", "alice-example",
}

EMAIL_RE = _c(r"[A-Za-z0-9._%+-]+@(?P<d>[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
EMAIL_OK_DOMAIN = _c(r"(?i)(?:^|\.)(?:users\.noreply\.github\.com|example\.(?:com|org|net)|[a-z0-9-]*invalid|test|example|localhost)$")
EMAIL_OK_LOCAL = _c(r"(?i)^(?:no-?reply|git)$")


def email_ok(local: str, domain: str) -> bool:
    return bool(EMAIL_OK_DOMAIN.search(domain)) or bool(EMAIL_OK_LOCAL.match(local)) or domain.lower().endswith("noreply.github.com")


# ---------------------------------------------------------------- pattern files

class PatternError(ValueError):
    pass


def parse_pattern_file(text: str, origin: str = "patterns"):
    """Format: '# comment', '[CLASS]' or '[CLASS:WARN]' header, then one regex per line.

    Returns Rule objects. The header severity applies to both profiles.
    """
    rules, cls, sev = [], None, LEAK
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            head = line[1:-1].strip()
            cls, _, s = head.partition(":")
            cls = cls.strip().upper()
            sev = s.strip().upper() or LEAK
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", cls) or sev not in (LEAK, WARN, INFO):
                raise PatternError(f"{origin}:{n}: bad class header {line!r}")
            continue
        if cls is None:
            raise PatternError(f"{origin}:{n}: regex before any [CLASS] header")
        try:
            rx = re.compile(line, re.I)
        except re.error as e:
            raise PatternError(f"{origin}:{n}: invalid regex ({e})") from None
        rules.append(Rule(cls, rx, f"{cls.lower()} pattern", public=sev, anonymous=sev))
    return rules


def parse_private_file(text: str, origin: str = "private patterns"):
    """One regex per line. Returns [(index, compiled)] with 1-based indexes."""
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            out.append((len(out) + 1, re.compile(line, re.I)))
        except re.error as e:
            raise PatternError(f"{origin}:{n}: invalid regex ({e})") from None
    return out


# ---------------------------------------------------------------- allowlist

@dataclass(frozen=True)
class AllowEntry:
    glob: str
    regex: re.Pattern
    reason: str


def parse_allow(text: str, origin: str = "allowlist"):
    """One entry per line: <path glob> | <regex> | <reason>. Narrow entries only."""
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(" | ")]
        if len(parts) != 3 or not all(parts):
            raise PatternError(f"{origin}:{n}: expected '<path glob> | <regex> | <reason>'")
        glob, rx, reason = parts
        if glob.strip("*/") == "":
            raise PatternError(f"{origin}:{n}: path glob is too broad ({glob!r})")
        if re.fullmatch(r"[\w\s.-]*|\.\*|\.\+|\^?\.\*\$?", rx):
            raise PatternError(f"{origin}:{n}: bare-word or catch-all regex is not allowed ({rx!r})")
        try:
            out.append(AllowEntry(glob, re.compile(rx), reason))
        except re.error as e:
            raise PatternError(f"{origin}:{n}: invalid regex ({e})") from None
    return out


def allowed(entries: Iterable[AllowEntry], rel: str, line_text: str) -> bool:
    for e in entries:
        if fnmatch.fnmatch(rel, e.glob) and e.regex.search(line_text):
            return True
    return False


# ---------------------------------------------------------------- matching

class Matcher:
    def __init__(self, profile: str, extra_rules=(), private=(), allow=()):
        if profile not in PROFILES:
            raise ValueError(f"unknown profile {profile!r}")
        self.profile = profile
        self.extra = list(extra_rules)
        self.private = list(private)
        self.allow = list(allow)

    def sev(self, rule: Rule) -> str:
        return rule.public if self.profile == "public-release" else rule.anonymous

    def _apply(self, rule: Rule, rel: str) -> bool:
        if not rule.files:
            return True
        base = rel.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(base, g) for g in rule.files)

    def scan_line(self, line: str, rel: str) -> Iterator[tuple]:
        """Yield (severity, class, detail) for one line of text."""
        for rule in SECRET_RULES + FINGERPRINT_RULES + [TOOL_NAME_RULE, HOSTNAME_RULE] + IDENTITY_RULES + self.extra:
            if not self._apply(rule, rel):
                continue
            m = rule.regex.search(line)
            if not m:
                continue
            if rule.cls == "HOSTNAME" and m.group(0).lower().startswith("localhost"):
                continue
            shown = m.group("who") if "who" in rule.regex.groupindex else m.group(0)
            detail = f"{rule.detail}: {redact(shown)}" if rule.redact else f"{rule.detail}: {shown.strip()[:80]}"
            yield self.sev(rule), rule.cls, detail
        for kind, rx in PATH_RULES:
            for m in rx.finditer(line):
                if m.group("n").lower() in PATH_PLACEHOLDERS:
                    continue
                yield LEAK, "PATH", f"local user path: {m.group(0)}"
        for m in EMAIL_RE.finditer(line):
            local = m.group(0).rsplit("@", 1)[0]
            if not email_ok(local, m.group("d")):
                yield LEAK, "EMAIL", f"email address: {m.group(0)}"
        for idx, rx in self.private:
            m = rx.search(line)
            if m:
                yield LEAK, "PRIVATE", f"private-pattern #{idx}: {redact(m.group(0))}"

    def scan_text(self, text: str, rel: str, display: str, commit: str = "") -> list:
        out = []
        for n, line in enumerate(text.splitlines(), 1):
            if len(line) > 4000:
                line = line[:4000]
            for sev, cls, detail in self.scan_line(line, rel):
                if allowed(self.allow, rel, line):
                    continue
                out.append(Finding(sev, cls, display, n, detail, rel, commit))
        return out

    def instruction_file(self, rel: str, display: str) -> Finding | None:
        norm = rel.replace("\\", "/")
        for name in INSTRUCTION_FILES:
            if norm == name or norm.endswith("/" + name):
                sev = SANCTIONED if self.profile == "public-release" else LEAK
                return Finding(sev, "INSTRUCTION_FILE", display, 0, f"AI instruction file {name}", rel)
        return None
