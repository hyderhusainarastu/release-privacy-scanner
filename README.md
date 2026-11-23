# release-privacy-scanner

`leakscan` scans a repository, its git history and release archives for publication leaks before a public push or a double-blind submission. It is for maintainers, researchers and anyone who hands code to people outside their own machine.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

It flags local paths, personal identifiers, emails, private hostnames, AI-tool fingerprints and secret-shaped strings. Two profiles encode different policies: `public-release` and `anonymous-submission`. Standard library only, Python 3.10+.

## Works with

| Surface | How (prompt / native skill / CLI / hook / MCP) | Status |
|---|---|---|
| Terminal / CI | CLI (`leakscan`, or `python3 -I leakscan.py`) | tested 2026-11-23, Python 3.14, git 2.54, macOS |
| pre-commit | hook (`.pre-commit-hooks.yaml`) | not tested |
| GitHub Actions | CLI in a workflow (`docs/github-action.md`) | not tested |
| Claude Code | native skill (`SKILL.md`) and CLI | not tested |
| Codex | native skill via .agents/skills, and CLI | not tested |
| Gemini CLI | native skill via .agents/skills, and CLI | not tested |
| Cursor | AGENTS.md, skill via .agents/skills, and CLI | not tested |
| Copilot | pointer to AGENTS.md, and CLI | not tested |
| ChatGPT / Claude.ai / Gemini (chat) | prompt (`PROMPT.md`), a reading aid only | not tested |

## Quick start

```sh
pip install release-privacy-scanner     # or: git clone <repo> && python3 -I leakscan.py .
leakscan . --history                    # working tree + every blob, author and message in git history
leakscan . --history --profile anonymous-submission
leakscan dist/ --archive release.zip --archive release.tar.gz
leakscan . --pack                       # also lint README, AGENTS.md, SKILL.md, PROMPT.md budgets
```

As a skill (Claude Code, Codex, Gemini CLI, Cursor):

```sh
./install.sh --claude                    # ~/.claude/skills/release-privacy-scanner
./install.sh --agents --project .        # .agents/skills (Codex, Cursor, Gemini CLI)
```

Options: `--patterns FILE` (extra patterns, repeatable), `--private-patterns FILE`, `--allow FILE`, `--json`, `--with-gitleaks`. Exit codes: 0 no LEAK, 1 at least one LEAK, 2 usage error.

## Example

A scratch directory with a key-shaped string, a note naming a fictional codename listed in a private pattern file, and an instruction file:

```
$ leakscan . --private-patterns ../private-patterns.txt
leakscan 0.1.0  profile=public-release  files=3 blobs=0 commits=0 skipped=0

LEAK (2)
  app.py:1  SECRET  api key shape (sk-): sk*** (len 43)
  notes.md:1  PRIVATE  private-pattern #1: Zo*** (len 7)

SANCTIONED (counted, not failures): 1
  AGENTS.md  INSTRUCTION_FILE x1

result: FAIL  (2 LEAK, 0 WARN, 1 SANCTIONED, 0 INFO)
```

Secrets and private-pattern hits are always redacted to the first two characters plus the length.

## Why two profiles

- `public-release`: the repository will be public. Naming Claude Code, Codex, Cursor and similar tools in a compatibility table, and shipping AGENTS.md, CLAUDE.md, GEMINI.md, SKILL.md or a Copilot instructions file, is intended, so those are SANCTIONED (listed and counted, never a failure). Author and copyright lines are INFO. Paths, personal emails, secret shapes and AI attribution trailers are still LEAK.
- `anonymous-submission`: reviewers must not learn who wrote this. AI tool names, instruction files, author identity, copyright holders and private hostnames are LEAK.

Severities: LEAK (exit 1), WARN (printed, exit 0), SANCTIONED and INFO (counted). Classes: SECRET, PATH, EMAIL, HOSTNAME, AI_FINGERPRINT, AI_TOOL, INSTRUCTION_FILE, IDENTITY, PRIVATE, PACK.

## Private patterns

Owner-specific names (a surname, a codename, an institution) must not live in the repository you are scanning. Put one regex per line in `.leakscan.local.txt` (picked up automatically from the working directory or scan root) or pass `--private-patterns FILE`. The scanner warns if that file is not git-ignored, reports hits as `private-pattern #N` with file:line and a redacted match, and never prints the pattern text. See `examples/private-patterns.example.txt`.

## Allowlist

Each line is `<path glob> | <regex> | <reason>`. A bare word, a catch-all regex or a `*` glob is rejected. See `examples/allow.example.txt`.

## Use with gitleaks and trufflehog

Those tools find secrets, and they are good at it. This one finds publication leaks: a home-directory path, a co-author trailer, a copyright line or a `.local` hostname is not a secret, but it still should not ship, and a double-blind submission has a different policy from a public release. Run both. `--with-gitleaks` runs `gitleaks detect` when it is on PATH and merges its findings as SECRET; otherwise it prints that it was skipped (that code path is tested with a stub only, not against a real gitleaks).

## How it differs

- gitleaks, trufflehog, detect-secrets: deep secret detection (entropy, verification, many vendor rules). leakscan carries only a small set of anchored vendor shapes.
- git-filter-repo and BFG: rewrite history. leakscan only reports; it never modifies anything.
- Generic grep or pre-commit pattern hooks: no profiles, no redaction, no archives, no history attribution.

## Limits

- Regex scanning misses paraphrased or indirect identities (a nickname, a distinctive project description). Review WARN and INFO items by hand, and read README footers and sample data yourself.
- The secret rules are a short list of vendor shapes plus one assignment heuristic; they will miss unlisted formats. Use a dedicated secret scanner too.
- Binary files and files over 2 MB are skipped and counted. Images, PDFs and notebooks outputs can carry metadata this tool does not read.
- History scan attributes a blob to the oldest commit that added it; blobs only reachable from stashes or unreachable objects are not scanned.
- Archives are read in memory; nested archives are not opened.
- Test counts and the tested dates above are the only measurements claimed; no accuracy or speed figures are published.

## Develop

```sh
python -m pip install -e . pytest
python -m pytest -q        # offline
bash test_install.sh       # skill installer test
```

## Related

- palimnote-tools catalog: https://github.com/hyderhusainarastu/palimnote-tools

## Keywords

privacy scan, anonymize repository, double-blind review, release checklist, pre-commit hook, secret shapes, git history scan, local path leak, AGENTS.md lint.

---
Part of palimnote-tools - more at https://github.com/hyderhusainarastu
