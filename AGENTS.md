# release-privacy-scanner

A stdlib Python CLI (`leakscan`) that finds publication leaks in a repo, its git history and release archives.

## Using this in your project

- Run `leakscan . --history` before a public push. Run `leakscan . --history --profile anonymous-submission` before sharing for double-blind review. Without installing: `python3 -I leakscan.py .`
- Add `--archive FILE` for each release archive, `--pack` to lint the packaging standard, `--json` for machine output.
- Exit codes: 0 no LEAK findings (WARN items may exist), 1 at least one LEAK, 2 usage or input error.
- Fix every LEAK. Read every WARN by hand. SANCTIONED items are counted, not failures.
- Never print, copy or commit a redacted value. Report the file, line and class only.
- Never put owner-specific regexes in the repository. Keep them in `.leakscan.local.txt` (git-ignored) and pass `--private-patterns`.
- Never add a broad allowlist entry to make a scan pass. Each entry needs a path glob, a regex and a reason.
- No PROMPT.md: CLI. The agent skill in SKILL.md covers chat use.

## Working on this repo

- Setup: `python -m pip install -e . pytest`
- Test: `python -m pytest -q` (runs offline; gitleaks is stubbed).
- Build secret-shaped and attribution-shaped fixtures at runtime by string concatenation, so no file in the repo trips a scanner.
- Do not write real paths, names or emails into tests, examples or docs.

<!-- cc-only -->
<!-- Claude Code reads CLAUDE.md, which imports this file. Nothing extra is needed. -->
<!-- /cc-only -->
