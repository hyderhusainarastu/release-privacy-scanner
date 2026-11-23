---
name: release-privacy-scanner
description: Scan a repo, its git history and release archives for local paths, personal identifiers, emails, hostnames, AI fingerprints and secret-shaped strings before a public push or a double-blind submission. Use before publishing.
---

# Scan before you publish

1. Install: `pip install release-privacy-scanner`, or run `python3 -I leakscan.py` from a clone.
2. Choose the profile. `public-release` for a public repository. `anonymous-submission` for double-blind review, where AI tool names, instruction files and author identity also count as leaks.
3. Run `leakscan . --history --profile <profile>`. Add `--archive release.zip` for each archive and `--pack` when the repo follows the shared packaging standard.
4. If the owner keeps private patterns, pass `--private-patterns <file>`. Never copy that file into the repo.
5. Read the report. LEAK means fix it (exit 1). WARN means review by hand. SANCTIONED and INFO are counted for your information.
6. Fix the source text. A hit inside git history needs the owner's decision (rewriting history is theirs to approve); do not rewrite it yourself.
7. Re-run until the result is PASS.

Rules for the agent:

- Never print a redacted value (the report already shows the first two characters and the length). Quote file, line and class only.
- Never loosen the allowlist to silence a hit. Entries are `<path glob> | <regex> | <reason>` and must be narrow.
- Regex scanning misses paraphrased identities. After a PASS, still skim README footers, LICENSE holders and sample data.
- This tool finds publication leaks. Use gitleaks or trufflehog for deep secret detection; `--with-gitleaks` merges its results when installed.
