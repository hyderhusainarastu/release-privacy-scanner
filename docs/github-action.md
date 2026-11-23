# Run leakscan in GitHub Actions

Sample workflow. It is documentation, not an active workflow in this repository.
Copy it to `.github/workflows/leakscan.yml` in the repository you want to check.

```yaml
name: leakscan
on:
  pull_request:
  push:
    branches: [main]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # needed for --history
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install release-privacy-scanner
      - run: leakscan . --history --profile public-release
```

Use `--profile anonymous-submission` for a repository that will be shared for double-blind review.
Keep private patterns out of the repository; supply them from a CI secret written to a file at run time
and pass it with `--private-patterns`.
