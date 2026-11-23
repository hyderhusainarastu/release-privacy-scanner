import json
import os
import tarfile
import zipfile

from conftest import fake_key, git, leakscan, trailer, user_path, write


def test_secret_caught_and_redacted(tree):
    key = fake_key()
    write(tree, "app.py", f'KEY = "{key}"\n')
    code, out, _ = leakscan(tree)
    assert code == 1
    assert "SECRET" in out and "app.py:1" in out
    assert key not in out and key[:12] not in out
    assert "sk*** (len 43)" in out


def test_lookalike_words_not_caught(tree):
    write(tree, "notes.md", "The task-force is risk-free. Open the desk-lamp ticket.\n")
    code, out, _ = leakscan(tree)
    assert code == 0, out
    assert "SECRET" not in out


def test_user_path_caught(tree):
    write(tree, "cfg.txt", f"root = {user_path()}\n")
    code, out, _ = leakscan(tree)
    assert code == 1 and "PATH" in out


def test_placeholder_path_ok(tree):
    write(tree, "doc.md", "Use /" + "Us" + "ers/<name>/ or /" + "home/you/ as an example.\n")
    assert leakscan(tree)[0] == 0


def test_email_rules(tree):
    write(tree, "a.txt", "ok: 12345+me@users.noreply.github.com and a@example.com and x@host.invalid\n")
    assert leakscan(tree)[0] == 0
    write(tree, "b.txt", "contact jane.roe" + "@" + "university-mail.net.org\n")
    code, out, _ = leakscan(tree)
    assert code == 1 and "EMAIL" in out


def test_hostname_warn_then_leak(tree):
    write(tree, "h.txt", "ssh build-box" + ".lan\n")
    code, out, _ = leakscan(tree)
    assert code == 0 and "WARN" in out
    code, out, _ = leakscan(tree, "--profile", "anonymous-submission")
    assert code == 1


def test_works_with_profiles(tree):
    write(tree, "README.md", "## Works with\n\nClaude Code, Codex and Cursor.\n")
    write(tree, "AGENTS.md", "Run the tests.\n")
    code, out, _ = leakscan(tree)
    assert code == 0
    assert "SANCTIONED" in out and "AI_TOOL" in out and "INSTRUCTION_FILE" in out
    code, out, _ = leakscan(tree, "--profile", "anonymous-submission")
    assert code == 1
    assert "AI_TOOL" in out.split("LEAK")[1]


def test_ai_fingerprint_is_leak_in_both(tree):
    write(tree, "x.txt", trailer() + "\nas an AI language model, I cannot\n")
    for prof in ("public-release", "anonymous-submission"):
        code, out, _ = leakscan(tree, "--profile", prof)
        assert code == 1 and "AI_FINGERPRINT" in out


def test_identity_info_vs_leak(tree):
    write(tree, "LICENSE", "MIT License\n\nCopyright (c) 2026 Jane Q Example\n")
    code, out, _ = leakscan(tree)
    assert code == 0 and "INFO" in out and "Jane" not in out
    code, out, _ = leakscan(tree, "--profile", "anonymous-submission")
    assert code == 1 and "IDENTITY" in out


def test_private_pattern_redacted_and_not_echoed(tree, tmp_path_factory):
    outside = str(tmp_path_factory.mktemp("priv"))
    pf = write(outside, "priv.txt", "# owner list\nzorblax-[a-z]+\n")
    write(tree, "r.md", "see Zorblax-Station for details\n")
    code, out, err = leakscan(tree, "--private-patterns", pf)
    assert code == 1
    assert "private-pattern #1" in out and "r.md:1" in out
    assert "Zo*** (len 15)" in out
    assert "zorblax-[a-z]+" not in out + err and "Zorblax" not in out


def test_default_private_file_warns_when_not_ignored(tree):
    git(tree, "init", "-q")
    write(tree, ".leakscan.local.txt", "hidden-name\n")
    write(tree, "a.txt", "hello\n")
    code, out, _ = leakscan(".", cwd=tree)
    assert code == 0 and "not git-ignored" in out
    write(tree, ".gitignore", ".leakscan.local.txt\n")
    _, out, _ = leakscan(".", cwd=tree)
    assert "not git-ignored" not in out


def test_default_private_file_is_used_and_not_scanned(tree):
    write(tree, ".leakscan.local.txt", "hidden-name\n")
    write(tree, "a.txt", "mentions hidden-name here\n")
    code, out, _ = leakscan(".", cwd=tree)
    assert code == 1 and "a.txt:1" in out and ".leakscan.local.txt:" not in out


def test_history_finds_secret_only_in_old_commit(tree):
    key = fake_key()
    write(tree, "cfg.py", f'K = "{key}"\n')
    git(tree, "init", "-q", "-b", "main")
    git(tree, "add", "."); git(tree, "commit", "-q", "-m", "add config")
    write(tree, "cfg.py", "K = None\n")
    git(tree, "commit", "-qam", "remove key")
    assert leakscan(tree)[0] == 0
    code, out, _ = leakscan(tree, "--history")
    assert code == 1 and "cfg.py" in out and "commit" in out
    assert key not in out


def test_history_scans_identity_and_messages(tree):
    write(tree, "a.txt", "hi\n")
    git(tree, "init", "-q", "-b", "main"); git(tree, "add", "."); git(tree, "commit", "-q", "-m", "init\n\n" + trailer("Gemini"))
    code, out, _ = leakscan(tree, "--history")
    assert code == 1 and "AI_FINGERPRINT" in out and "message" in out
    assert "IDENTITY" in out  # author name is INFO under public-release


def test_history_requires_repo(tree):
    write(tree, "a.txt", "x\n")
    assert leakscan(tree, "--history")[0] == 2


def test_archives(tree, tmp_path_factory):
    out_dir = str(tmp_path_factory.mktemp("arc"))
    z = os.path.join(out_dir, "rel.zip")
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("pkg/cfg.txt", f"k={fake_key()}\n")
    t = os.path.join(out_dir, "rel.tar.gz")
    src = write(out_dir, "src/p.txt", f"at {user_path('bob')}\n")
    with tarfile.open(t, "w:gz") as f:
        f.add(src, arcname="pkg/p.txt")
    empty = write(tree, "ok.txt", "fine\n")
    code, out, _ = leakscan(tree, "--archive", z, "--archive", t)
    assert code == 1 and "rel.zip!pkg/cfg.txt" in out and "rel.tar.gz!pkg/p.txt" in out
    assert fake_key() not in out


def test_allowlist_narrow(tree):
    write(tree, "docs/ex.md", f"example {user_path('carol')}\n")
    al = write(tree, "allow.txt", "docs/*.md | /project/notes | documented sample path\n")
    assert leakscan(os.path.join(tree, "docs"), "--allow", al)[0] == 1  # rel path is ex.md, glob needs docs/
    assert leakscan(tree, "--allow", al)[0] == 0


def test_allowlist_rejects_bare_word(tree):
    write(tree, "a.txt", "x\n")
    bad = write(tree, "bad.txt", "* | carol | because\n")
    code, _, err = leakscan(tree, "--allow", bad)
    assert code == 2 and "too broad" in err
    bad2 = write(tree, "bad2.txt", "docs/*.md | carol | because\n")
    code, _, err = leakscan(tree, "--allow", bad2)
    assert code == 2 and "bare-word" in err


def test_json_output(tree):
    write(tree, "app.py", f'K="{fake_key()}"\n')
    code, out, _ = leakscan(tree, "--json")
    d = json.loads(out)
    assert code == 1 and d["result"] == "FAIL" and d["summary"]["LEAK"] == 1
    assert fake_key() not in out


def test_extra_patterns_file(tree):
    write(tree, "a.txt", "ticket INT-4412 is internal\n")
    pf = write(tree, "p.txt", "# demo\n[TICKET:WARN]\n\\bINT-\\d+\\b\n")
    code, out, _ = leakscan(tree, "--patterns", pf)
    assert code == 0 and "TICKET" in out
    assert leakscan(tree, "--patterns", write(tree, "q.txt", "no header\n"))[0] == 2


def test_gitleaks_skipped_when_missing(tree, monkeypatch):
    write(tree, "a.txt", "x\n")
    monkeypatch.setenv("PATH", "/nonexistent")
    import subprocess, sys
    from conftest import ROOT
    r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "leakscan.py"), tree, "--with-gitleaks"],
                       capture_output=True, text=True)
    assert r.returncode == 0 and "gitleaks not found" in r.stdout


def test_gitleaks_stub_merged(tree, tmp_path_factory):
    binp = str(tmp_path_factory.mktemp("bin"))
    stub = write(binp, "gitleaks", '#!/bin/sh\nwhile [ $# -gt 0 ]; do [ "$1" = --report-path ] && R=$2; shift; done\n'
                 'echo \'[{"File":"a.txt","StartLine":3,"RuleID":"demo-rule"}]\' > "$R"\nexit 1\n')
    os.chmod(stub, 0o755)
    write(tree, "a.txt", "x\n")
    import subprocess, sys
    from conftest import ROOT
    env = dict(os.environ, PATH=binp + os.pathsep + os.environ["PATH"])
    r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "leakscan.py"), tree, "--with-gitleaks"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 1 and "demo-rule" in r.stdout


def test_exit_2_on_missing_path():
    assert leakscan("/nonexistent-dir-xyz")[0] == 2
