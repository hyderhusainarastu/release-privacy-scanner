import os

from conftest import leakscan, write

GOOD_README = "# demo\n\n## Works with\n\n| Surface | How | Status |\n|---|---|---|\n| CLI | cli | not tested |\n"


def good(tree):
    write(tree, "README.md", GOOD_README)
    write(tree, "AGENTS.md", "# demo\n\nRun the tests.\n\n<!-- cc-only -->\nUse the Task tool.\n<!-- /cc-only -->\n")
    write(tree, "LICENSE", "MIT License\n")
    write(tree, "SKILL.md", "---\nname: demo-skill\ndescription: Does a thing.\n---\n# body\n")
    write(tree, "PROMPT.md", "short prompt\n")


def test_pack_good(tree):
    good(tree)
    code, out, _ = leakscan(tree, "--pack")
    assert code == 0, out


def test_pack_oversize_prompt(tree):
    good(tree)
    write(tree, "PROMPT.md", "x" * 6001)
    code, out, _ = leakscan(tree, "--pack")
    assert code == 1 and "PROMPT.md" in out and "6000" in out
    write(tree, "PROMPT.md", "ok\n")
    write(tree, "PROMPT.short.md", "y" * 1401)
    assert leakscan(tree, "--pack")[0] == 1


def test_pack_cc_only_outside_fence(tree):
    good(tree)
    write(tree, "AGENTS.md", "# demo\n\nHook it with Pre" + "ToolUse before commits.\n")
    code, out, _ = leakscan(tree, "--pack")
    assert code == 1 and "AGENTS.md:3" in out


def test_pack_missing_files_and_table(tree):
    good(tree)
    os.remove(os.path.join(tree, "LICENSE"))
    write(tree, "README.md", "# demo\n\nWorks with everything.\n")
    code, out, _ = leakscan(tree, "--pack")
    assert code == 1 and "LICENSE" in out and "Works with" in out


def test_pack_skill_frontmatter(tree):
    good(tree)
    write(tree, "SKILL.md", "---\nname: Bad_Name\ndescription: x\n---\nbody\n")
    assert leakscan(tree, "--pack")[0] == 1
    write(tree, "SKILL.md", "---\nname: ok-name\ndescription: x\n---\n" + "line\n" * 501)
    code, out, _ = leakscan(tree, "--pack")
    assert code == 1 and "501" in out
