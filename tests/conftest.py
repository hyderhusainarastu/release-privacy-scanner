import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def fake_key():
    # Built at runtime so this file never contains a key-shaped string.
    return "sk" + "-" + "A1b2C3d4" * 5


def user_path(name="alice"):
    return "/" + "Us" + "ers/" + name + "/project/notes.txt"


def trailer(tool="Claude"):
    return "Co-" + "Authored-By: " + tool + " <noreply@example.com>"


def write(base, rel, text):
    p = os.path.join(base, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)
    return p


def leakscan(*args, cwd=None):
    r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "leakscan.py"), *args],
                       capture_output=True, text=True, cwd=cwd)
    return r.returncode, r.stdout, r.stderr


def git(cwd, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="dev", GIT_AUTHOR_EMAIL="dev@users.noreply.github.com",
               GIT_COMMITTER_NAME="dev", GIT_COMMITTER_EMAIL="dev@users.noreply.github.com")
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True, env=env)


@pytest.fixture
def tree(tmp_path):
    return str(tmp_path)
