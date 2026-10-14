"""The README's runnable example runs, and the shipped skills are well formed."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKILL_DIRS = [
    ROOT / "enlace_auth" / "data" / "skills" / "enlace-auth-usage",
    ROOT / "skills" / "enlace-auth-dev",
]


def test_readme_example_runs(monkeypatch):
    text = (ROOT / "README.md").read_text()
    match = re.search(r"<!-- readme-example -->\n```python\n(.*?)\n```", text, re.S)
    assert match, "README lost its marked example"
    monkeypatch.setenv("ENLACE_SIGNING_KEY", "a-demo-key-of-at-least-32-characters")
    exec(compile(match.group(1), "README.md", "exec"), {"__name__": "readme"})


@pytest.mark.parametrize("skill_dir", SKILL_DIRS, ids=lambda p: p.name)
def test_skill_is_spec_clean(skill_dir):
    text = (skill_dir / "SKILL.md").read_text()
    front = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert front, "no frontmatter"
    name = re.search(r"^name: (.+)$", front.group(1), re.M).group(1).strip()
    assert name == skill_dir.name
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name)
    top_keys = set(re.findall(r"^([a-z-]+):", front.group(1), re.M))
    assert top_keys <= {"name", "description", "license", "metadata", "compatibility"}
    assert len(text.splitlines()) < 500


def test_claude_skill_symlinks_resolve():
    if not (ROOT / ".claude").exists():
        pytest.skip("not a git checkout (an sdist leaves .claude out on purpose)")
    for skill_dir in SKILL_DIRS:
        link = ROOT / ".claude" / "skills" / skill_dir.name
        assert link.is_symlink()
        assert link.resolve() == skill_dir.resolve()
