"""The command line itself: what argv spellings the parser accepts, and what they exit.

``tests/test_cli.py`` calls the verb functions directly — as Python functions, with
keyword arguments. That is worth doing (it is where the store behaviour is pinned) but
it says nothing about the CLI: every test in that file would still pass if the dispatch
call were deleted outright. Nothing here is true unless the parser is real.

Recorded from the ``argh`` implementation before the ``cw`` migration and replayed
after: 31 argv vectors — top-level and per-subcommand ``--help``, the no-argument case,
four usage errors, and eleven real invocations against a scratch home — produced
byte-identical stdout, stderr and exit codes. That full-body diff cannot live in CI,
because CPython rewrites argparse's own option column between versions and this repo's
matrix spans several. What is asserted here is the grammar, which does not move.

The load-bearing case is ``revoke-connector-session``. Its signature is
``revoke_connector_session(family=None, *, email=None, toml=...)``: a *defaulted
positional*. Under cw's default convention (:data:`cw.ARGH`, which reproduces
``argh.dispatch_commands``) ``family`` renders as the option ``--family``. Under
``cw.MODERN`` — equally ``cw.BY_NAME_IF_KWONLY``, which is what ``argh.add_commands``
applies post-0.30 — it becomes the positional
``enlace-auth revoke-connector-session <family>``. That reinterpretation parses, runs,
and revokes on a different reading of the operator's intent, so both halves are
asserted: the option is accepted AND the positional is rejected.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import enlace_auth
from enlace_auth.__main__ import COMMANDS

_ROOT = Path(enlace_auth.__file__).resolve().parent.parent
_CLI_TIMEOUT = 120

#: Every verb the CLI exposes, spelled as the command line spells it.
COMMAND_NAMES = [f.__name__.replace("_", "-") for f in COMMANDS]

_RUNNER = """
import sys
sys.argv = ['enlace-auth'] + {argv!r}
from enlace_auth.__main__ import main
main()
"""


@pytest.fixture
def scratch_home(tmp_path):
    """A HOME of its own.

    The default store path is ``~/.enlace/platform_store``, so a test that runs a real
    verb writes to the operator's own store unless HOME is redirected. It also makes
    the read verbs deterministic: every listing starts empty.
    """
    home = tmp_path / "home"
    home.mkdir()
    return home


def run_cli(*argv, home, cwd=None):
    """Run ``enlace-auth <argv>`` in a subprocess, ``argv[0]`` pinned to the name."""
    return subprocess.run(
        [sys.executable, "-c", _RUNNER.format(argv=list(argv))],
        cwd=str(cwd or home),
        capture_output=True,
        text=True,
        timeout=_CLI_TIMEOUT,
        env={
            "PYTHONPATH": str(_ROOT),
            "PATH": "/usr/bin:/bin",
            "HOME": str(home),
            "COLUMNS": "80",
        },
    )


def test_every_command_is_reachable_and_documents_itself(scratch_home):
    """Each verb in COMMANDS is a subcommand, and its ``--help`` renders."""
    top = run_cli("--help", home=scratch_home)
    assert top.returncode == 0
    for name in COMMAND_NAMES:
        assert name in top.stdout, f"{name} missing from `enlace-auth --help`"
        sub = run_cli(name, "--help", home=scratch_home)
        assert sub.returncode == 0, sub.stderr
        assert sub.stdout.startswith(f"usage: enlace-auth {name}")


def test_family_is_an_option_not_a_positional(scratch_home):
    """The grammar trap. See the module docstring for what the other reading does."""
    help_ = run_cli("revoke-connector-session", "--help", home=scratch_home)
    assert "[-f FAMILY]" in help_.stdout
    assert "--family FAMILY" in help_.stdout

    named = run_cli("revoke-connector-session", "--family", "fam", home=scratch_home)
    assert named.returncode == 0
    assert "Revoked 0 refresh token(s) for fam." in named.stdout

    positional = run_cli("revoke-connector-session", "fam", home=scratch_home)
    assert positional.returncode == 2
    assert "unrecognized arguments" in positional.stderr


def test_required_positionals_stay_required(scratch_home):
    """``revoke-session`` and ``grant`` take bare arguments, not flags."""
    assert run_cli("revoke-session", home=scratch_home).returncode == 2
    assert run_cli("grant", "only-one", home=scratch_home).returncode == 2

    granted = run_cli("grant", "myapp", "a@b.c", "--note", "hi", home=scratch_home)
    assert granted.returncode == 0
    assert "Granted a@b.c access to myapp" in granted.stdout

    listed = run_cli("list-grants", "--json", home=scratch_home)
    assert [r["app_id"] for r in json.loads(listed.stdout)] == ["myapp"]

    revoked = run_cli("revoke-grant", "myapp", "a@b.c", home=scratch_home)
    assert revoked.returncode == 0
    assert json.loads(run_cli("list-grants", "--json", home=scratch_home).stdout) == []


def test_no_arguments_prints_usage_to_stdout_and_exits_zero(scratch_home):
    """argh's behaviour; plain argparse with a required subparser does NOT do this."""
    result = run_cli(home=scratch_home)
    assert result.returncode == 0
    assert result.stdout.startswith("usage: enlace-auth")
    assert result.stderr == ""


@pytest.mark.parametrize(
    "argv",
    [
        ("no-such-command",),
        ("list-users", "--no-such-flag"),
        ("revoke-session",),
        ("grant", "only-one"),
    ],
)
def test_usage_errors_exit_two(argv, scratch_home):
    """``cw.dispatch`` *returns* the code, so ``main`` must ``raise SystemExit`` on it.

    Dropping that ``SystemExit`` turns every one of these into exit 0, which no other
    test in this suite would notice.
    """
    assert run_cli(*argv, home=scratch_home).returncode == 2


@pytest.mark.parametrize(
    "verb", ["list-users", "list-sessions", "list-grants", "list-connector-sessions"]
)
def test_json_listings_stay_machine_readable(verb, scratch_home):
    result = run_cli(verb, "--json", home=scratch_home)
    assert result.returncode == 0
    assert json.loads(result.stdout) == []


def test_a_verb_that_reports_a_missing_prerequisite_exits_nonzero(scratch_home):
    """``reset-link`` needs a signing key; without one it is a failure, not a no-op."""
    result = run_cli("reset-link", "a@b.c", "--hours", "3", home=scratch_home)
    assert result.returncode == 1
    assert "No signing key" in result.stderr


def test_the_package_declares_the_cli_library_it_imports():
    """``enlace_auth/__main__.py`` imports cw; the dependency list has to say so."""
    pyproject = (_ROOT / "pyproject.toml").read_text()
    assert '"cw>=' in pyproject
    assert "argh" not in pyproject
