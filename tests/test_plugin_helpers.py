"""Tests for plugin-level helpers that guard connector sessions.

These exist because of a production outage in which every MCP connector was
stranded for a day: the pieces here are the ones whose failure modes end a
session in a way only a human can undo.
"""

from __future__ import annotations

import multiprocessing as mp

from enlace_auth.plugin import _make_file_claim, _make_is_active


def _claim_in_child(args):
    directory, key = args
    return _make_file_claim(directory)(key)


def test_a_claim_is_granted_exactly_once_across_processes(tmp_path):
    """An in-process lock is not enough: production runs several workers."""
    key = "a" * 64
    with mp.Pool(8) as pool:
        granted = pool.map(_claim_in_child, [(str(tmp_path), key)] * 8)
    assert sum(granted) == 1


def test_a_released_claim_can_be_taken_again(tmp_path):
    claim = _make_file_claim(str(tmp_path))
    key = "b" * 64
    assert claim(key) is True
    assert claim(key) is False
    claim.release(key)
    assert claim(key) is True, "a released claim must not strand the token forever"


def test_releasing_a_claim_that_was_never_taken_is_harmless(tmp_path):
    claim = _make_file_claim(str(tmp_path))
    claim.release("c" * 64)  # must not raise


def test_an_unreadable_user_store_does_not_revoke_everyone(caplog):
    """A False answer revokes a whole connector session.

    Treating a transient store failure as "account deleted" would end every
    connector session at once — the outage this guards against, triggered by a
    disk hiccup rather than an attacker.
    """

    class Broken:
        def __contains__(self, key):
            raise OSError("store unavailable")

    assert _make_is_active(Broken())("someone@example.com") is True


def test_a_readable_store_still_reports_a_missing_account(tmp_path):
    assert _make_is_active({"a@example.com": {}})("a@example.com") is True
    assert _make_is_active({"a@example.com": {}})("gone@example.com") is False


def test_a_stale_claim_is_taken_over(tmp_path):
    """A worker killed after claiming must not strand the token forever.

    claim() returning False on FileExistsError meant the client's own retries
    could never heal it: they never reach the sweep that would clear the file.
    """
    import os
    import time

    claim = _make_file_claim(str(tmp_path), keep_seconds=1)
    key = "d" * 64
    assert claim(key) is True
    assert claim(key) is False  # still fresh: nobody may take it

    stale = tmp_path / key
    os.utime(stale, (time.time() - 10, time.time() - 10))
    assert claim(key) is True, "a dead worker's claim stranded the token forever"


def test_takeover_does_not_apply_to_a_live_claim(tmp_path):
    claim = _make_file_claim(str(tmp_path), keep_seconds=3600)
    key = "e" * 64
    assert claim(key) is True
    assert claim(key) is False
    assert claim(key) is False
