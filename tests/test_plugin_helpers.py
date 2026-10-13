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


def _contend_for_stale_claim(directory, key, barrier, results):
    import pathlib
    import time

    # Widen the stat-to-unlink window so a race shows up in a few rounds, not
    # one in thirty: this child process is the only one that sees the patch.
    unlink = pathlib.Path.unlink

    def slow_unlink(self, *args, **kwargs):
        time.sleep(0.005)
        return unlink(self, *args, **kwargs)

    pathlib.Path.unlink = slow_unlink
    claim = _make_file_claim(directory, keep_seconds=60)
    barrier.wait()
    results.put(claim(key))


def test_a_stale_claim_is_taken_over_by_exactly_one_process(tmp_path):
    """Stat-then-unlink-then-create let two processes both take one stale claim.

    P2 could unlink the claim P1 had just re-created, then create its own (#60).
    """
    import os
    import time

    contenders, rounds = 8, 20
    ctx = mp.get_context("fork")
    key = "f" * 64
    for round_ in range(rounds):
        directory = tmp_path / str(round_)
        directory.mkdir()
        stale = directory / key
        stale.touch()
        os.utime(stale, (time.time() - 600, time.time() - 600))
        barrier, results = ctx.Barrier(contenders), ctx.Queue()
        procs = [
            ctx.Process(
                target=_contend_for_stale_claim,
                args=(str(directory), key, barrier, results),
            )
            for _ in range(contenders)
        ]
        for p in procs:
            p.start()
        granted = [results.get(timeout=30) for _ in procs]
        for p in procs:
            p.join(timeout=30)
        assert sum(granted) == 1, f"round {round_}: {sum(granted)} winners"


def test_a_claim_sweeps_stale_entries_but_keeps_its_own(tmp_path):
    import os
    import time

    claim = _make_file_claim(str(tmp_path), keep_seconds=60)
    for i in range(5):
        stale = tmp_path / f"{i:064x}"
        stale.touch()
        os.utime(stale, (time.time() - 600, time.time() - 600))
    assert claim("1" * 64) is True  # triggers the sweep
    assert [p.name for p in tmp_path.iterdir()] == ["1" * 64]
    assert claim("1" * 64) is False


def test_a_stale_claim_swept_while_waiting_is_still_granted(tmp_path, monkeypatch):
    """Found by the review of #61: the takeover's stat raced a sweep.

    The key was free (the sweep had removed the stale file), yet the takeover
    reported it taken, and the caller turned that into ``invalid_grant``.
    """
    import os
    import time

    claim = _make_file_claim(str(tmp_path), keep_seconds=60)
    key = "9" * 64
    stale = tmp_path / key
    stale.touch()
    os.utime(stale, (time.time() - 600, time.time() - 600))

    real_open = os.open
    swept = []

    def open_then_sweep(path, flags, *args):
        # The first O_EXCL attempt fails on the stale file; a sweep in another
        # process then removes it before our takeover gets the lock.
        if str(path) == str(stale) and flags & os.O_EXCL and not swept:
            swept.append(True)
            try:
                return real_open(path, flags, *args)
            finally:
                stale.unlink()
        return real_open(path, flags, *args)

    monkeypatch.setattr(os, "open", open_then_sweep)
    assert claim(key) is True


def test_a_claim_dir_that_cannot_be_locked_is_logged(tmp_path, monkeypatch, caplog):
    import os
    import time

    import sys

    plugin = sys.modules["enlace_auth.plugin"]

    def no_locks(fd, op):
        raise OSError(37, "No locks available")

    monkeypatch.setattr(plugin.fcntl, "flock", no_locks)
    claim = _make_file_claim(str(tmp_path), keep_seconds=60)
    key = "8" * 64
    stale = tmp_path / key
    stale.touch()
    os.utime(stale, (time.time() - 600, time.time() - 600))
    assert claim(key) is False  # fail closed
    assert "cannot lock claim dir" in caplog.text
