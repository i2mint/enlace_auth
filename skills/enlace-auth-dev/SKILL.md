---
name: enlace-auth-dev
description: >-
  How to work on the enlace_auth codebase itself: run and write tests, change
  the auth, CSRF, session, grant, share or admin code safely, and what a change
  must keep true. Use when editing files in enlace_auth/, fixing an enlace_auth
  issue, reviewing a pull request to it, or when asked how enlace_auth is
  organized or tested.
metadata:
  audience: developers
---

# Working on enlace_auth

Read `CLAUDE.md` first for the architecture map. This skill is the working loop.

## Set up and run

```bash
uv venv -q .venv && . .venv/bin/activate
uv pip install -q -e ".[dev,oauth]" pip
python -m pytest -q --doctest-modules enlace_auth tests -p no:warnings
```

About 700 tests, roughly 70 seconds. For one area, `python -m pytest tests/test_csrf.py tests/test_csrf_scope.py -q`.

## The loop for a fix

1. Write the failing test first and watch it fail for the right reason. Copy a neighbor: `tests/test_csrf_scope.py` (full platform through `TestClient`), `tests/test_csrf.py` (a middleware driven directly as ASGI), `tests/test_shares.py` (a store over a dict).
2. Fix the code. Run the whole suite, not only your file: many tests share helpers such as `tests/test_admin.py::_csrf` and `_seed_account`.
3. Revert only the fix and confirm the test fails again.
4. Run `ruff check` and `ruff format` on the files you touched. Do not edit `version` in `pyproject.toml`; CI bumps it.

## Invariants a change must keep

- **Deny by default.** A new access level, route or resource is closed until something opens it. Add a test for the denied path beside the allowed one.
- **Pure ASGI.** No `BaseHTTPMiddleware`. Middleware order is auth, then store injection, then CSRF (see `plugin.wire`).
- **One predicate for access.** The gate and the launcher both use `enlace.access.is_user_allowed`. A new rule goes there, not in a second copy.
- **One normal form for addresses.** Go through `enlace_auth/emails.py`. A written allowlist entry is widened with `account_spellings`; a stored account key is compared exactly.
- **CSRF is checked everywhere it was; minting is narrow.** `CSRFMiddleware(mint_prefixes=...)` limits where the cookie is set, never where the check runs. A new client of the double-submit check gets its token from `GET /auth/csrf`.
- **Credential changes revoke.** Anything that changes a password or deletes an account calls `on_credentials_changed` so sessions and connector refresh families end together.
- **Damaged records must not crash a sweep.** Stores are hand-editable files; a loop over records (`ShareStore.list_all`, account deletion, doctor checks) skips or reports a malformed one instead of raising.

## Adding a store or route

Stores are `MutableMapping`s made by the factories in `stores/backends.py`; take one as an argument so a test can pass a dict. Routes are `make_*_router(...)` functions that `plugin.wire` includes; they inherit CSRF and auth, so do not add a bypass without an explicit exempt prefix and a test that names why.

## Releasing

Merging to `main` publishes through CI (wads reusable workflow). Do not tag or bump by hand.
