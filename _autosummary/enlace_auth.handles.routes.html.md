# enlace_auth.handles.routes

`/auth/handles/*`: the signed-in user’s handle, the availability check, lookups.

Every route needs a signed-in account (a handle is public to the platform’s users,
not to the open web) and none of them ever returns an email.

- `GET  /auth/handles/me` -> `{"handle", "chosen"}`; assigns the default on
  first call. While `chosen` is false, a frontend offers its “choose your
  username” step.
- `GET  /auth/handles/check?handle=<typed>` -> `{"handle", "available",
  "problem", "code", "suggestions"}`. Called as the person types.
- `POST /auth/handles/me` body `{"handle"}` -> `{"handle", "chosen"}`; posting
  the current handle confirms it. Errors are `{"detail": {"code", "message",
  "suggestions"}}` with 409 (taken), 429 (cooldown) or 422 (invalid, reserved).
  Under `/auth/`, so the platform’s double-submit CSRF check covers it.
- `GET  /auth/handles/{handle}` -> `{"handle"}` or `{"handle",
  "renamed_from"}` (a recent rename), 404 when no account holds it publicly.

Every route but `GET /me` is rate-limited per account (429): the check and the
lookup at *check_limit* per *check_window_seconds*, a claim at *claim_limit*.

### Functions

| [`make_handle_router`](#enlace_auth.handles.routes.make_handle_router)(\*, registry[, ...])   | Build the `/auth/handles` router over *registry*.   |
|--------------------------------------------------------------------------------------------|-----------------------------------------------------|

### enlace_auth.handles.routes.make_handle_router(, registry, rate_limiter=None, check_limit=120, check_window_seconds=60.0, claim_limit=20)

Build the `/auth/handles` router over *registry*.

*rate_limiter* (`allow(key, *, limit, window)`) bounds the availability
check and the lookup to *check_limit* calls per account per
*check_window_seconds*, and claims to *claim_limit*; the default counts in
memory, per process.

* **Return type:**
  `APIRouter`
