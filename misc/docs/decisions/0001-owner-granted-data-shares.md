# ADR 0001 — Owner-granted data shares

- Status: accepted, 2026-10-01 (revised the same day after an adversarial review; the review's findings and what was done with each are at the end)
- First consumer: a maths-practice app on a family-run enlace platform (a child's practice sessions, shared with her parents)

## Context

enlace_auth answers one authorization question today: *may this user open this app?* (`access` levels, `allowed_users`, admin-made **grants** in `auth/grants.py`). Its per-user store (`stores/middleware.py`) then scopes every read and write to `"{user_id}/{app_id}/"`, the signed-in user's own prefix, with no way to reach anyone else's.

The first real case needs a second question: *may this user read or write that user's data in this app?* A child owns her practice sessions in one app; her two parents, signed in as themselves, need to see and add to them from any device. Nothing in enlace or enlace_auth covers it (no issue, no ADR; only admin grants exist).

It is a mechanism, not a feature of that app: "let the owner of some per-user data let named people at it" will recur in any per-user app on the platform. So it lives in enlace_auth, beside grants, and that app is its first consumer.

## Decision

### 1. A share is (app, owner, grantee), read-write or read-only

A **share** says: in app `app_id`, `grantee` may act on `owner`'s per-user data. Stored like grants — a thin adapter (`ShareStore`, `auth/shares.py`) over a `MutableMapping` from the platform store factory, key `"{app_id}/{owner}/{grantee}"`, value:

```json
{"app_id": "practice", "owner": "kid@example.com", "grantee": "parent@example.com",
 "access": "rw", "label": "Kid", "granted_at": 1790870000.0, "granted_by": "admin@example.com",
 "expires_at": null}
```

- `access`: `"rw"` (default) or `"ro"` (GET only). One field now, so a read-only grantee — a teacher, say — never needs a format change.
- `label`: how the **grantee** sees this space ("Kid"). Optional; an app falls back to the owner's email.
- Emails are normalised (lowercased, shape-checked) with the same rules as grants. Expiry works as for grants. One record per pair: granting again replaces it.
- No re-sharing: a grantee cannot grant onward, because the owner side of a share is always the signed-in user (or an admin acting explicitly).

### 2. A share names an existing account, and dies with it

Password registration does not prove ownership of an address, and a deleted account frees its email for re-registration. So:

- **A share may only name accounts that exist** — owner and grantee alike. Otherwise `409` (HTTP) or a refusal (CLI). There are no pending shares.
- **Deleting an account removes every share it is part of**, both ways, in the same operation (`delete_user`). A share never outlives the account it names.

### 3. Who manages shares

- **The owner**, signed in: `GET /auth/shares/{app_id}` → `{"owner": me, "granted": [...with "active"], "received": [active shares to me]}`; `PUT /auth/shares/{app_id}/{grantee}` (body `{"access"?, "label"?, "expires_at"?}`); `DELETE /auth/shares/{app_id}/{grantee}`. A grantee can leave: `DELETE /auth/shares/{app_id}/received/{owner}` (registered before the `{grantee}` route). CSRF-protected like every state-changing `/auth/*` route.
- **An admin**, through the existing admin API beside grants (`GET/POST /_admin/api/shares`, `DELETE /_admin/api/shares/{app_id}/{owner}/{grantee}`), and the CLI (`enlace-auth share`, `list-shares`, `revoke-share`). This is the path for an owner who is a child: the parent who runs the platform manages her shares without her password or an ssh session.
- Every route refuses an `app_id` that has no per-user store (see §4), and runs `owner`/`grantee` through both email normalisation and `sanitize_key`; expiry is parsed by the grants module's `parse_expires_at`.

### 4. How the per-user store honours it

- **`?owner=<email>`** on `/api/{app_id}/store/...` selects whose prefix to use. Absent, or equal (after normalisation) to the signed-in user: their own, as today. Different: allowed only with an active share `(app_id, owner, user)`, and only for GET when the share is `"ro"`; otherwise **404** — a stranger probing for owners learns nothing. A client must read 404 under `?owner=` as "no access (any more)", not as "empty".
- **A list route**, `GET /api/{app_id}/store?prefix=<p>` → `{"items": {key: {"value": v, "etag": e}}}`. It lists by walking only the owner's directory under `p` (a `keys_under` fast path on the file backend), never the whole platform store; capped at `max_items` (default 5000) with `"truncated": true` past it.
- **Conditional writes.** Every GET returns an `ETag` (a hash of the stored value; also in the list route's items). `PUT` and `DELETE` accept `If-Match: <etag>` (or `If-None-Match: *` for create-only) and answer **412** with the current value and etag when it no longer matches. Two devices, or two people, writing the same key can then resolve instead of overwriting: the store stays generic, and the app decides what "resolve" means (the first consumer: the newer record by its own revision stamp wins).
- **CSRF on writes.** The store routes are under `/api/`, which the platform's CSRF middleware exempts. For an app with a per-user store, the store router itself requires the double-submit header (`X-CSRF-Token` matching the `enlace_csrf` cookie, the same check `/auth/*` uses) on every `PUT` and `DELETE`. Shares raise the stakes — a grantee's cookie now reaches someone else's data — so cookie SameSite alone is not enough on an origin that hosts many apps.
- **Which apps get a store**: `access = "protected:user"` apps, as today, plus any app whose `app.toml` sets `user_store = true` (`AppConfig` is `extra="allow"`). That lets a **public** app offer a store to visitors who happen to be signed in; anonymous requests get 401 and the app does what it did before. A `user_store` app is **not** added to the `protected:user` set the grants admin uses.

### 5. Where it sits

`ShareStore` is built in `plugin.py` beside `GrantStore`, from `platform_factory("shares")`, so shares live under the platform store root (outside the deploy target, surviving redeploys, backed up with it). The store router receives a `share_access(app_id, owner, user) -> "rw" | "ro" | None` callable, not the store.

## Seams

| # | Seam | v1 default | Replacement you can point at |
|---|---|---|---|
| 1 | where shares live | `platform_factory("shares")` (JSON files, as grants) | any `MutableMapping` — the factory's existing dol variant (`stores/backends.py`) |
| 2 | how the store router decides | `share_access` built from `ShareStore` | an app-specific policy (e.g. a guardian relation) — same signature |

NOT seams: groups of grantees, re-sharing, per-key scopes, a `can_manage` delegate flag (the admin path covers the child-owner case), aliases (a short name for the email), a web UI for shares beyond the admin API. Each is "no" on purpose; none has a consumer.

Surfaces: HTTP (owner routes, admin API, store), CLI (admin). MCP or a frontend would call `ShareStore`'s methods; neither needs the core to change.

## Consequences

- Per-user data stops being strictly private to its owner. A request with `?owner=` costs one share lookup (one small file read); without it the hot path is unchanged.
- A public app that enables `user_store` must treat 401 as "no account mode" and 404 under `?owner=` as "access gone".
- Store writes from a browser now need the CSRF header; existing `protected:user` apps that write to the store from a page must send it (none on the first deployment does today: the store is off there).
- The per-user store is still off on a platform without `[stores.user_data]`; enabling it is a platform decision.

## Alternatives rejected

- **Extend admin grants with an owner field.** Grants answer "may open the app" and are admin-made; folding owner-made, data-scoped permissions into them would make every grant check reason about two different things.
- **Share the owner's password, or a shared-password app.** No per-person revocation, and a child's password in three heads.
- **A capability link.** Good for a read-only view (the first consumer already has one), but the parents need write access from several devices, signed in as themselves, revocable per person.
- **Impersonation / "acting as".** Broader than needed: the grantee would become the owner everywhere.

## Review (2026-10-01) and what was done

An adversarial review of the first draft found: shares to unregistered or deleted emails could be claimed by whoever registers the address next (→ §2); unconditional writes would quietly undo a consumer's merge rule (→ conditional writes, §4); a list over the file backend walked the whole platform store (→ `keys_under`, cap); `/api/` is CSRF-exempt (→ router-level check, §4); share routes lacked input gates (→ §3); a child owner cannot manage her own shares (→ admin API, §3); all-or-nothing access would force a format change for the first read-only grantee (→ `access`); the grantee-facing label was conflated with an owner note (→ `label`); and `user_store` apps must not join the grants admin's `protected:user` set (→ §4).
