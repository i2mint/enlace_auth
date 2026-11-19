---
name: enlace-auth-usage
description: >-
  How to add sign-in, sessions, CSRF protection, admin accounts, per-app access
  levels, runtime grants and per-user storage to an enlace multi-app platform
  with the enlace_auth plugin. Use when the user mentions enlace_auth, the
  enlace-auth CLI, protected:user or protected:shared apps, ENLACE_SIGNING_KEY,
  ENLACE_ADMIN_EMAILS, X-CSRF-Token or /auth/csrf, request.state.store, add-user,
  reset-link, grant, share, invite, [auth.signup], sign-up, "continue with
  email" or account deletion, passkeys, WebAuthn, Face ID or Touch ID sign-in,
  a step-up confirmation or step-up proof; or wants to put login, self-service
  sign-up, or a "confirm this action with your passkey" tap in front of apps
  served by enlace.
metadata:
  audience: users
---

# Using enlace_auth

`enlace_auth` is an enlace plugin. Install it next to enlace, give the platform a signing key, mark apps with an access level, and every request is gated.

## 1. Wire it in

```python
from enlace import PlatformConfig, build_backend
from enlace_auth import plugin as auth_plugin

config = PlatformConfig.from_toml("platform.toml")
app = build_backend(config, plugins=[auth_plugin])
```

With `uvicorn --factory enlace.compose:create_app`, set `ENLACE_PLUGINS=enlace_auth:plugin` instead. The plugin does nothing unless `[auth] enabled = true`.

## 2. Configure

`python -m enlace_auth init` prints a starter `[auth]` block. `python -m enlace_auth generate-signing-key` prints a value for `ENLACE_SIGNING_KEY` (32+ characters; the platform refuses to start without one, and `ENLACE_ALLOW_UNSIGNED=1` boots it with authentication disabled, for diagnostics only). `ENLACE_ADMIN_EMAILS` (comma separated) names who may open `/_admin`.

An app declares `access` in its `app.toml`: `public`, `protected:shared` (one shared password, `shared_password_env` holds its argon2 hash from `python -m enlace_auth hash-password`) or `protected:user` (a signed-in account, optionally narrowed by `allowed_users`). **An app with no `access` is `local`, which the gate treats as open to everyone.** Always write `access` explicitly. A request path that matches no app falls under the platform's public root rule, and an unrecognized `access` value is denied.

## 3. Accounts and access from the CLI

All commands take `--toml platform.toml`.

| Task | Command |
|---|---|
| Create an account (the only way to make an admin) | `enlace-auth add-user EMAIL` |
| Give someone a one-time password link | `enlace-auth reset-link EMAIL` |
| Grant an app to a user at runtime | `enlace-auth grant APP EMAIL --expires 2026-12-31` |
| Share one user's data in an app | `enlace-auth share APP OWNER GRANTEE --access ro` |
| Invite an address to sign up | `enlace-auth invite EMAIL --apps APP` (`uninvite`, `list-invites`) |
| See who may sign up where | `enlace-auth signup-policy` |
| List what exists | `list-users`, `list-sessions`, `list-grants`, `list-shares` |

## 3b. Self-service sign-up

Off by default. `[auth.signup]` sets a policy per app: `default = "closed"` plus `apps = { game = "open", studio = "invite" }`; the modes are `closed`, `allowlist` (`allowlist = [...]` or `ENLACE_REGISTRATION_ALLOWLIST`), `invite` (`enlace-auth invite`) and `open` (shown as "for people aged 15 and over"). `registration_open = true` is the old spelling of `default = "open"`. An admin address can never self-register.

- The sign-in page offers "Continue with email" when `ENLACE_SMTP_HOST` is set: a 6-digit code is mailed, and the account is created only when it checks out. From an app, link to `/auth/login?next=/<app>/`; the app's policy is taken from `next`.
- A non-browser client calls `GET /auth/email/challenge`, waits `min_seconds`, then `POST /auth/email/start {email, app, next, challenge}` (always the same 202, or 429), then `POST /auth/email/verify {email, code}`.
- **The account is platform-wide, and access is unchanged: a `protected:user` app with no `allowed_users` opens to every account.** Give it `allowed_users = ["@admins"]` (or a list) before opening sign-up anywhere; `enlace doctor` fails until you do.
- Set `privacy_url`, `terms_url` and `terms_version`. Signed-in users delete their own account from `/auth/account`, confirmed by a mailed code. Children under 15 must not sign up themselves; managed profiles held by an adult are planned (i2mint/enlace_auth#81).

## 3c. Passkeys, and confirming an action with one (step-up)

Off by default: set `[auth.passkeys] enabled = true` (py_webauthn comes with enlace_auth). The relying party is the platform's public origin (the OAuth issuer, else `https://{domain}`); set `rp_id = "example.com"` to let one passkey cover sibling hosts, and `origins = [...]` to accept more than one. Changing `rp_id` later orphans every passkey already made (they stop counting toward the policy too).

- **Add and remove** from `/auth/account` (any signed-in account, several per account, each named). Both need a sign-in from the last 15 minutes (`fresh_seconds`), and once the account has a passkey, a sign-in **with a passkey**: a password holder cannot plant one. Each change is mailed to the account, and a removal ends its other sessions and connector sessions. To enrol two devices that do not share a keychain, enrol the phone first, then on the computer sign in with the phone's passkey (the browser shows a QR code) and add the computer's. Recovery for a lost device: `enlace-auth list-passkeys EMAIL`, `enlace-auth remove-passkey EMAIL --passkey-id ID` (or `--all`).
- **Sign in** with the "Sign in with a passkey" button or the email field's autofill on `/auth/login`. The email code and password stay as the way back in.
- **Require it** for some accounts: `required = ["@admins", "@family", "a@x.io"]`. The rule applies once an account has `enforce_from` passkeys (default 2) or one synced passkey (iCloud Keychain, Google Password Manager), so one lost device never locks an account out. From then on every other sign-in method, and the password reset, answers 403 for it, and the sessions it opened by password end. Below the threshold, or while passkey sign-in is not mounted (a configuration error, logged), the account keeps its other methods. A required account cannot remove a passkey from the page while that would take it back to its threshold.

**Step-up: a backend asks the account holder to confirm one action in person.** The proof is single-use, lives 120 seconds (`step_up_ttl_seconds`), and names the account and the exact action text it was signed for.

1. On a page of a signed-in user (any app on the platform), show the action and **prepare the request before the tap** (Safari only opens the passkey prompt straight from a tap):

   ```html
   <script src="/auth/passkeys/passkeys.js"></script>
   <script type="module">
     const action = "equerry: start job 42 on owner/repo, 'title'";  // shown on the page
     const prepared = await enlacePasskeys.prepareStepUp(action);
     confirmButton.onclick = async () => {
       const {proof} = await enlacePasskeys.stepUp(prepared);     // Face ID / Touch ID
       await fetch("/api/myapp/jobs/42/confirm", {method: "POST", body: JSON.stringify({proof})});
     };
   </script>
   ```

   A prepared request is good for four minutes (prepare again on focus). `prepareStepUp` rejects with `err.status === 409` when the account has no passkey yet (send the user to `/auth/account`); `stepUp` rejects with `err.name === "NotAllowedError"` when the user cancels.
2. The backend, before acting, redeems it. No cookie and no CSRF token are needed. Name the action you are about to perform AND the account that must have confirmed it; the server compares both:

   ```python
   r = httpx.post(
       f"{PLATFORM}/auth/passkeys/step-up/redeem",
       json={"proof": proof, "action": action, "email": owner_email},
   )
   confirmed = r.status_code == 200
   # 200 -> {"ok": true, "email", "action", "verified_at", "method": "passkey", "passkey"}
   ```

   A proof for another action or another account, a second redemption, an expired proof, or one whose passkey was removed answers 400; a disabled account 403; a missing field 422. Build the action text on the backend from the job itself (never from what the browser sends back) and prefix it with your app's name, since every app on the platform shares the origin.

Raw endpoints, for a client without the helper: `POST /auth/passkeys/step-up/options {action}` returns WebAuthn request options (base64url JSON, user verification required); `POST /auth/passkeys/step-up/verify {action, credential}` takes the `PublicKeyCredential` as JSON and returns `{proof, action, expires_in}`. Both need the session cookie and the CSRF pair.

## 4. Calling the HTTP API correctly

Every POST, PUT, PATCH and DELETE needs the CSRF pair, except the OAuth callback and consent routes (`/auth/callback`, `/auth/login/<provider>`, `/auth/oauth/`), the step-up redeem (`/auth/passkeys/step-up/redeem`), sub-app APIs under `/api/` (but not `/api/{app}/store`), and proxied `process`/`external` apps. That covers `/auth`, `/_admin`, `/_apps/{name}/meta` and the per-user store. Fetch the token first, then echo it in a header:

```python
token = client.get("/auth/csrf").json()["csrf"]
client.post(
    "/auth/login", json={"email": e, "password": p}, headers={"X-CSRF-Token": token}
)
```

The cookie is set only by `/auth/*`, `/_admin` and `protected:*` apps. Public pages set no cookie, so a public page that must POST has to call `/auth/csrf` itself. Sub-app APIs under `/api/` are exempt because the session cookie is `SameSite=Lax`.

## 5. Inside an app

For `protected:user` apps (and public apps with `user_store = true`), read `request.state.user_id`, `request.state.user_email` and `request.state.store`, a `MutableMapping` scoped to that user and app. Never trust an `X-User-ID`-style header: the middleware strips them.

## Gotchas

- Changing a password, deleting a user or rotating a shared password ends the affected sessions (and connector refresh tokens). That is intended.
- `enlace doctor` runs this package's checks (signing key, admin accounts, OAuth refresh, sign-up policy) when enlace is new enough to discover plugin checks.
- To test an app behind the plugin, build a platform in a temp directory and use Starlette's `TestClient`; `README.md` has a complete runnable example.
