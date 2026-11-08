# Self-service sign-up for the enlace platform: synthesis and recommendation

*2026-11-08 · scope: sign-up and sign-in methods, abuse protection, email, recovery, minors and consent (EU and France), build vs buy, placement in the enlace packages · requested for: adding self-service sign-up and sign-in to enlace, ahead of three first consumer apps (a children's maths-practice app, a judo learning game, a gesture music instrument). Not legal advice: items marked **[lawyer]** need a lawyer's confirmation.*

## Summary and recommendation

1. **Build it in `enlace_auth`, not in core enlace and not in a new package.** Sign-up writes the same user store, opens sessions through `open_session`, normalises addresses through `emails.py`, revokes through `on_credentials_changed`, and sits behind the same CSRF and gate. A separate package would import most of those internals and split the security boundary in two. Core enlace stays auth-agnostic. One part is independently reusable and is written so it can leave: the rate limiter, a host-free module whose candidate home is enlace_metering's rolling-window policy [15].
2. **v1 sign-up method: a six-digit email code, with the same code also sent as a link, and verify-before-create.** A single "Continue with email" field serves both sign-up and sign-in. The response is always "check your email", and the user record is written only after the code verifies. That closes the account-enumeration and pre-hijacking gaps in today's `/auth/register` [1][6][8], needs no new dependency (the HMAC signing and the SMTP sender are already there), and works on any device. Google sign-in stays as it is.
3. **v1.1: passkeys as the upgrade, not the gate.** After the first verified sign-in, offer to create a passkey, with autofill on the email field. Use py_webauthn (BSD-3) [11], with the apex domain as the RP ID, so that one passkey covers every app. Passwords stay optional and follow NIST SP 800-63B-4: at least 15 characters as a sole factor, no composition rules, and a breached-password check [7].
4. **Sign-up policy is per app, and access stays where it is.** Each app sets `closed | allowlist | invite | open`, while the account is platform-wide. "May create an account here" is the new policy. "May open this app" stays the single `is_user_allowed` predicate.
5. **Around an open sign-up: rate limits, a cheap bot check and a deliverable sender.** Rate-limit every endpoint that sends mail, per IP, per target address and globally. Add a honeypot and a signed time-to-submit token. Keep a self-hosted proof-of-work challenge (ALTCHA, MIT) [12] behind a seam, and avoid reCAPTCHA, which the CNIL says needs consent [2]. Send from an EU provider over the existing SMTP seam, with SPF, DKIM and DMARC set [2].
6. **Minors: no one under 15 signs up alone, and children are never account holders with an email.** Open self-sign-up is for people aged 15 and over. A child's account is a pseudonymous profile under an adult: a parent, a teacher's class or a club. The core service rests on a contract with that adult, not on consent, so GDPR Art. 8 and the French LIL art. 45 apply only to optional extras [3][9][10]. Managed profiles are v2. The children's app must not open its sign-up before v2 ships, together with a privacy notice and a short DPIA [3].
7. **Buying is already possible and costs no code.** enlace_auth already consumes any OIDC provider. If the in-house path ever proves too heavy, Hanko Cloud (Frankfurt) or a self-hosted Rauthy plug in as a provider [4]. Keycloak, Authentik, ZITADEL and Ory Kratos each need a database server this platform does not run [4][5].

## What already exists (in-house)

- **In code** (enlace_auth `main`, 0.1.52):
  - `POST /auth/register` creates email and password accounts with no proof of address. It is closed by default, opened by `registration_open` or an env allowlist, and refuses admin addresses.
  - OAuth first sign-in creates an account only for a provider-verified email, and never takes over a password account.
  - SMTP sender with a console fallback, password reset, an admin dashboard (create, disable, delete accounts) and owner-granted data shares [14].
- **Missing:** email verification, codes or magic links, passkeys, invitations, rate limiting, bot checks, self-service account deletion, and anything about minors.
- **Earlier research:**
  - The enlace repository's auth cross-cutting study, which compares self-hosted IdPs [5].
  - The enlace phase 2–3 plan, which deferred "a real signup flow (email verification, password reset)".
  - A French legal-posture ADR for a parent-built school tool (private repository), whose findings are verified and extended in [3].
- **Adjacent open work:**
  - [enlace_auth#78](https://github.com/i2mint/enlace_auth/issues/78): the CSRF cookie has no `Secure` flag. Land it first, so that the new endpoints inherit the fix [17].
  - [enlace_auth#80](https://github.com/i2mint/enlace_auth/issues/80): share links. Its token-and-redemption mechanism should be the same one that invitations use [16].
  - [enlace_metering#9](https://github.com/i2mint/enlace_metering/issues/9): a rolling-window limiter [15].
  - [enlace#108](https://github.com/i2mint/enlace/issues/108): a request-body limit [18].
- **Theme reports** behind this synthesis, in `general/`: methods [1], abuse, email and recovery [2], minors and consent [3], build vs buy [4].

## Findings in the current code (security-relevant)

- `/auth/register` answers 409 for an existing address, so anyone can test whether an address has an account [1][8].
- It creates an account for an address nobody has proven. With `registration_open`, an attacker can squat a victim's address. The victim's later Google sign-in is refused (correctly: OAuth never takes over a password account), so the victim is locked out until they run a password reset. The reset itself is safe, because it ends sessions [1][6].
- The minimum password length is 8, which NIST allows only inside multi-factor. A sole factor needs 15. There is no breached-password check [7].
- There is no rate limit on any endpoint that sends mail. Today these are only password reset; open sign-up would add more [2].
- None of these is exploitable on the live deployment while registration stays closed (the default). All of them become live the day an app opens sign-up, which is why v1 replaces the unverified flow rather than adding a second one beside it.

## Where it goes: core enlace vs enlace_auth vs a new package

| Option | For | Against | Verdict |
|---|---|---|---|
| Core enlace | One place for everything | enlace is deliberately auth-agnostic (auth plugs in through `build_backend(config, plugins=[...])`), and sign-up is pure auth | **No** |
| enlace_auth | Same user store, sessions, CSRF, address normal form, revocation hook, pages, doctor; one security boundary to review | The package grows by one more subpackage | **Yes**: `enlace_auth/signup/` |
| New `enlace-signup` package | Separate release cadence | Would import `open_session`, `AccountRecords`, `emails`, `revocation`, the CSRF mint and the page shell; two packages to keep in step on every security fix | **No** |
| Extract only the rate limiter | Reusable outside auth (metering, any public endpoint) | Its second consumer is still only an issue | **A host-free module now** (`enlace_auth/ratelimit.py`, imports nothing from enlace_auth); move it to enlace_metering when #9 lands |

## The seam table

| # | Seam | v1 default (no new dependency) | Replacement you can point at |
|---|---|---|---|
| 1 | `signup_policy`: may this address create an account from this app | per-app value from config: `closed / allowlist / invite / open` | a custom predicate per app: a club roster, a school's class list (the club and class consumers below) |
| 2 | `rate_limiter`: may this IP, address or global key send one more mail | in-process sliding window over a `MutableMapping` (dict or file store) | enlace_metering's rolling-window policy [15] |
| 3 | `bot_check`: is this submission from a person | honeypot field plus a signed time-to-submit token | ALTCHA (MIT, self-hosted) or Cloudflare Turnstile [2][12] |
| 4 | `send_email` (exists) | the SMTP sender, with the console fallback in development | any EU provider over SMTP: configuration only, no code [2] |
| 5 | external IdP (exists) | Google and GitHub presets, generic OIDC | Hanko Cloud or Rauthy as a generic OIDC provider [4] |

Surface for v1: HTTP plus the server-rendered `/auth` pages, since this is a web platform and so the build order is inverted. Alongside them come a CLI (`enlace-auth signup-policy`, `enlace-auth invite`), doctor checks, and an update to the consumer skill `enlace-auth-usage`. MCP is not built: no agent signs people up. A JS client is not built either, because apps link to `/auth/login?next=...` (see #76 for the store client).

NOT seams: code length (6 digits), code lifetime (10 minutes), attempt cap (5), link-landing page, email templates (French and English, written directly). These are config values or plain code, on purpose.

v1 is done when: a TestClient run of `POST /auth/email/start` takes the code from the captured sender and posts it to `POST /auth/email/verify`, after which `GET /auth/whoami` returns the address. No user record exists before the verify step. The start response is byte-identical for a known address, an unknown one and a refused one.

## v1 scope (one PR, adversarially reviewed)

- **`POST /auth/email/start {email, app?, next?}`**: an always-uniform 202.
  - If the rate limits and bot check pass, it sends one mail. For an existing account, or a new address the app's policy admits, the mail carries the code and the link. For an address the policy refuses, it is a short "sign-up here is by invitation" notice, which is still rate-limited.
  - Pending codes are kept hashed in a TTL mapping: `{code_hash, expires, attempts, app, next}`.
- **`POST /auth/email/verify {email, code}`**: signs in an existing account, or creates the account (`created_via: "email-code"`, `email_verified_at`, `terms_version`) and then signs in. The pending code is spent on success and dies after 5 failures.
- **`GET /auth/email/link?t=...`**: a page with one button that POSTs. A GET never spends the token, so mail scanners cannot burn it [1].
- **Per-app `signup` policy** under `[auth.signup]`, with a platform default plus per-app overrides. `registration_open` and the allowlist env keep working as aliases (expand, migrate, contract).
- **`/auth/register`** becomes verify-first, or is retired in favour of the email flow; see decision D3. Admin addresses still never self-register.
- **Self-service deletion, `POST /auth/account/delete`**: re-authenticates by code, reuses the admin deletion path and `on_credentials_changed`, and cascades to shares and grants. GDPR Art. 17 owes it, and the App Store requires it of any iOS app that creates accounts [1][13].
- **Legal hooks:**
  - `privacy_url` and `terms_url` are shown on the sign-up step, and the accepted `terms_version` is stored on the account (the contract basis).
  - An open policy shows "for people aged 15 and over".
  - Doctor fails an open policy with no real sender, and warns on one with no `privacy_url`.
- **Abuse:** seams 2 and 3 with their defaults, per-IP, per-address and global limits on start, resend and reset, and a client IP taken only from a trusted proxy hop [2].
- **Pages:** the `/auth/login` page gets a "Continue with email" field, plus the Google button when configured, in French and English.

**Next, each as its own PR:**
- v1.1: passkeys (registration offered after sign-in, conditional UI, a second passkey or recovery codes for recovery) [1][11].
- v1.2: invitations, unified with the #80 share-link token.
- v2: managed profiles for minors (below).
- Sign in with Apple when an iOS app ships, but only if that app offers Google [13].

## Rules for minors, as the platform will encode them

These are drawn from [3], where each has its primary source.

1. Open self-sign-up states "for people aged 15 and over", and asks no age question on adult-oriented apps.
2. An app flagged as reaching children (`audience = "mixed"`) shows a neutral two-button screen ("15 or older" / "under 15"). An under-15 answer creates nothing and shows "ask a parent or your teacher".
3. A child exists only as a profile under an adult holder:
   - The holder is a parent (family), a teacher (class) or a club admin (members).
   - The profile has a pseudonym, an avatar from a fixed set and a grade band.
   - It has no email, birthdate, photo, free-text field or location.
   - The child signs in on the holder's device, or with a holder-set code or a printed QR badge.
4. The core service rests on the adult's contract (Art. 6(1)(b)). A class is the school's processing, with the platform as processor under an Art. 28 contract **[lawyer for club use]**. Consent records exist only for optional extras (public leaderboards, sharing, recordings), and are given jointly by the holder and the child under 15.
5. Deletion cascades: holder, then profiles, then progress, shares and grants. Class profiles are deleted at the end of the school year. Inactive family accounts are purged after a stated period, with a warning first.
6. Auth pages load nothing from third parties. The CSRF and session cookies are exempt under LIL art. 82 because they are strictly necessary.
7. Before a children's app opens sign-up, these must exist:
   - mentions légales (LCEN art. 1-1 since the 2024 SREN law),
   - a privacy notice, with a version written for children,
   - CGU,
   - a short DPIA for the maths and music apps [3].

## What the first consumers need (generic; app-specific notes are kept privately)

| Consumer | Today | Needs from v1 | Needs later |
|---|---|---|---|
| Gesture music instrument (education market; may go native) | Public instruments; a gated studio app limited to admins | `invite` policy for the studio, then `open` (15+); account deletion | Passkeys (v1.1); Sign in with Apple and in-app deletion when native; class profiles (v2) for schools; camera data stays on the device |
| Judo learning game (club members, some children) | Public, progress kept in the browser | `open` (15+) with `user_store = true`, so adult learners keep progress across devices; key the learner model on the account id | Club mode (v2): a club admin invites families, children as profiles |
| Children's maths practice (10–13, parents, teachers) | Family accounts by allowlist, shares between family members | Nothing to open: stays `allowlist` | v2 profiles (family and class), legal pages and DPIA before any open sign-up; teacher class codes |

## Decisions needed

- **D1, the home:** `enlace_auth`, with the rate limiter as a host-free module. Recommended; the alternative is a new package.
- **D2, v1 methods:** the email code (plus link) and the existing Google sign-in, with passkeys as an immediate v1.1 PR. Recommended; the alternative is passkeys inside v1.
- **D3, `/auth/register`:** make it verify-before-create with uniform responses, and require 15 characters for new password-only accounts. This breaks any client that relies on the 409 or on getting a session at once; none is known, since registration is closed everywhere.
- **D4, minors:** adopt the rules above, with managed profiles in v2, not v1.
- **D5, production sender:** an EU provider (Brevo, or Amazon SES in Paris) or the SMTP already configured. Either way, an account and DNS records (SPF, DKIM, DMARC) are the owner's to set up.
- **D6, the first app to open:** recommended order is the music studio (invite), then the judo game (open, 15+), then the maths app (after v2).

## Open questions

- **[lawyer]** Whether a free, ad-free service is an "information society service", which decides whether Art. 8 and LIL art. 45 apply at all [3].
- **[lawyer]** Whether a CGU concluded by a parent is a sound Art. 6(1)(b) basis for a child's learning profile [3].
- **[lawyer]** The controller and processor split for club use [3].
- Brevo's and Scaleway's current prices and EU-only processing were not verified [2].
- Whether enlace_metering#9's design fits per-IP and per-address keys was not checked against the issue text [2].

## REFERENCES

[1] [Self-service sign-up and sign-in methods, November 2026 — enlace_auth research](general/signup-signin-methods.md)
[2] [Open sign-up: abuse protection, email deliverability, account recovery — enlace_auth research](general/signup-abuse-email-recovery.md)
[3] [Accounts held by or about minors: consent, GDPR and design rules (EU and France) — enlace_auth research](general/minors-consent-eu-france.md)
[4] [Build vs buy for self-service sign-up identity — enlace_auth research](general/identity-build-vs-buy.md)
[5] [Authentication and authorization as cross-cutting concerns — enlace repository](https://github.com/i2mint/enlace/blob/main/misc/docs/auth_cross_cutting__Authentication_and_Authorization_as_Cross_Cutting_Concerns.md)
[6] [Sudhodanan A, Paverd A. Pre-hijacked accounts: an empirical study of security failures in user account creation on the web. USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/sudhodanan)
[7] [NIST SP 800-63B-4, Digital Identity Guidelines: Authentication and Authenticator Management (2025)](https://pages.nist.gov/800-63-4/sp800-63b.html)
[8] [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
[9] [CNIL, Recommandation 4 : rechercher le consentement d'un parent pour les mineurs de moins de 15 ans (2021)](https://www.cnil.fr/fr/recommandation-4-rechercher-le-consentement-dun-parent-pour-les-mineurs-de-moins-de-15-ans)
[10] [EDPB, Guidelines 05/2020 on consent under Regulation 2016/679](https://www.edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-052020-consent-under-regulation-2016679_en)
[11] [duo-labs/py_webauthn](https://github.com/duo-labs/py_webauthn)
[12] [ALTCHA, open-source proof-of-work captcha](https://altcha.org/open-source-captcha/)
[13] [Apple, App Store Review Guidelines (4.8, 5.1.1(v))](https://developer.apple.com/app-store/review/guidelines/)
[14] [ADR 0001: owner-granted data shares — enlace_auth](../decisions/0001-owner-granted-data-shares.md)
[15] [i2mint/enlace_metering#9, rolling-window call-count policy](https://github.com/i2mint/enlace_metering/issues/9)
[16] [i2mint/enlace_auth#80, item-scoped shares and share links](https://github.com/i2mint/enlace_auth/issues/80)
[17] [i2mint/enlace_auth#78, CSRF cookie without Secure](https://github.com/i2mint/enlace_auth/issues/78)
[18] [i2mint/enlace#108, request-body limit](https://github.com/i2mint/enlace/issues/108)
