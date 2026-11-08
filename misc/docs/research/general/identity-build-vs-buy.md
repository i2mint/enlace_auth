# Build vs buy for self-service sign-up and sign-in identity (enlace_auth)

Date of research: 2026-11-08. Scope: a single-VPS, file-backed, one-developer platform with users mostly in France, tens to low thousands of users, no database server. Prices are those shown on the vendor pages on that date, in USD, and change often. Where a page did not show a fact, the report says "not verified" instead of guessing. Items labelled "estimate" are the author's reasoning, not sourced.

## Summary and recommendation

- Keep authorization, sessions, CSRF, grants, shares and the admin dashboard in enlace_auth. That is the part no IdP replaces, and enlace_auth already consumes any OIDC provider through its generic `server_metadata_url` config, so the "buy" seam exists today and costs no code.
- For self-service sign-up at this scale, the best default is to extend enlace_auth in-house with the low-risk, high-value pieces: email-verified registration, email one-time code or magic link sign-in, and optionally passkeys via py_webauthn. Ghost and similar products show that email-code sign-in is enough for most member audiences [1][2].
- Do not run Keycloak, Authentik, ZITADEL or Ory Kratos for this: each needs a real database server and a resident service, which breaks the "no database server" constraint and adds a second security-critical system to patch [3][4][5][6][7].
- If an external IdP is wanted, the best fits are: Hanko Cloud (hosted only in Frankfurt, 10,000 MAU free, passkeys on every tier) [8], or self-hosted Rauthy (Apache-2.0, embedded database, about 40 MB RAM idle, optional open registration restricted by email domain) [9]. Hanko's open-source licence was not named on its pricing page; its "non-AGPL commercial licence" wording implies AGPL, not verified.
- Avoid for an EU-first service: Clerk (no EU residency, US sub-processors, Data Privacy Framework transfer) [10], Auth0 above the free tier (price jumps to $70 at 1k and $700 at 10k MAU on B2C Essentials) [11], and Ory Network (EU storage only on paid plans from $770/year) [12]. fastapi-users is in maintenance mode: do not build on it [13].
- Children: France sets the digital age of consent at 15; below it, consent must come from the minor and a parent [14]. No vendor surveyed advertises a parental-consent flow, so this stays an application-level duty under every option (not verified per vendor).

## 1. Hosted providers

Free tier is monthly active users (MAU) unless noted. "1k / 10k" is the monthly bill at that user count for the cheapest plan that keeps the feature set (passkeys, social). Sources in brackets.

| Provider | Free tier | 1k / 10k MAU | Passkeys, social, orgs | EU residency | Verdict |
|---|---|---|---|---|---|
| Auth0 | 25,000 MAU, 5 orgs [11] | Free / Free on Free plan; B2C Essentials $70 / $700 [11] | Passkeys all plans, unlimited social [11] | Public EU tenants in Frankfurt with Dublin failover per community answers, with exceptions such as dashboard and support (secondary source) [15] | Free tier is generous; the cliff is steep. Acceptable as a free OIDC provider while under 25k |
| Clerk | 50,000 monthly retained users (MRU) on Hobby; passkeys not on Hobby [16] | Free / Free on Hobby; Pro $25/month for passkeys [16] | Orgs 100 free [16] | None: Clerk states no region selection, US infrastructure, DPF transfers [10] | Avoid for EU-first |
| WorkOS AuthKit | 1,000,000 MAU free [17] | Free / Free | Not shown on page | Not verified | Aimed at B2B SSO; free tier is huge but fits enterprise buyers, not this need |
| Stytch | 10,000 MAU [18] | Free / Free | Not shown on page | Not verified | Acquired by Twilio, announced 2025-10-30 [19]; roadmap now B2B and AI agents. Avoid as a long-term dependency |
| Supabase Auth | 50,000 MAU free; Pro $25 includes 100,000, overage $0.00325 [20] | Free / Free | Not shown on page | Region list not on page (not verified) | Only sensible if Supabase is used anyway |
| Firebase / Identity Platform | 50,000 MAU, then $0.0055 per MAU in the first tier up to 100,000 [21] (secondary source) | Free / Free | SMS is billed separately [21] | Not verified | US vendor, no EU guarantee verified; SMS cost trap |
| AWS Cognito | 10,000 MAU on Lite and Essentials; Essentials $0.015 per MAU after [22] | Free / Free | Passkeys on Essentials and Plus, not Lite [22] | Available AWS regions (Paris etc.) not verified on page | Workable but heavy to configure and awkward hosted UI |
| Kinde | 10,500 MAU; Pro $25 base [23] | Free / Free | Not shown | "Choice of data residency" on all plans; EU not named [23] | Reasonable, residency unconfirmed |
| Hanko Cloud | 10,000 MAU, 2 projects; Pro $29/month then $0.01 per MAU above 10,000 [8] | Free / Free | Passkeys on every tier [8] | Frankfurt only [8] | Best hosted fit for the stated profile |
| Ory Network | Developer tier free but 0 production environments and no EU storage [12] | Production $770/year plus $0.14 per average daily active user, $21/month credit included [12] | Passkeys in Kratos [7] | EU storage on Production and above [12] | Too costly for free service |
| Descope | 7,500 MAU free; Pro from $249/month billed annually [24] | Free / Pro $249 | Passkeys on all plans [24] | Multi-region listed, EU not named [24] | Avoid at 10k |
| Frontegg | 7,500 MAU pay-as-you-go at $0 [25] | Free / enterprise quote | Not shown | Not verified | Enterprise-oriented, avoid |

Lock-in, children's features and SDKs: I did not find vendor pages that confirm password-hash export for Auth0, Clerk, Cognito or Kinde within this research, and none of the vendor pages fetched advertised parental-consent features. Treat hash export as something to negotiate or test before adoption, not assume. Python SDK quality was not assessed from primary sources. Because enlace_auth uses the Authlib generic OIDC client, no vendor SDK is needed, which also limits lock-in to the user records stored at the vendor.

## 2. Self-hosted identity providers

| IdP | Licence | Database and weight | Self-registration, passkeys, email login | Verdict |
|---|---|---|---|---|
| Rauthy | Apache-2.0 [9] | Embedded Hiqlite, Postgres optional; about 40 MB idle [9] | Optional open registration, can be limited to email domains; passkeys, including passkey-only accounts [9] | Best self-hosted fit; young project, so check release cadence before depending on it |
| Pocket ID | BSD-2-Clause [26] | Not stated on the page; the earlier study gives SQLite [27] | Passkey-only; sign-up not mentioned on the page [26] | Good for invite-only. Passkey-only is a user-experience risk for a public sign-up |
| Kanidm | MPL-2.0 [28] | Own embedded database [28] | Self-registration not mentioned [28]; passkeys yes | Aimed at organisations, not public sign-up |
| Authelia | Apache-2.0 [29] | File or LDAP users | OIDC user registration listed as unsupported [30] | Gatekeeper, not an identity creator. Avoid for sign-up |
| Logto | MPL-2.0 [31] | Requires PostgreSQL [31] | Sign-up, social, passwordless tags, Python SDK [31] | Capable; the Postgres dependency conflicts with the constraint |
| Ory Kratos | Apache-2.0 [7] | PostgreSQL, MySQL, CockroachDB; SQLite not mentioned on page [7] | Self-service registration, passkeys, magic link [7] | Best engineered, but headless: you build the UI. Needs Postgres |
| ZITADEL | AGPL-3.0 for core, console and hosted login since 2025-03-13; SDKs and APIs stay Apache-2.0 [5][32] | Needs a SQL database (not re-verified here) | Full | Licence flipped from Apache-2.0 to AGPL in 2025 (verified). AGPL is acceptable for internal use but the service weight is excessive |
| Authentik | Not re-verified | PostgreSQL only since 2025.10, Redis removed [4]; one secondary source cites 2 CPU cores and 2 GB RAM minimum [4] | Flows allow enrolment | Too heavy |
| Keycloak | Not re-verified (known Apache-2.0, unverified) | About 1250 MB RAM per pod baseline [6] | Registration supported | Too heavy |
| SuperTokens | Core Apache-2.0, `ee/` directory separately licensed [33] | Database not stated on the page; a PostgreSQL image is listed [33] | Python SDK exists (not tested here) | The core is a separate Java service plus a database: avoid |
| Hanko | Not named on the page | Needs a database (not verified) | Passkey-first | See hosted row |

Operational note: every one of these except Rauthy, Pocket ID and Kanidm is a second always-on service with its own database to back up and patch. On a one-VPS, one-developer setup that is the dominant cost, not the licence.

## 3. Python libraries to build in-house

| Library | Status | Verdict |
|---|---|---|
| Authlib | 1.6.11 released 2026-04-16, active security fixes [34] | Depend (already used) |
| py_webauthn | BSD-3-Clause, Python 3.10+, server-side registration and authentication helpers, active repository [35] | Depend, for passkeys |
| django-allauth | Headless mode for single-page and mobile apps; login-by-code, MFA and passkey flows named in its docs summary but not explained on the page I fetched [36] | Study as a design reference for flows and API shape; do not import |
| fastapi-users | README states "now in maintenance mode"; no new features, security and dependency updates only [13] | Avoid |
| AuthX | MIT, JWT-oriented, sessions only in a separate package [37] | Avoid: wrong model (JWT) for cookie sessions |
| itsdangerous | Signed tokens; not re-checked | Depend for email links, if not already used (not verified) |
| Litestar auth | Not researched | Not assessed |

## 4. Total cost of ownership and risk

| | Extend enlace_auth | Self-hosted IdP behind the OIDC seam | Hosted IdP behind the OIDC seam |
|---|---|---|---|
| Money (estimate) | $0 | $0 licence; RAM and backup effort | $0 up to 10k MAU on several vendors, then cliff |
| Security responsibility | Yours: hashing, rate limits, enumeration, account takeover | Split: IdP code patching is yours, enlace_auth still owns sessions | Vendor owns credentials; you still own sessions and authorization |
| Breach liability (GDPR) | Controller and operator, no processor | Controller and operator | Controller; vendor is a processor and needs a DPA |
| Sub-processors outside EU | None | None | Check each; Clerk's are all US [10] |
| Code to write | Largest, but incremental | Config only | Config only |
| Lock-in | None | Low | Medium, depends on hash export |

What stays in enlace_auth in every option (estimate from the architecture): the access rule per route prefix, allowlists, runtime grants, shares, the per-user store, CSRF and the admin dashboard. An IdP supplies only an identity (`sub`, email, verified flag), and enlace_auth maps it to its own account and mints its own session. Consequences: logout from enlace_auth does not log the user out of the IdP unless RP-initiated logout is wired; a disabled user at the IdP stays able to hold a live enlace_auth session until it expires or is revoked; and the email must be trusted only when the IdP says it is verified, since account linking by email is the classic takeover path, as the Discourse SSO documentation warns [38]. Credential changes must still go through `on_credentials_changed` as the project convention requires.

## 5. How comparable platforms do it

- Ghost: member sign-in is passwordless, by emailed magic link with a 24-hour life and optionally a one-time code [1][2].
- Plausible Community Edition: built-in accounts with a `DISABLE_REGISTRATION` setting taking true, false or invite_only, and invite-only as the default [39]. Whether it persists users in Postgres was not verified.
- Discourse: its own accounts; DiscourseConnect replaces local login when enabled, and trusts the email supplied, so unverified emails are a risk [38].
- Mastodon: its own accounts with registration modes, plus an optional OIDC-only mode via a config flag, documented mostly in third-party guides [40].
The pattern: own accounts with email-based passwordless login, plus an optional OIDC door for those who want an external identity.

## 6. What you did not ask about

- Abuse of open sign-up: email-sending cost and reputation, bots, disposable addresses, account enumeration, rate limits per IP and per address. Sign-up needs a throttle and a verification step before the account can use anything.
- Account recovery for passkey-only accounts, and the single point of failure that email is for code login.
- Retention and erasure: GDPR deletion must reach file-backed per-user stores and backups.
- A hosted IdP adds a Transfer Impact question (US vendors depend on the Data Privacy Framework) [10].
- Keep an exit: store the OIDC `iss` and `sub` per account so a provider can be replaced.

## REFERENCES

[1] Ghost. Members sign in. [ghost.org/help/members-sign-in](https://ghost.org/help/members-sign-in). Accessed 2026-11-08.
[2] Ghost. One-time codes for sign in. [ghost.org/changelog](https://ghost.org/changelog/one-time-codes-for-sign-in/). Accessed 2026-11-08.
[3] Authentik. We removed Redis (2025-11-13). [goauthentik.io/blog/2025-11-13-we-removed-redis](https://goauthentik.io/blog/2025-11-13-we-removed-redis/). Accessed 2026-11-08.
[4] Authentik vs Authelia 2026 comparison (secondary, memory figure). [techfuelhq.com](https://techfuelhq.com/homelab/authelia-vs-authentik-2026/). Accessed 2026-11-08.
[5] ZITADEL. Moving to AGPL 3.0 (2025-03-13). [zitadel.com/blog/apache-to-agpl](https://zitadel.com/blog/apache-to-agpl). Accessed 2026-11-08.
[6] Keycloak. Memory and CPU sizing. [keycloak.org](https://www.keycloak.org/high-availability/single-cluster/concepts-memory-and-cpu-sizing). Accessed 2026-11-08.
[7] Ory Kratos repository. [github.com/ory/kratos](https://github.com/ory/kratos). Accessed 2026-11-08.
[8] Hanko. Pricing. [hanko.io/pricing](https://www.hanko.io/pricing). Accessed 2026-11-08.
[9] Rauthy repository. [github.com/sebadob/rauthy](https://github.com/sebadob/rauthy). Accessed 2026-11-08.
[10] Clerk. Security and compliance, via search summary. [clerk.com/security](https://clerk.com/security); DPF notice [clerk.com/legal/dpf](https://clerk.com/legal/dpf). Accessed 2026-11-08.
[11] Auth0. Pricing. [auth0.com/pricing](https://auth0.com/pricing). Accessed 2026-11-08.
[12] Ory. Pricing. [ory.com/pricing](https://www.ory.com/pricing). Accessed 2026-11-08.
[13] fastapi-users repository. [github.com/fastapi-users/fastapi-users](https://github.com/fastapi-users/fastapi-users). Accessed 2026-11-08.
[14] CNIL. Recommandation 4: consentement d'un parent pour les moins de 15 ans. [cnil.fr](https://cnil.fr/fr/recommandation-4-rechercher-le-consentement-dun-parent-pour-les-mineurs-de-moins-de-15-ans). Accessed 2026-11-08.
[15] Auth0 community. Data center for EU region. [community.auth0.com](https://community.auth0.com/t/data-center-for-eu-region/150928). Secondary source, accessed 2026-11-08.
[16] Clerk. Pricing. [clerk.com/pricing](https://clerk.com/pricing). Accessed 2026-11-08.
[17] WorkOS. Pricing. [workos.com/pricing](https://workos.com/pricing). Accessed 2026-11-08.
[18] Stytch. Pricing. [stytch.com/pricing](https://stytch.com/pricing). Accessed 2026-11-08.
[19] Stytch. Stytch joins Twilio. [stytch.com/blog/stytch-joins-twilio](https://stytch.com/blog/stytch-joins-twilio/). Accessed 2026-11-08.
[20] Supabase. Pricing. [supabase.com/pricing](https://supabase.com/pricing). Accessed 2026-11-08.
[21] Firebase Authentication pricing, secondary summaries. [blog.logto.io](https://blog.logto.io/it/firebase-authentication-pricing); Google [cloud.google.com/identity-platform/pricing](https://cloud.google.com/identity-platform/pricing) (page content could not be fetched). Accessed 2026-11-08.
[22] AWS. Cognito pricing. [aws.amazon.com/cognito/pricing](https://aws.amazon.com/cognito/pricing/). Accessed 2026-11-08.
[23] Kinde. Pricing. [kinde.com/pricing](https://kinde.com/pricing/). Accessed 2026-11-08.
[24] Descope. Pricing. [descope.com/pricing](https://www.descope.com/pricing). Accessed 2026-11-08.
[25] Frontegg. Pricing. [frontegg.com/pricing](https://www.frontegg.com/pricing). Accessed 2026-11-08.
[26] Pocket ID repository. [github.com/pocket-id/pocket-id](https://github.com/pocket-id/pocket-id). Accessed 2026-11-08.
[27] Prior in-repo study of self-hosted IdPs (Pocket ID, Authelia, Logto, ZITADEL, Authentik, Keycloak): the enlace repository, `misc/docs/auth_cross_cutting__Authentication_and_Authorization_as_Cross_Cutting_Concerns.md`.
[28] Kanidm repository. [github.com/kanidm/kanidm](https://github.com/kanidm/kanidm). Accessed 2026-11-08.
[29] Authelia repository. [github.com/authelia/authelia](https://github.com/authelia/authelia/blob/master/README.md). Accessed 2026-11-08.
[30] Authelia. OpenID Connect introduction (feature support chart). [authelia.com](https://www.authelia.com/integration/openid-connect/introduction/). Accessed 2026-11-08.
[31] Logto repository. [github.com/logto-io/logto](https://github.com/logto-io/logto). Accessed 2026-11-08.
[32] ZITADEL. LICENSE (AGPL-3.0). [github.com/zitadel/zitadel](https://raw.githubusercontent.com/zitadel/zitadel/main/LICENSE). Accessed 2026-11-08.
[33] SuperTokens core repository. [github.com/supertokens/supertokens-core](https://github.com/supertokens/supertokens-core). Accessed 2026-11-08.
[34] Authlib changelog. [docs.authlib.org](https://docs.authlib.org/en/v1.6.11/changelog.html). Accessed 2026-11-08.
[35] py_webauthn repository. [github.com/duo-labs/py_webauthn](https://github.com/duo-labs/py_webauthn). Accessed 2026-11-08.
[36] django-allauth. Headless introduction. [docs.allauth.org](https://docs.allauth.org/en/latest/headless/introduction.html). Accessed 2026-11-08.
[37] AuthX repository. [github.com/yezz123/authx](https://github.com/yezz123/authx). Accessed 2026-11-08.
[38] Discourse Meta. Setup DiscourseConnect. [meta.discourse.org](https://meta.discourse.org/t/setup-discourseconnect-official-single-sign-on-for-discourse-sso/13045). Accessed 2026-11-08.
[39] Plausible. Configuration overview (secondary mirror). [mintlify.com/plausible/analytics](https://www.mintlify.com/plausible/analytics/self-hosting/configuration). Accessed 2026-11-08.
[40] Mastodon OIDC set-up (secondary). [blog.thms.uk](https://blog.thms.uk/2026/07/mastodon-oidc-setup/). Accessed 2026-11-08.
