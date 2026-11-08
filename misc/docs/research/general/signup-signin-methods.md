# Self-service sign-up and sign-in methods: state of the art, November 2026

Research note for adding self-service account creation to enlace_auth: a pure-ASGI auth plugin with signed cookie sessions, CSRF double-submit, `MutableMapping` stores, Authlib OIDC client login, Argon2 hashing and an SMTP sender, serving several small apps under one domain (`/<app>/`), with users mostly in France, some of them children aged 10 to 15 with parents and teachers, and one app that may ship to iOS and Android. Self-hosted identity providers were compared in the enlace repository's `misc/docs/auth_cross_cutting__Authentication_and_Authorization_as_Cross_Cutting_Concerns.md` and are not repeated here. Library versions were read from PyPI, npm and GitHub on 2026-11-08.

## Summary and recommendation

1. **Prove the address before an account exists.** Move `POST /auth/register` to verify-before-create, behind a uniform "check your email" response. Today it creates unverified accounts and answers 409 for a known address. That gives away which addresses have accounts, and creating accounts for addresses nobody has proven is the root cause of the "pre-hijacking" attacks found on 35 of 75 popular services [1][2].
2. **Make a six-digit email code the universal bootstrap.** Use it for sign-up, passwordless sign-in and recovery. Codes work across devices and are not spent by link-scanning mail filters, and they need only the SMTP sender and an HMAC, both already in the stack [3][4]. Send a magic link only as a convenience, and have it land on a page that spends the token on a POST, never on a GET.
3. **Offer passkeys as the upgrade, not the gate.** Offer to create a passkey right after the first verified sign-in. Turn on autofill (conditional UI) on the email field. Use py_webauthn on the server (BSD-3-Clause, v3.0.1, September 2026). The RP ID is the apex domain, so one passkey covers every app on the platform [5][6].
4. **Keep passwords optional and bring them in line with NIST SP 800-63B-4.** That means at least 15 characters when the password is the only factor (the current minimum is 8), at least 64 allowed, no composition rules, and a breached-password check through the Pwned Passwords k-anonymity API [7][8].
5. **Keep linking keyed on the provider's subject.** Social login already keys accounts on `(provider, sub)`, so keep it that way. Add Sign in with Apple only if the iOS app offers Google or GitHub login: Guideline 4.8 then requires an equivalent privacy-preserving login [9]. Build account deletion now, platform-wide, because iOS requires it in-app [10].
6. **Do not require email from children.** Most do not have one. Give them accounts created and recovered by an adult (a parent or teacher invite, then a passkey or QR badge), and get parental consent under 15 wherever consent is the legal basis [11].
7. **Set sign-up policy per app.** Use one setting per app (`open | invite | allowlist | closed`) over a single platform account, and gate access with the existing `is_user_allowed` predicate.

## 1. Methods compared

**Passkeys (WebAuthn).** A passkey is a FIDO2/WebAuthn *discoverable* credential: the authenticator stores it in full, so the user can sign in without typing an identifier. *Synced* passkeys are backed up by a passkey provider such as iCloud Keychain or Google Password Manager. *Device-bound* passkeys stay on one authenticator, typically a security key [12]. WebAuthn Level 3 became a W3C Recommendation on 25 August 2026 [13]. It standardises client capabilities including `conditionalGet`, `conditionalCreate`, `hybridTransport`, `relatedOrigins` and the signal methods [5].

- *Adoption.* The FIDO Passkey Index 2026 pools 15 large consumer relying parties. Across them, 90% of active accounts can use a passkey, 42% of those eligible have enrolled one, and 36% of successful sign-ins now use a passkey, up from 26% in 2025. Passkey sign-ins succeed 93% of the time against 78% for traditional MFA, and save about 27 seconds per sign-in [14]. The 2025 Index reported over 3 billion passkeys and a 93% versus 63% success rate against other methods [15]. FIDO's 2026 consumer survey (11,000 adults in 10 countries, France among them) found 75% had enabled passkeys on at least one account [16]. These are member-supplied, unweighted figures from very large services. Nothing measures adoption on small sites, so treat them as an upper bound.
- *Conditional UI and conditional create.* With autofill (`autocomplete="username webauthn"`), existing passkeys appear in the field's suggestion list [12]. *Conditional create* (`mediation: "conditional"` on `create()`) lets the password manager add a passkey silently, but only right after a sign-in with a saved password. Magic-link, phone and federated sign-ins do not qualify. The response reports user presence and verification as false, so the server must not require them in that ceremony [17].
- *Signal API.* `signalUnknownCredential`, `signalAllAcceptedCredentials` and `signalCurrentUserDetails` tell the user's passkey provider that a credential was deleted or a name changed. It is supported in Chrome on desktop from version 132 and on Android from 144. Providers may ignore a signal, and the call returns nothing [18].
- *Cross-device (hybrid).* A phone that holds the passkey can sign in on a laptop by scanning a QR code over CTAP hybrid transport [12].
- *Assurance.* NIST allows syncable authenticators up to AAL2 but not AAL3, because a synced key is exportable [7].
- *Recovery.* Syncing reduces lost-passkey cases but does not remove them. Service providers still have to plan recovery for users who cannot reach any authenticator [19]. NIST recognises four recovery classes: saved recovery codes, issued recovery codes (which may go by email, at least six digits, valid up to 24 hours), recovery contacts and repeated identity proofing. Every recovery must notify the subscriber [7]. For an email-identified account the realistic floor is therefore an emailed code, so the account is only as strong as the mailbox.
- *Passkey-first sign-up.* The common pattern is to verify the email with a code, create the account, and register a passkey in the same session. Sign-up with a passkey and a username but no email works too, but it leaves no recovery channel. That makes it suitable only for managed accounts where an adult is the recovery contact (design inference, not a cited standard).
- *iOS.* A native app can use the web's passkeys only through a `webcredentials` associated domain backed by an `apple-app-site-association` file on that domain [20].

**Email magic links and one-time codes.** Both prove control of a mailbox at the moment of use, and neither resists phishing, because the inbox remains the trust anchor [3]. NIST SP 800-63B-4 says email "SHALL NOT be used" for out-of-band authentication. It treats email codes as address confirmation or recovery, not as an authenticator [7]. Email sign-in is therefore, in NIST terms, a recovery on every visit. That is an acceptable trade-off for low-value apps, but it should not be called MFA.

- *Scanners.* Mail-security gateways fetch the links in incoming mail, which spends single-use tokens before the user clicks, a frequent cause of "token expired" reports. The fix is a code, or a link to a side-effect-free page that spends the token on a POST [4][21].
- *Cross-device.* A code read on a phone can be typed on a laptop, which is the strongest practical argument for codes. Links also open new tabs and break the flow [3]. Okta binds a magic link to the browser that requested it and falls back to a code when the user opens it elsewhere [22].
- *In-app browsers.* A link opened from a mail app can land in a different browser and cookie jar than the one where sign-in started. This is widely reported, but no authoritative source was found, so treat it as unverified.
- *Parameters.* NIST caps out-of-band secrets at 10 minutes, requires rate limiting for secrets under 64 bits, and says issuing a new secret must not reset the attempt counter [7].

**OAuth/OIDC social login.** enlace_auth already binds identities to the provider's stable subject. That matches OWASP, which says to identify a federated user by `iss` plus `sub`, never by email [2]. It also matches Google, which says to key on `sub` and to treat a Google-asserted email as strong evidence only for Gmail addresses or Workspace accounts with `hd` set [23][24].

- *nOAuth.* Disclosed in 2023, it lets an attacker set any email in their own Entra tenant and log in as the victim at apps that match on email [25]. A 2025 follow-up still found 9 of 104 Entra gallery apps vulnerable [26]. Microsoft's guidance is to key on `tid` plus `oid`. Since June 2023, new multi-tenant apps by default no longer receive emails whose domain is unverified, and the `xms_edov` claim reports domain-owner verification [27].
- *Sign in with Apple.* App Store Guideline 4.8 says an iOS app that uses third-party login for the primary account "must also offer as an equivalent option" a login that limits data collection to name and email, lets the user keep the email private, and does not track for advertising. Apps using only their own account system are exempt [9]. Sign in with Apple is the usual way to meet this. Deleting such an account requires revoking its tokens through Apple's REST API [10].
- *Children.* Since 2021, Google accounts that parents manage through Family Link can sign in to third-party apps under parental controls. This comes from secondary reporting and was not checked against current Google help [28].

**Password with email verification.** NIST SP 800-63B-4 (final, July 2025) [29] sets these rules. The minimum is 15 characters when the password is the only factor and 8 within MFA. At least 64 characters must be allowed, and Unicode accepted. Composition rules and periodic rotation are prohibited. Every new password is checked against a blocklist of common and compromised values, whole-string. Password managers and paste are allowed [7]. France diverges slightly. ANSSI's guide (v2.0, 8 October 2021) recommends 12 to 14 characters for "medium to strong" sensitivity and 15 or more for "strong". It recommends no maximum length (R22) and, unlike NIST, still recommends complexity rules (R23) [30]. The CNIL's 2022 recommendation asks for 80 bits of entropy when the password is the only protection, for example 12 characters across four character classes, 14 without special characters, or a passphrase of 7 words. It accepts 50 bits when throttling is in place and names Argon2 or scrypt for storage [31]. Breached-password checks need no dependency. The Pwned Passwords range API takes the first five hex characters of a SHA-1 hash, and an `Add-Padding` header hides the response size [8].

| Method | Phishing resistance | Sign-up friction | Cost in this stack | New dependency | Child without email |
|---|---|---|---|---|---|
| Passkey | High (origin-bound) | Low once supported; needs a capable device | Medium: two ceremonies, a credential store, JS | py_webauthn, optional `@simplewebauthn/browser` | Yes, if an adult creates the account and is the recovery contact |
| Email code (OTP) | Low (code can be relayed) | Low-medium: switch to mail | Low: SMTP + HMAC + a TTL store | None | No |
| Magic link | Low | Lowest on one device, poor across devices | Low, plus scanner-safe POST landing | None | No |
| Google / GitHub / Microsoft | Inherits the provider's (often passkey or MFA) | Lowest for adults | Done; linking by `sub` exists | Authlib (present) | Only supervised Google accounts, parent-controlled |
| Sign in with Apple | As above | Lowest on iOS | Medium: key-signed client secret [32], token revocation on delete [10] | Authlib (present) | Apple child accounts not verified here |
| Password + verified email | Low | Highest | Low: exists; add verification + blocklist | None (HTTP to Pwned Passwords) | Only with a teacher-issued credential |

## 2. Normative guidance in one place

- **Uniform responses.** OWASP wants the same message and HTTP status whether or not an account exists, at login, at reset and at registration. Its suggested registration message is "A link to activate your account has been emailed to the address provided." No quick exit that skips hashing for unknown users [2].
- **Forgot password.** Tokens must be random, single-use, expiring and bound to the user. Never build the link from the Host header. Set `Referrer-Policy: no-referrer` on the reset page. Do not auto-login after a reset, end the other sessions, and rate-limit both requests and token attempts [33].
- **Credential stuffing.** OWASP recommends MFA where possible, CAPTCHA only on suspicious traffic, breached-password screening, and notification of suspicious events. It notes that a multi-step (identifier-first) login must not become an enumeration oracle [34].
- **Throttling.** NIST caps consecutive failures at 100 per authenticator [7]. ANSSI R10 asks for limits on attempts over time and R14 for no detail about why authentication failed. R8 advises against SMS as a channel for a factor [30].
- **Email changes.** Store the new address as pending, notify the old one and confirm the new one with time-limited nonces [2]. NIST also requires a notification on every recovery event [7].

## 3. Flow patterns

- **Identifier-first, "continue with email".** Use one field, with passkey autofill attached. On submit, always answer "we sent you a code". Look up the account only after the code verifies, then branch: an existing account is signed in, a new address goes to account creation under the app's sign-up policy. The difference between the two cases is visible only in the mailbox. That keeps the response uniform [2] and makes verify-before-create the default.
- **Verify-before-create, not pending accounts.** Keep `{email, code_hash, expires, attempts}` in a TTL `MutableMapping` and write the user record only after the code verifies. If pending accounts are ever used, a pending account must be unable to sign in or be linked, it must expire, and a verified sign-in for the same address must replace it. The pre-hijacking paper traces every attack class it found to failing to verify ownership of the claimed identifier [1].
- **Invitations and invite codes.** Sign invites with itsdangerous (already a dependency), bound to an email or to a usage cap. A token that must be single-use also needs a server-side "spent" record, because a signature alone cannot be revoked. This is the natural channel for teacher- and parent-created child accounts. A QR "badge" that a teacher prints is the established pattern for pupils who cannot type a password [35].
- **Waitlists.** A waitlist is an `invite` policy plus a form that collects an address with consent. It needs no new authentication mechanism.
- **Per-app policy.** Keep one platform account and one setting per app. "May sign up" and "may open the app" are separate: the first decides whether an account is created, the second stays with `is_user_allowed`.
- **Progressive profiling.** Ask only for what sign-in needs, and collect a display name, age band or school later, when a feature needs it. Apple forbids requiring personal information that is not directly relevant to the app's core function or required by law [9].
- **Account deletion.** An iOS app with account creation must let the user start deletion in-app. The deletion must cover the whole account and its data, not a deactivation, and must not require contacting support. Re-authentication is allowed [10]. A platform-level `/auth/account/delete` satisfies this for every app at once.

## 4. Libraries

| Library | Role | Licence | Latest (date) | Verdict |
|---|---|---|---|---|
| `webauthn` (py_webauthn, Duo Labs) [6] | WebAuthn RP verification | BSD-3-Clause | 3.0.1 (2026-09-25); v3.0 adds ML-DSA keys | **Depend.** Small, pure functions, no framework coupling |
| `fido2` (Yubico python-fido2) [36] | RP server and CTAP client | BSD-2-Clause, some files Apache-2.0 / MPL-2.0 | 2.2.1 (2026-06-29) | **Study**: an alternative RP; its client side drives real keys in manual tests |
| `Authlib` [37] | OIDC client (already used) | BSD-3-Clause | 1.9.5 (2026-11-05) | **Depend** (present); add an Apple preset |
| `itsdangerous` [38] | Signed tokens (already used) | BSD-3-Clause | 2.2.0 (2024-04-16) | **Depend** (present); stable, infrequent releases |
| `pyotp` [39] | TOTP/HOTP | MIT | 2.10.0 (2026-06-14) | **Avoid** for email codes (`secrets` + HMAC suffice); depend only if TOTP MFA is added |
| `fastapi-users` [40] | Full user system | MIT | 15.0.5 (2026-03-27) | **Avoid**: README declares maintenance mode, and it uses `Depends` injection; study its verify/reset flows |
| `argon2-cffi` / `pwdlib` [41] | Hashing | MIT / MIT | 25.1.0 (2025-06-03) / 0.3.1 (2026-08-12) | Keep argon2-cffi |
| Pwned Passwords API [8] | Breach check | Free service | n/a | **Wrap**: one HTTPS GET |
| `@simplewebauthn/browser` [42] | Browser ceremonies, base64url JSON | MIT | 14.0.0 (2026-09-02) | **Depend** or use plain `navigator.credentials`; the Level 3 JSON helpers [5] make plain JS viable, but check browser support |
| ALTCHA [43] | Self-hosted proof-of-work anti-bot | MIT | n/a | **Study** for open sign-up; no cookies (vendor claim) |

## 5. Terminology

| Term | Meaning (source) |
|---|---|
| Sign-up / registration | Product words for creating an account. NIST says *enrollment* for registering a subscriber with a credential service provider and *binding* for attaching an authenticator [7] |
| Subscriber, claimant | The account holder; the party who is trying to authenticate [7] |
| Relying party (RP), RP ID | The site verifying the user [12]; the RP ID is a domain (the origin's effective domain or a registrable suffix of it), never a path [5] |
| Authenticator | Something the user controls that proves identity: a platform or roaming authenticator, password, OTP device [12][7] |
| Conditional mediation | WebAuthn's term for passkey autofill (get) and silent upgrade (create) [12][17] |
| Account recovery | Regaining access when no bound authenticator is usable, through recovery codes, contacts or proofing [7] |
| JIT provisioning | Creating the local account on the first federated sign-in. The term is common in IdP documentation, but no normative definition was found. enlace_auth calls this auto-provisioning |
| Identifier-first | Ask for the identifier, then choose the method; OWASP's "multi-step login" [34] |

## 6. Things not asked about that matter

- **Findings in the current code.** `POST /auth/register` answers 409 for an existing address, which lets anyone test whether an address has an account [2]. Its 8-character minimum is the NIST figure for passwords inside MFA, not for a single factor, and no breached-password check is made [7]. An unverified registration also lets an attacker squat on a victim's address. Because OAuth never takes over a password account on an email match, the victim's later Google sign-in is refused. That is safe, but it denies the victim service until they reset. A reset ends sessions and unlinks external sign-ins, which defeats the "unexpired session" pre-hijack variant [1].
- **One origin, one RP.** Every app under the domain shares the RP ID, so a script in any co-hosted app can run WebAuthn ceremonies for the platform. This is the same trust boundary as the session cookie, which the OAuth module already documents (inference from [5]).
- **Deliverability is part of authentication.** Google requires SPF or DKIM, plus TLS, from every sender. Senders of more than 5,000 messages a day also need DMARC and alignment [44]. A code that lands in spam is an outage.
- **Minors in France.** Article 45 of the Loi Informatique et Libertés sets 15 as the age for consenting alone when consent is the legal basis, and the CNIL recommends seeking a parent's consent below that age. The CNIL itself notes that the texts do not say how to verify age or collect consent [11]. Apple's Kids Category forbids sending personal data to third parties, which constrains social login inside a kids' app (inference from [9]). The EU's age-verification blueprint, piloted in France from July 2025, proves "over 18" rather than parental consent [45]. Watch it, but it does not solve this case.
- **Notify on security events.** Send mail when a passkey is added, a password changes, recovery runs or an identity is linked [7][2].

## REFERENCES

1. [Sudhodanan A, Paverd A. Pre-hijacked accounts: An Empirical Study of Security Failures in User Account Creation on the Web. USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/sudhodanan)
2. [OWASP. Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
3. [Hanko. Magic links vs email passcodes (25 March 2026)](https://www.hanko.io/blog/magic-links-vs-email-passcodes)
4. [Supabase community. Magic links and password reset tokens consumed by email scanners in institutional environments, discussion 41618](https://github.com/orgs/supabase/discussions/41618)
5. [W3C. Web Authentication: An API for accessing Public Key Credentials, Level 3 (Recommendation)](https://www.w3.org/TR/webauthn-3/)
6. [duo-labs/py_webauthn on GitHub (CHANGELOG) and PyPI `webauthn`](https://github.com/duo-labs/py_webauthn)
7. [NIST SP 800-63B-4. Digital Identity Guidelines: Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
8. [Have I Been Pwned. API v3, Pwned Passwords range search](https://haveibeenpwned.com/API/v3)
9. [Apple. App Store Review Guidelines (4.8 Login Services; 5.1.1(v) Account Sign-In; 1.3 Kids Category)](https://developer.apple.com/app-store/review/guidelines/)
10. [Apple. Offering account deletion in your app](https://developer.apple.com/support/offering-account-deletion-in-your-app/)
11. [CNIL. La CNIL publie 8 recommandations pour renforcer la protection des mineurs en ligne](https://www.cnil.fr/fr/node/313)
12. [passkeys.dev. Terms](https://passkeys.dev/docs/reference/terms/)
13. [W3C News. Web Authentication Level 3 is now a W3C Recommendation (2026)](https://www.w3.org/news/2026/web-authentication-an-api-for-accessing-public-key-credentials-level-3-is-now-a-w3c-recommendation/)
14. [FIDO Alliance. Passkey Index, October 2026 (PDF)](https://fidoalliance.org/wp-content/uploads/2026/10/Passkey-Index-October-2026.pdf)
15. [FIDO Alliance. FIDO Alliance Launches Passkey Index (13 October 2025)](https://fidoalliance.org/fido-alliance-launches-passkey-index-revealing-significant-passkey-uptake-and-business-benefits/)
16. [FIDO Alliance. The State of Passkeys 2026 (7 May 2026)](https://fidoalliance.org/the-state-of-passkeys-2026/)
17. [Chrome for Developers. Help users adopt passkeys more seamlessly (conditional create), updated 22 December 2025](https://developer.chrome.com/docs/identity/webauthn-conditional-create)
18. [Chrome for Developers. Keep passkeys consistent with credentials on your server with the Signal API](https://developer.chrome.com/docs/identity/webauthn-signal-api)
19. [Yubico. Passkey Best Practices for Service Providers](https://docs.yubico.com/hardware/yubikey-guidance/best-practices/sp-bestpractices-passkeys.html)
20. [Apple Developer. Supporting passkeys](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys)
21. [Supabase. OTP verification failures: 'token has expired' or 'otp_expired' errors](https://supabase.com/kb/troubleshooting/otp-verification-failures-token-has-expired-or-otp_expired-errors)
22. [Okta Developer. Email Magic Links overview](https://developer.okta.com/docs/guides/email-magic-links-overview/main/)
23. [Google Identity. Verify the Google ID token on your server side](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)
24. [Google Identity. Streamlined linking with OAuth and Google Sign-In](https://developers.google.com/identity/account-linking/oauth-with-sign-in-linking)
25. [Descope. nOAuth: How Microsoft OAuth Misconfiguration Can Lead to Full Account Takeover (2023)](https://www.descope.com/blog/post/noauth)
26. [Semperis. Research uncovers ongoing risk from nOAuth vulnerability in Microsoft Entra ID (June 2025)](https://www.semperis.com/press-release/research-risk-noauth-vulnerability-microsoft-entra-id-enterprise-saas-applications/)
27. [Microsoft Learn. Migrate away from using email claims for user identification or authorization](https://learn.microsoft.com/en-us/entra/identity-platform/migrate-off-email-claim-authorization)
28. [Android Police. Google accounts for kids can now finally sign into third-party apps (June 2021)](https://www.androidpolice.com/2021/06/10/google-accounts-for-kids-can-now-finally-sign-into-third-party-apps/)
29. [NIST CSRC. SP 800-63B-4 final, published July 2025](https://csrc.nist.gov/pubs/sp/800/63/b/4/final)
30. [ANSSI. Recommandations relatives à l'authentification multifacteur et aux mots de passe, v2.0, 8 October 2021](https://cyber.gouv.fr/publications/recommandations-relatives-lauthentification-multifacteur-et-aux-mots-de-passe)
31. [CNIL. Mots de passe : recommandations pour maîtriser sa sécurité (délibération 2022-100)](https://cnil.fr/fr/node/8939)
32. [Apple Developer. Creating a client secret](https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret)
33. [OWASP. Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
34. [OWASP. Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
35. [VentureBeat. Clever's new Badges help K-2 students access apps on its education platform](https://venturebeat.com/business/clevers-new-badges-help-k-2-students-access-apps-on-its-education-platform)
36. [Yubico/python-fido2 on GitHub](https://github.com/Yubico/python-fido2)
37. [Authlib on PyPI](https://pypi.org/project/Authlib/)
38. [itsdangerous on PyPI](https://pypi.org/project/itsdangerous/)
39. [pyotp on PyPI](https://pypi.org/project/pyotp/)
40. [fastapi-users README (maintenance-mode notice)](https://github.com/fastapi-users/fastapi-users)
41. [pwdlib on PyPI](https://pypi.org/project/pwdlib/) and [argon2-cffi on PyPI](https://pypi.org/project/argon2-cffi/)
42. [@simplewebauthn/browser on npm](https://www.npmjs.com/package/@simplewebauthn/browser)
43. [altcha-org/altcha on GitHub](https://github.com/altcha-org/altcha)
44. [Google. Email sender guidelines](https://support.google.com/mail/answer/81126)
45. [Computing. EU unveils prototype age verification app and platform guidelines (July 2025)](https://www.computing.co.uk/feature/2025/eu-unveils-prototype-age-verification-app-and-platform-guidelines)
