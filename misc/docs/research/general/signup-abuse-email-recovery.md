# Open sign-up for enlace_auth: abuse protection, email deliverability, account recovery

Research date: 2026-11-08. Prices are as read on that date from vendor pages where a reference says so; otherwise they are marked unverified.

## Summary and recommendation

1. Ship open sign-up only with email verification. An unverified `POST /auth/register` lets anyone make the platform send mail to third-party addresses, which is the real abuse (email bombing, sender-reputation damage), not fake accounts.
2. Layer cheap defences first: honeypot field, signed time-to-submit token, disposable-domain blocklist (CC0 list [1]), and a per-IP, per-email and global rate limit on every endpoint that sends mail (register, resend, reset), as OWASP advises for reset [2].
3. For a challenge, prefer a self-hosted proof-of-work widget (ALTCHA, MIT [3]) as an optional seam. It sets no cookies by the vendor's own account, so it avoids the CNIL consent problem [4]. Avoid reCAPTCHA: the CNIL names it as needing consent [4]. Turnstile is free and WCAG 2.2 AAA per Cloudflare [5], but is a third-party processor; keep it as a drop-in alternative, not the default.
4. Rate limiting: write a small in-process sliding-window limiter over a `MutableMapping`, behind one keyword seam; do not add slowapi. If `enlace_metering` issue #9 lands a rolling-window policy keyed by principal, reuse its core with the key changed to ip/email (not verified: issue text was not read).
5. Behind a reverse proxy, derive the client IP only from addresses a trusted proxy appended [6]. A wrong setting makes every limit bypassable or makes all users share one bucket.
6. Email: at this volume you are far below Gmail's bulk threshold (about 5,000 messages per day) [7], but SPF, DKIM and a DMARC record (p=none minimum) are still the entry ticket in practice. Verification and reset mail are transactional and exempt from one-click unsubscribe [7]. Use an EU provider (Brevo or Scaleway TEM, both unverified here) or Amazon SES in an EU region ([8], region pricing unverified).
7. Recovery: passwords and email links are the baseline; add saved recovery codes (NIST names them [9]) and, for children, a parent-mediated recovery on the parent's verified email. Always send a notice on change and end sessions after recovery [2].
8. Decide a retention rule for unverified accounts (suggest 7 days, an estimate) and log IPs for a bounded period (CNIL log guidance: 6 to 12 months [10]).

## 1. Bot protection

| Option | Posture | Cost | Python side | Verdict |
|---|---|---|---|---|
| ALTCHA | Self-hosted proof of work; MIT; vendor says no cookies, no fingerprinting, no third-party data; targets WCAG 2.2 AA [3] (vendor claims, no independent audit seen) | Free (open core); dashboards and risk scoring are paid tiers [3] | Verify an HMAC-signed challenge yourself; small | Wrap as optional seam; default when a challenge is wanted |
| Cloudflare Turnstile | Third-party; Cloudflare states WCAG 2.2 AAA; free plan 20 widgets, unlimited challenges [5]; GDPR posture "usable, not automatically compliant" per one third-party analysis [11] | Free [5] | POST token to siteverify | Wrap (alternative adapter) |
| reCAPTCHA v3 | CNIL: consent needed where the provider reuses data for its own purposes, reCAPTCHA cited; consent-gated captchas are self-defeating [4] | Not verified | siteverify | Avoid |
| Friendly Captcha (EU) | EU vendor, proof of work | Pricing page could not be read | Not verified | Study |
| hCaptcha, mCaptcha | Not researched in this pass; mCaptcha is a self-hosted PoW project | Not verified | Not verified | Study |

Child users matter: image puzzles are the hostile kind, so favour invisible proof of work. Consent-free is worth more than any score quality at this scale. CNIL: no consent is needed when the captcha's only purpose is securing the site and the provider does not reuse data [4].

Cheap signals, none from a cited source beyond the list, so treat as standard practice: a hidden honeypot input (reject if filled), an HMAC-signed timestamp issued with the form (reject submits faster than about 2 seconds, an estimate), and the `disposable-email-domains` blocklist, licensed CC0, community-maintained, with the caveat that entries may no longer be disposable, so allow an admin override [1]. An MX lookup adds a DNS dependency and a failure mode; make it optional and fail open.

## 2. Rate limiting without Redis

The `limits` library offers one API for sync and async code and storage backends listed as Redis, Memcached and MongoDB [12]; its in-memory backend was not confirmed on the page I read, so verify before depending on it. For one small server, a 40-line sliding window over a dict is simpler than a dependency and fits the existing `MutableMapping` store idiom. State is per process, so run one worker or accept per-worker limits.

Keys: limit by IP (and by IPv4 /24 or IPv6 /64 as a coarse tier, estimate), by target email, and globally for mail sent per hour. The email key is what stops mail bombing: a victim address receives at most N messages per window regardless of how many IPs ask. OWASP's reset sheet says to limit requests per account or require a captcha to prevent floods of emails, and to rate-limit token guessing [2]. It also says not to lock accounts on forgotten-password activity [2]. The same rule applies to sign-up: throttle, never lock.

Behind a proxy, `X-Forwarded-For` is spoofable; use only addresses appended by a trusted proxy, counted from the right [6]. Make the trusted proxy count a setting; the safe default with no proxy configured is the socket peer.

Credential stuffing on login: per-account and per-IP throttling with uniform error text. I did not retrieve the OWASP credential-stuffing sheet, so this is general practice, not a cited claim.

## 3. Transactional email

Google's sender rules [7]: a bulk sender is one sending close to 5,000 or more messages a day to Gmail; bulk senders need SPF and DKIM, and a DMARC record with at least p=none, aligned on SPF or DKIM; spam rate should stay under 0.1% and never reach 0.3%; one-click unsubscribe applies to marketing only, and password resets are listed as transactional and excluded [7]. Microsoft's consumer-domain rules have applied since 5 May 2025 at 5,000+ per day, but only vendor blogs were read and they conflict on one-click unsubscribe, so that is unverified [13]. Practical reading, an estimate: authenticate anyway, because small senders on a shared IP or a fresh domain are filtered on the same signals.

| Provider | Free tier | Paid entry | EU data | Notes |
|---|---|---|---|---|
| Amazon SES | $200 credits for 6 months for new accounts | $0.10 per 1,000 (pay as you go) [8] | EU regions exist; pricing by region not confirmed | SMTP and API; account starts sandboxed (from memory, unverified) |
| Postmark | 100 per month, does not expire [14] | $15 per month for 10,000 [14] | Not verified | Strong transactional reputation (reputation claim unverified) |
| Resend | 3,000 per month, 100 per day [15] | $20 per month for 50,000 [15] | "Multi-region", EU not named [15] | API first, SMTP available (unverified) |
| Brevo (FR) | Free page unreadable; secondary sources say 300 per day, with conflict [16] | Unverified | French company | Verify before choosing |
| Scaleway TEM (EU) | One unreliable source: 300 per month free, 0.25 per 1,000 [16] | Unverified | EU | Verify on the vendor page |
| Mailgun, Mailjet, Google Workspace SMTP | Not researched | | | Google SMTP has low daily caps and ties mail to a person's account (general knowledge, unverified) |

DNS for a self-hosted domain: SPF include for the provider, DKIM keys the provider gives you, DMARC `v=DMARC1; p=none; rua=...` first, tightening to quarantine once reports are clean. Send from a subdomain (for example `mail.example.org`) so marketing or experiments never touch the main domain's reputation (practice, no source).

Templates: plain text plus HTML, one link, a short expiry stated in the text (reset tokens are single-use with an expiry; OWASP gives no fixed number [2], 30 to 60 minutes is common), no tracking pixels or link rewriting (disable provider click tracking, which also breaks token links), and links built from a configured base URL, never the Host header [2].

## 4. Account recovery

OWASP reset points [2]: same response and similar timing whether or not the account exists; token from a CSPRNG, bound to one user, single-use, expiring; do not log in automatically after reset; email a change notice; end sessions or ask; set no-referrer on the reset page; after suspected compromise do not trust recently changed recovery details and invalidate outstanding links.

NIST SP 800-63B-4 defines recovery codes as secrets issued to a subscriber who can no longer authenticate, covers saved and issued codes and recovery contacts, and requires its account recovery procedures when the subscriber cannot meet the AAL [9]. I could not read section 4.2 itself; entropy and combination rules in secondary blogs (64 bits, two codes for AAL2) are unconfirmed.

For this platform, an estimate of a sensible ladder: (a) email link, (b) 8 to 10 saved single-use recovery codes shown once at passkey or password enrolment, stored hashed, (c) a second passkey, (d) for children, no child email: a parent account owns the child's recovery and issues a one-time code, with a notice to the parent, and (e) admin-mediated reset as the last resort, logged. Every recovery ends sessions and connector refresh families together, which the repository already routes through one function.

## 5. Not asked, but important

- Children and GDPR: parental consent thresholds for online services apply in France; the exact age (15) was not verified in this pass, so confirm with the CNIL before launch.
- Log retention: the CNIL logging recommendation points to 6 months to 1 year for traceability logs, longer only when justified [10]. Log sign-up events (time, outcome, hashed or truncated IP, email hash) not raw bodies.
- Unverified accounts: delete after a short window so the store does not grow with squatted addresses; do not reveal that an email is already registered (same neutral response as reset), sending the owner a "you already have an account" mail instead.
- Password policy: breach-list check and length over composition rules (general NIST direction, not re-read here).
- Fail closed and add tests for the unchanged denial path, per the repository's own rule.

## Gaps

Not verified: Brevo, Scaleway, Mailgun, Mailjet prices; hCaptcha, mCaptcha, Friendly Captcha terms; Microsoft's one-click requirement; NIST section 4.2 text; the French digital-consent age; `limits` in-memory backend; `enlace_metering` issue contents.

## REFERENCES

1. [disposable-email-domains (CC0 blocklist)](https://github.com/disposable-email-domains/disposable-email-domains)
2. [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
3. [ALTCHA open source captcha](https://altcha.org/open-source-captcha/)
4. [CNIL cookies Q&A, question on captcha](https://www.cnil.fr/fr/questions-reponses-lignes-directrices-modificatives-et-recommandation-cookies-traceurs)
5. [Cloudflare Turnstile plans](https://developers.cloudflare.com/turnstile/plans/)
6. [MDN: X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For)
7. [Google email sender guidelines FAQ](https://support.google.com/a/answer/14229414)
8. [Amazon SES pricing](https://aws.amazon.com/ses/pricing/)
9. [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
10. [CNIL logging recommendation](https://www.CNIL.fr/sites/cnil/files/atoms/files/recommandation_-_journalisation.pdf)
11. [captcha.eu: is Turnstile GDPR compliant](https://www.captcha.eu/is-cloudflare-turnstile-gdpr-compliant/)
12. [limits documentation](https://limits.readthedocs.io/en/stable/)
13. [Resend: Microsoft bulk sending requirements 2025](https://www.resend.com/blog/microsoft-bulk-sending-requirements-2025)
14. [Postmark pricing](https://postmarkapp.com/pricing)
15. [Resend pricing](https://resend.com/pricing)
16. [Dupple: best transactional email services 2026](https://dupple.com/learn/best-transactional-email-services)
