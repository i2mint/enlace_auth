# Usernames (handles): synthesis and decisions

Date: 2026-11-27. What `enlace_auth.handles` implements, why, and where it departs from the research. The evidence is in two companion reports in this folder, each with its own numbered references: [the identifier and its abuse surface](usernames-identifiers-and-abuse.md) (characters, Unicode, reserved and offensive names, renames, races) and [defaults, the first-run UI and privacy](usernames-defaults-ux-privacy.md) (generating a default from an email, the availability check, GDPR). References below are to those reports: `[I-n]` for the first, `[D-n]` for the second.

## Summary

The account key stays the email; the handle is an alias resolved at read time, so apps store the account id and never a handle (Slack and GitHub both learned this the hard way [I-5] [I-3]). Handles are ASCII, lowercase, unique under a key that ignores separators and folds look-alike characters, claimed under a lock rather than check-then-insert, and never handed to someone else while recently released. The one product requirement that needed a design answer is "the default username is the email's local part": a handle made from an email leaks part of the address [D-1], and GDPR Art. 25(2) says personal data must not be made public by default without the person's own action [D-4]. So the default is **private and soft** until its owner confirms or changes it.

## Decisions

| Topic | Decision | Source |
|---|---|---|
| Identity | Email is the account key; apps store `request.state.user_id` and render `handle_of(user_id)` at read time | [I-5], [I-3], [D-5] |
| Charset | `a-z`, `0-9`, and `.` `_` `-` as separators; no leading, trailing or doubled separator; 3 to 30 characters; at least one letter | [I-6], [I-7], [I-8] |
| Input | NFKC, case-fold, NFKC again (idempotent; plain `casefold(NFKC(x))` is not), then require ASCII. Stored lowercase: the display form is the key form, no locale question | [I-1], [I-41] |
| Uniqueness key | separators removed, `0`→`o`, `1` and `i`→`l` (PyPI's "ultranormalised" idea) | [I-13], [I-14], [I-15] |
| Reserved | routes and pages, roles and RFC 2142 mailboxes, protocol names (`wpad`, `autoconfig`, `.well-known`), words that read as nobody; plus the platform's `[auth.groups]` names; plus `[auth.handles] reserved` | [I-12], [I-19], [D-10] |
| Default | local part, `+tag` dropped, accents folded, then `name`, `name1` ... `name10`, `name11`; `_` before the suffix when the name ends in a digit; a role mailbox (`info@`) falls back to `user`; random 4-digit suffixes after 99 | [D-6], product requirement |
| Default visibility | private and soft until confirmed: lookups return nothing, the availability check calls the name free, a claim of it moves the default on | [D-1], [D-4] |
| First run | one screen: the prefilled handle, a live `@handle` preview, "made from your email address, others will see it", "Continue as @handle" or change it | [D-29], [D-32] |
| Availability check | signed-in only, rate-limited per account, returns the normalised preview, the problem in words, and up to three suggestions; the server re-checks on submit | [D-30], [D-37], [I-29] |
| Renames | first choice free; then once per 30 days; the old name stays with the account for 90 days and redirects | [I-2], [I-23], [I-24] |
| Deletion | the name is held 90 days with no account attached (the email is erased); an unconfirmed default is freed at once | [D-15], [D-44] |
| Races | every write under one lock (`flock` across the workers of a host); the read path ignores an entry its account no longer points back at, so an interrupted write never yields two owners | [I-26], [I-27], [I-29] |

## Where the code departs from the reports, and why

- **Dots and underscores are allowed** ([I-6] recommends hyphen only, for DNS-label validity). Defaults come from email local parts, where `john.smith` is the common form; the uniqueness key folds separators, so the near-duplicate risk is covered. Revisit if handles ever become subdomains.
- **Fullwidth and compatibility forms are mapped, not rejected** ([I-1] prefers rejecting). The mapping is idempotent and the stored form is ASCII, so two inputs can only reach the same handle by being the same name.
- **No separate case-preserved display form.** Lowercase only, as Discord did in 2023 [D-22]; an expressive, non-unique display name is a separate future field.
- **Offensive names are not filtered yet.** The reports recommend whole-token matching against LDNOOBW (CC-BY-4.0) with hits held for review [I-49], [I-50]; until then the reserved list is the only block, and admins rename with `enlace-auth set-handle --force`.
- **Transliteration is stdlib-only** (NFKD, accents dropped). `anyascii` (ISC) is the better engine for non-Latin scripts [D-7]; today such a local part falls back to `user`.
- **Allocation probes sequentially** under the lock rather than with a range query [D-12]; at the platform's scale a probe is a file read, and the random tail bounds the worst case.

## Next steps

- A display name beside the handle (Unicode, not unique).
- Offensive-name screening, held for an admin's review.
- A platform-served "choose your username" page for apps without their own first-run step.
- The admin dashboard's view of handles (the CLI exists).
