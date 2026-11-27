# Usernames on a multi-app platform: the identifier and its abuse surface

Research date: 2026-11-27. Scope: the public handle (unique, case-insensitive) that sits beside a private email identifier. Covers the character set, Unicode canonicalisation, reserved and offensive names, renames and squatting, and atomic uniqueness. The companion report in this folder covers defaults, UX and privacy.

## Summary

The handle is a lookup key and a display string, never an identity. Every incident found in this research comes from forgetting that: Spotify let two different strings canonicalise to the same account because its canonicaliser was not idempotent [1]; GitHub lets a renamed user's old name be claimed by anyone, which became the "repojacking" supply-chain attack [2] [3]; Mastodon shipped an app-level uniqueness check and later had to delete accounts whose usernames differed only in case when it added a database index on `lower(username)` [4]. The safe design is small: an immutable user ID that everything references, an ASCII-only handle with one canonical form, a namespace table where users, reserved names and retired handles share one unique key, and a create-if-absent write to claim a name.

## Recommendations (implementable rules)

1. **Reference users by an immutable ID everywhere; the handle is an alias.** Shares, grants, mentions, ACLs and URLs-with-authority store the user ID, and the handle is resolved at render time. Reason: Slack dropped unique usernames in 2017 and told integrators to mention users by ID [5]; GitHub's own advice against repojacking is to check the stable numeric repo ID, not the name [3].
2. **v1 charset: ASCII `a-z`, `0-9` and `-` only; 3 to 30 characters; must start and end with a letter or digit; no two consecutive hyphens; at least one letter.** Regex on the canonical form: `^(?=.*[a-z])[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){2,29}$`. Reason: this is GitHub's rule [6] with Discourse's default minimum of 3 [7] and Mastodon's and Instagram's maximum of 30 [8] [9]; it is a valid DNS label (so a handle can later become a subdomain without a migration), it excludes `.` (Discourse rejects names ending in `.json`, `.png` and similar because they read as files [10]; GitLab rejects `.git` and `.atom` suffixes [11]) and `_` (not valid in hostnames [12]). The "at least one letter" rule is this report's own reasoning: an all-digit handle can be confused with a numeric ID in a URL.
3. **Canonical form = the input with ASCII uppercase mapped to lowercase; reject, never map, anything else.** Store two columns: `handle_key` (canonical, unique) and `handle_display` (what the user typed, case preserved). Validate that `canonical(x)` passes the regex and that `canonical(canonical(x)) == canonical(x)`. Reason: rejecting non-ASCII input avoids the whole class of canonicaliser bugs (Spotify's fix was exactly this idempotence check [1]); for ASCII, `lower()` and `casefold()` agree, so no locale question arises.
4. **Add a similarity key to block near-collisions, separate from the uniqueness key.** `sim_key = handle_key` with `-` removed, then `0→o`, `1→l`, `i→l` (or a similar fixed map). Reject a new handle whose `sim_key` equals an existing handle's or a reserved name's. Reason: PyPI rejects new project names whose "ultranormalised" form (separators stripped, `l`/`i`→`1`, `o`→`0`) matches an existing one [13]; npm rejects new names that equal an existing one after removing punctuation [14]; Mastodon's username blocklist compares through a digit-to-letter homoglyph map [15].
5. **If Unicode handles are ever allowed, do it behind a seam:** validate with PRECIS `UsernameCasePreserved`, key with `UsernameCaseMapped` (RFC 8265 [16], via `precis_i18n` [17]), require UTS #39 "Highly Restrictive" or "Moderately Restrictive" script mixing [18], and block a new name whose UTS #39 skeleton matches an existing one. Section 2 explains why the obvious `NFKC + casefold` is not enough.
6. **Reserved names are data, not code, and are checked through the similarity key.** Union of: every first path segment your router serves (computed from the router, as Discourse does [10]); every app name on the platform; the infrastructure list from django-registration (BSD-3-Clause) [19]; one general list such as `marteinn/The-Big-Username-Blocklist` (MIT) [20]; and a short "contains" list (`admin`, `official`, `staff`, `support`, `moderator`, the platform's name) matched as substrings. Reason: X refuses handles containing "Admin" or "X" for non-official accounts [21].
7. **Offensive names: whole-token match on the hyphen-split handle and on its `sim_key`, substring match only for a short curated list, an allowlist for false positives, and "hold for review" rather than "reject" on a hit.** Reason: substring filters block real names and places (the Scunthorpe problem) [22]; Discourse routes username matches through the same watched-words actions (block, require approval) it uses for posts [10].
8. **Renames: at most one per 30 days; the old handle is retired to the same account, redirects to the new one, and is never given to another account.** Deleted accounts' handles are retired for at least 90 days, permanently if they had public content. No reclamation of inactive handles except a trademark claim. Reason: GitHub frees a renamed user's name immediately [2], which made repojacking possible and forced GitHub to retire popular names permanently [23]; GitHub holds a deleted account's name for 90 days [24] and reviews release requests only for trademarks [25].
9. **Claim a handle with one atomic create-if-absent write on `handle_key`, never with check-then-insert.** SQL: a unique index on the canonical column and `INSERT ... ON CONFLICT DO NOTHING RETURNING id` [26]. Key-value store: `O_CREAT|O_EXCL` on a file named by the key [27], or an S3 `PutObject` with `If-None-Match: *` [28]. The loser gets a 409 with suggestions. Reason: check-then-act is a TOCTOU race (CWE-367) [29].

## 1. Characters and length on major platforms

| Platform | Charset | Length | Case | Separator rules | Source |
|---|---|---|---|---|---|
| GitHub (users) | ASCII letters, digits, `-` | 1–39 | regex is case-insensitive; display preserves case | no leading/trailing `-`, no `--` | [6] |
| GitLab (user slug) | letters, digits, `_`, `.`, `-` | not verified | not verified | start and end alphanumeric; no consecutive specials; no `.git`/`.atom` suffix; no reserved route followed by `.` | [11] |
| Reddit | letters, digits, `_`, `-` | 3–20 | not verified | not verified | secondary only [30] |
| X / Twitter | letters, digits, `_` | ≤15 (one help page says "more than 4") | case-insensitive (not verified) | none stated; "X"/"Admin" reserved | [21] |
| Instagram | letters, digits, `.`, `_` | ≤30 | not verified | not verified | secondary only [9] |
| Mastodon (local) | `[a-z0-9_]`, case-insensitive match | ≤30 (remote ≤2048) | unique index on `lower(username), lower(domain)` | local accounts: no `.` or `-` at all | [8] [31] |
| Discourse | ASCII `[\w.-]` by default; opt-in Unicode (`\p{Alnum}`, marks, `._-`, minus Hangul fillers and variation selectors) | 3–20 grapheme clusters by default, hard cap 60 code points | key = NFC then `downcase` | start alphanumeric or `_`; end alphanumeric; no 2+ consecutive `-_.`; no file-like suffix | [10] [7] [32] |
| Slack | no unique username since 2017; `display_name` is not unique | n/a | n/a | mention by user ID | [5] |
| npm (packages) | lowercase, URL-safe; no `~)('!*`, no spaces | 1–214 | lowercase only | no leading `.` or `_`; not a Node core module name; new names may not equal an existing one minus punctuation | [33] [14] |
| PyPI (projects) | ASCII letters, digits, `.`, `_`, `-` | not limited by the spec | normalised: runs of `-_.` → `-`, lowercase | start and end alphanumeric | [34] |
| PyPI (usernames) | ASCII letters, digits, `.`, `_`, `-` | ≤50 | not verified | start and end alphanumeric | [35] |

Patterns: every platform listed is ASCII-only for its unique key except Discourse (opt-in) and GitLab (emoji in display names); all forbid separators at the ends; most cap at 15–39. Platforms that use the name in a URL (GitHub, GitLab, npm, Discourse) are the ones that forbid `.`-suffixes or reserve route names.

**ASCII-only vs Unicode.** ASCII-only excludes users who write their name in a non-Latin script, but costs nothing in security engineering: there are no confusables beyond `0/o`, `1/l/i`, no normalisation and no locale-dependent case. Unicode handles need everything in Section 2 plus a policy decision on script mixing, and the confusables data changes with every Unicode release [36]. Since the platform already has a free-text display name, a reasonable split is: Unicode in the display name (not unique, not used for lookup), ASCII in the handle. This mirrors Slack, where the expressive name is not the unique one [5].

## 2. Unicode: normalisation, case, confusables

**Normalisation (UAX #15).** NFC composes canonically equivalent sequences without changing meaning; NFKC also folds compatibility characters (ligatures, superscripts, fullwidth forms), and the standard says the K forms "must not be blindly applied to arbitrary text" but "can be applied more freely to domains with restricted character sets" [37]. For a key, NFKC is the right direction; for display, keep NFC.

**Case (UAX #31, Python, PRECIS).** UAX #31 points case-insensitive identifier comparison to full case folding, and specifically to `toNFKC_Casefold`, which folds case, normalises and removes default-ignorable code points [38]. Python's `str.casefold()` implements Unicode default case folding, so `'straße'.casefold() == 'strasse'` while `lower()` leaves `ß` alone [39]. Default folding is locale-neutral: the Turkish mappings (`I`→`ı`, `İ`→`i`) are separate "T" entries in `CaseFolding.txt` that default folding does not apply [40], so `'İ'.casefold()` yields `i` plus a combining dot. RFC 8265 went the other way: its `UsernameCaseMapped` profile uses `toLowerCase()` and the RFC records that it removed `toCaseFold()` [16]; under it `ß` and `ss` stay distinct.

**Python has no `NFKC_Casefold`.** James Bennett notes that `NFKC` then `casefold()` is the closest stdlib approximation and suggests re-normalising after folding [41]. This matters: a test run for this report (Python 3.11, Unicode 14) found that `f(x) = casefold(NFKC(x))` is not idempotent. `"ᾼ̈"` (capital alpha, diaeresis, ypogegrammeni) gives `α ι ̈` on the first pass and `α ϊ` on the second; a small search over Greek letters and combining marks found 663 such three-code-point sequences. `NFKC(casefold(NFKC(x)))` was idempotent on every case tested. Idempotence failure is exactly the Spotify bug: a reset flow that canonicalised twice reached a different account [1].

**PRECIS (RFC 8264/8265).** `UsernameCaseMapped`: IdentifierClass (no spaces, no compatibility characters), fullwidth/halfwidth width mapping, `toLowerCase`, NFC, Bidi rule; comparison is octet equality after enforcement [16]. `UsernameCasePreserved` is the same without case mapping. Tested with `precis_i18n` 1.1.2: `ＦＵＬＬ` → `full`, `Straße` → `straße`, and Spotify's `ᴮᴵᴳ` is rejected (`DISALLOWED/has_compat`) instead of being mapped. Rejecting compatibility characters is the safer behaviour for a key.

**Confusables (UTS #39).** Two strings are confusable iff `skeleton(X) = skeleton(Y)`, where the skeleton is NFD, removal of default-ignorables, replacement by prototype from `confusables.txt`, NFD again (the current version wraps this in a bidi step); skeletons are for comparison only, not for display or storage as the user's name [18] [42]. The standard distinguishes single-script, mixed-script and whole-script confusables, and defines restriction levels: ASCII-Only, Single Script, Highly Restrictive (single script, or Latin with Han/Japanese/Korean), Moderately Restrictive (Latin plus one other recommended script, except Cyrillic and Greek), Minimally Restrictive, Unrestricted [18]. ICU's `SpoofChecker` implements all of this; its default level is Highly Restrictive, and its documentation warns that skeletons "are not guaranteed to be the same between ICU releases", so store them with the data version and recompute on upgrade [36].

**Canonical vs display form (Unicode variant).** `handle_display` = PRECIS `UsernameCasePreserved` output (NFC, case kept). `handle_key` = PRECIS `UsernameCaseMapped` output, unique. `handle_skel` = UTS #39 skeleton of `handle_key` tagged with the ICU/Unicode version, indexed but not unique, checked before insert. Accept only if the restriction level is at most Moderately Restrictive and enforcement is idempotent.

### Python libraries

| Library | Licence | Latest release | What it gives | Verdict |
|---|---|---|---|---|
| stdlib `unicodedata`, `str.casefold` | PSF | follows Python | NFC/NFKC, default case folding; Unicode version tied to the interpreter (3.11 ships 14.0) | depend (ASCII path needs nothing more) |
| `precis_i18n` [17] | MIT | 1.1.2, Oct 2025, "Production/Stable" | RFC 8264/8265 profiles; pure Python; Unicode from the runtime's `unicodedata` or `unicodedata2` | depend, if Unicode handles are added |
| `PyICU` [43] | MIT | 2.17, Oct 2026 | `SpoofChecker`: skeletons, `areConfusable`, restriction levels | depend only for a Unicode variant; needs ICU installed and compiles against it (the `pyicu-binary` wheel used for testing here is unofficial) |
| `confusable_homoglyphs` [44] | MIT | 3.3.1, Jan 2024; GitHub repo archived Jan 2024, moved to sr.ht | "dangerous" = mixed-script and contains a confusable; not a full skeleton | study (django-registration depends on it [19]) |
| `idna` [45] | BSD-3-Clause | 3.20, Sep 2026 | IDNA 2008 and UTS #46 for domain labels | avoid unless handles become DNS labels |
| `better_profanity`, `profanity-check` | MIT | 2020, 2019 | word list / ML profanity scoring | avoid (stale) |

Licences and dates are from PyPI metadata and the GitHub API on 2026-11-27.

## 3. Reserved and offensive names

**Why reserve.** Geoffrey Thomas's survey [12] lists what goes wrong when user-chosen names collide with names that protocols assume the domain owner controls: hostnames used for discovery (`wpad`, `autoconfig`, `localhost`, `www`, `mail`), mailbox names that certificate authorities use for domain validation (`admin`, `administrator`, `webmaster`, `hostmaster`, `postmaster`), RFC 2142 role mailboxes (`abuse`, `security`, `support`, `noc`) [46], automated senders (`noreply`, `mailer-daemon`), and top-level URL paths that are really files (`robots.txt`, `favicon.ico`, `crossdomain.xml`, `.well-known`). django-registration ships this list as `DEFAULT_RESERVED_NAMES` (BSD-3-Clause), adds `keybase.txt` and Bluesky's `xrpc`, and rejects anything starting with `.well-known` [19].

**Route words.** GitLab publishes its reserved top-level names (`admin`, `api`, `dashboard`, `explore`, `groups`, `help`, `login`, `oauth`, `profile`, `projects`, `search`, `users`, `-`, ...) [11]. Discourse asks the Rails router whether `/u/<name>` resolves to anything other than the profile page [10], and ships default reserved names including `admin`, `moderator`, `system`, `you`, `all`, `here` [7]. For a multi-app platform the reserved set must be recomputed when an app is added, because a new app's slug or route can collide with an existing user's handle.

**General lists.**
- `shouldbee/reserved-usernames`: MIT, ~600 entries in txt/json/csv/sql/php, last commit May 2023 [47].
- `marteinn/The-Big-Username-Blocklist`: MIT, ~560 entries in six categories (privileges, code words such as `null`/`void`, technical terms, financial, site sections, actions), Python and JS packages, last commit Oct 2021; excludes profanity by design [20].
- `Mottie/github-reserved-names`: MIT, GitHub's own route names; the maintainer says it is not complete [48].

Lists are starting points; none covers `me`, `you`, `undefined` and the platform's own app names at once, so merge and add.

**Impersonation.** X reserves handles containing "X" or "Admin" for official accounts [21]; Mastodon's admin blocklist supports "equals" and "contains" rules, compared after mapping digits to look-alike letters [15]. Apply the substring rule only to a short list (staff words and brand names); a long substring list produces false positives.

**Offensive names.** The standard multilingual list is LDNOOBW (Shutterstock), 27 languages, CC-BY-4.0 (attribution required), built for autocomplete suppression and openly subjective [49]. Substring matching causes the Scunthorpe problem: AOL blocked Scunthorpe residents in 1996, Hotmail blocked the surname Cockburn in 2004, Verizon blocked Libshitz in 2008 [22]. The JS library `obscenity` (MIT, active) shows a better design: patterns with word-boundary anchors, "transformers" that undo leetspeak and look-alike characters, and an explicit allowlist [50]. For handles: split on `-`, match whole tokens against the list after the `sim_key` map (which undoes basic leetspeak), match substrings only for a short list of unambiguous slurs, keep an allowlist, and send hits to moderation rather than hard-rejecting (Discourse's `require_approval` action [10]).

## 4. Squatting and renames

**GitHub.** After a username change the old name "becomes available for anyone else to claim"; repository URLs redirect until the new owner of the old name creates a repository with the same name, which silently overrides the redirect; profile links, @mentions and gist URLs are not redirected [2]. That is repojacking: an attacker registers the abandoned name, recreates the repository, and serves code to anyone still fetching the old URL [3]. GitHub's mitigation retires an owner/repository pair when the repository had more than 100 clones at rename time; Checkmarx reported bypasses of that rule, one through repository transfer, fixed in September 2022 [23]. A deleted account's name is held for 90 days [24]. GitHub forbids squatting, does not release names for inactivity, and reviews release requests only for trademark claims [25].

**X / Twitter.** X asks users to log in every 30 days and may remove inactive accounts, while its help text says usernames cannot currently be released [51]. In October 2025 it opened a paid "Handle Marketplace" redistributing inactive handles to Premium+ and Premium Business subscribers, without disclosing how inactivity is decided [52]. In 2023 it took the `@x` handle from its owner without notice [53]. The old-handle hijack risk is the same as GitHub's: a journalist reported in 2014 that after she changed handle an impersonator took the old one, and links across the web kept pointing to it [54] (reported via secondary search; not read in full).

**Reddit and Instagram.** Reddit usernames are reported to be permanent once chosen (exceptions for auto-generated names); Instagram is reported to allow renames with a 14-day window to revert. Both help centres refused automated reading, so these are unverified [30] [9].

**Discourse.** Renames are allowed only within `username_change_period` days after registration, default 3; 0 disables renames [7].

**Rules for the platform.**
- Every handle ever assigned stays in the namespace table with `state ∈ {active, retired, reserved}` and the owning user ID. A rename inserts the new key and flips the old row to `retired` in one transaction.
- `retired` rows redirect to the owner's current handle and can be reclaimed only by that owner. Default: never released (configurable to a quarantine of at least 90 days, mirroring GitHub's deletion hold).
- Rate limit: one rename per 30 days per account, configurable (no source sets this number; it bounds churn and the size of the retired set).
- No inactivity reclamation; administrative transfer only for a verified trademark claim, and logged.

## 5. Uniqueness races

**The failure.** Validate-then-insert (`SELECT ... WHERE lower(name) = ?` followed by `INSERT`) is a time-of-check/time-of-use race [29]: two sign-ups both see "free" and both insert. Framework validators of this kind (django-registration's `CaseInsensitiveUnique` [19], Mastodon's `UniqueUsernameValidator` [55]) are fine for an early error message but are not the guarantee. Mastodon's 2018 migration that created the unique index on `lower(username), lower(domain)` first had to "irreversibly delete user accounts with duplicate usernames" [4].

**SQL.** Store the canonical key in its own column with a `UNIQUE` constraint (or a unique expression index), and claim with `INSERT ... ON CONFLICT (handle_key) DO NOTHING RETURNING id`; zero rows returned means the name was taken. PostgreSQL documents unique-index inference on columns or expressions for the conflict target and an atomic outcome under concurrency for `DO UPDATE` [26]. Alternatives: a nondeterministic ICU collation (`und-u-ks-level2`), which PostgreSQL warns costs performance and blocks some pattern matching [56]. Do not rely on SQLite `COLLATE NOCASE`: it folds only the 26 ASCII letters [57]. An explicit canonical column is portable and testable.

**Key-value stores.** If the registry is a mapping `handle_key → user_id`, the claim must be a create-if-absent primitive, not `store[key] = uid` after `key in store`. File backend: `os.open(path, O_CREAT | O_EXCL)`, which fails with `EEXIST` if the file exists (not reliable on NFS without v3+) [27]. S3: `PutObject` with `If-None-Match: *`; when several writers race, the first to finish wins and the others get `412 Precondition Failed` [28].

**One namespace.** Users, reserved names and retired handles live under the same unique key; otherwise a rename and a sign-up can race across two tables. The similarity key (`sim_key` or skeleton) is a second, non-unique index checked before the claim; the remaining race window only lets two near-identical names through, which a moderator can fix, while the unique key is never violated.

**When two sign-ups collide.** The loser's request fails at the claim step; return `409` with three suggestions (the name plus a short suffix, checked for availability) and keep the rest of the form filled. In a verify-first flow, claim the handle when the account is created, or hold a reservation row with an expiry so the name is not lost while the user reads the verification email.

## What could not be verified

- X's, Reddit's and Instagram's help centres returned 403 or stripped content to automated fetches; their rules above come from search snippets of the official page (X) or secondary guides (Reddit, Instagram).
- GitHub's and X's case behaviour is common knowledge but not stated in any page read here. GitLab's username length limit was not found in its current docs.
- The 2014 handle-hijack report [54] and the 2023 `@x` takeover [53] were seen only through search results.
- The idempotence counter-example and the `precis_i18n` / ICU behaviour are this report's own tests (Python 3.11.14, Unicode 14.0; `precis_i18n` 1.1.2; `pyicu-binary` 2.7.4 with ICU 74.2), not published results.

## REFERENCES

1. [Spotify Engineering, "Creative usernames and Spotify account hijacking" (2013)](https://engineering.atspotify.com/2013/6/creative-usernames)
2. [GitHub Docs, "Username changes"](https://docs.github.com/en/account-and-profile/concepts/username-changes)
3. [GitHub Blog, "Repo-jacking explained: how it works and how to protect your GitHub projects" (2024, updated 2026)](https://github.blog/security/supply-chain-security/how-to-stay-safe-from-repo-jacking/)
4. [Mastodon, migration 20180528141303_fix_accounts_unique_index.rb](https://github.com/mastodon/mastodon/blob/main/db/migrate/20180528141303_fix_accounts_unique_index.rb)
5. [Slack developer changelog, "The one about usernames" (September 2017)](https://docs.slack.dev/changelog/2017-09-the-one-about-usernames)
6. [shinnn/github-username-regex (README and regex)](https://github.com/shinnn/github-username-regex)
7. [Discourse, config/site_settings.yml](https://github.com/discourse/discourse/blob/main/config/site_settings.yml)
8. [Mastodon, app/models/account.rb](https://github.com/mastodon/mastodon/blob/main/app/models/account.rb)
9. [Linktree, "How to change your Instagram handle" (secondary source); official article: Instagram Help Centre 583107688369069](https://linktr.ee/blog/how-to-change-instagram-handle)
10. [Discourse, app/models/username_validator.rb](https://github.com/discourse/discourse/blob/main/app/models/username_validator.rb)
11. [GitLab Docs, "Reserved project and group names"](https://docs.gitlab.com/user/reserved_names/)
12. [G. Thomas, "Names to reserve" (2015)](https://ldpreload.com/blog/names-to-reserve)
13. [PyPI Warehouse, migration d18d443f89f0 "ultranormalize_name function" (2021)](https://github.com/pypi/warehouse/blob/main/warehouse/migrations/versions/d18d443f89f0_ultranormalize_name_function.py)
14. [npm blog, "New package moniker rules" (December 2017)](https://blog.npmjs.org/post/168978377570/new-package-moniker-rules)
15. [Mastodon, app/models/username_block.rb](https://github.com/mastodon/mastodon/blob/main/app/models/username_block.rb)
16. [RFC 8265, PRECIS: Usernames and Passwords (2017)](https://www.rfc-editor.org/rfc/rfc8265.html)
17. [byllyfish/precis_i18n](https://github.com/byllyfish/precis_i18n)
18. [Unicode Technical Standard #39, Unicode Security Mechanisms (v18.0.0, 2026)](https://www.unicode.org/reports/tr39/)
19. [django-registration, src/django_registration/validators.py](https://github.com/ubernostrum/django-registration/blob/trunk/src/django_registration/validators.py)
20. [marteinn/The-Big-Username-Blocklist](https://github.com/marteinn/The-Big-Username-Blocklist)
21. [X Help Center, "Help with username registration"](https://help.x.com/en/managing-your-account/x-username-rules)
22. [Wikipedia, "Scunthorpe problem"](https://en.wikipedia.org/wiki/Scunthorpe_problem)
23. [Checkmarx, "Attacking the software supply chain with a simple rename" (2022)](https://checkmarx.com/blog/attacking-the-software-supply-chain-with-a-simple-rename/)
24. [GitHub Docs, "Personal account reference"](https://docs.github.com/en/account-and-profile/reference/personal-account-reference)
25. [GitHub Docs, "GitHub Username Policy"](https://docs.github.com/en/site-policy/other-site-policies/github-username-policy)
26. [PostgreSQL documentation, INSERT (ON CONFLICT)](https://www.postgresql.org/docs/current/sql-insert.html)
27. [Linux man-pages, open(2)](https://man7.org/linux/man-pages/man2/open.2.html)
28. [AWS, Amazon S3 User Guide, "How to prevent object overwrites with conditional writes"](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
29. [MITRE, CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
30. [MakeUseOf, "How to change your Reddit username" (secondary source)](https://www.makeuseof.com/how-to-change-reddit-username-rules/)
31. [Mastodon, db/schema.rb](https://github.com/mastodon/mastodon/blob/main/db/schema.rb)
32. [Discourse, app/models/user.rb (normalize_username)](https://github.com/discourse/discourse/blob/main/app/models/user.rb)
33. [npm/validate-npm-package-name](https://github.com/npm/validate-npm-package-name)
34. [PyPA, "Names and normalization" specification](https://packaging.python.org/en/latest/specifications/name-normalization/)
35. [PyPI Warehouse, warehouse/accounts/forms.py](https://github.com/pypi/warehouse/blob/main/warehouse/accounts/forms.py)
36. [ICU4C API, uspoof.h (SpoofChecker)](https://unicode-org.github.io/icu-docs/apidoc/released/icu4c/uspoof_8h.html)
37. [Unicode Standard Annex #15, Unicode Normalization Forms (v18.0.0, 2026)](https://www.unicode.org/reports/tr15/)
38. [Unicode Standard Annex #31, Unicode Identifiers and Syntax (v18.0.0, 2026)](https://www.unicode.org/reports/tr31/)
39. [Python documentation, str.casefold](https://docs.python.org/3/library/stdtypes.html#str.casefold)
40. [Unicode Character Database, CaseFolding.txt (18.0.0)](https://www.unicode.org/Public/UCD/latest/ucd/CaseFolding.txt)
41. [J. Bennett, "Truths programmers should know about case" (2018, updated 2020)](https://www.b-list.org/weblog/2018/nov/26/case/)
42. [Unicode, confusables.txt (security data)](https://www.unicode.org/Public/security/latest/confusables.txt)
43. [PyICU on PyPI](https://pypi.org/project/PyICU/)
44. [vhf/confusable_homoglyphs (archived; maintained at sr.ht/~valhalla)](https://github.com/vhf/confusable_homoglyphs)
45. [kjd/idna](https://github.com/kjd/idna)
46. [RFC 2142, Mailbox Names for Common Services, Roles and Functions (1997)](https://www.rfc-editor.org/rfc/rfc2142)
47. [shouldbee/reserved-usernames](https://github.com/shouldbee/reserved-usernames)
48. [Mottie/github-reserved-names](https://github.com/Mottie/github-reserved-names)
49. [LDNOOBW, List of Dirty, Naughty, Obscene, and Otherwise Bad Words](https://github.com/LDNOOBW/List-of-Dirty-Naughty-Obscene-and-Otherwise-Bad-Words)
50. [jo3-l/obscenity](https://github.com/jo3-l/obscenity)
51. [X Help Center, "Inactive account policy"](https://help.x.com/en/rules-and-policies/inactive-twitter-accounts.html)
52. [TechCrunch, "X to launch marketplace for buying inactive handles" (October 2025)](https://techcrunch.com/2025/10/20/x-to-launch-marketplace-for-buying-inactive-handles/)
53. [TechCrunch, "Twitter, now X, took over the @x handle without warning or compensating its owner" (July 2023)](https://techcrunch.com/2023/07/26/twitter-now-x-took-over-the-x-handle-without-warning-or-compensating-its-owner/)
54. [S. Sorcher, Christian Science Monitor, "How I learned to stop worrying and love the Twitterbot" (December 2014)](https://www.csmonitor.com/Technology/Tech/2014/1201/How-I-learned-to-stop-worrying-and-love-the-Twitterbot)
55. [Mastodon, app/validators/unique_username_validator.rb](https://github.com/mastodon/mastodon/blob/main/app/validators/unique_username_validator.rb)
56. [PostgreSQL documentation, Collation support (nondeterministic collations)](https://www.postgresql.org/docs/current/collation.html)
57. [SQLite, "Datatypes In SQLite" (collating sequences)](https://www.sqlite.org/datatype3.html)
