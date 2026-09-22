# enlace_auth.auth.pages

HTML pages for the enlace_auth browser-facing flows.

Single source of truth for the auth UI: the sign-in page, the account page
(change your own password), the password-recovery pages, and a generic notice
page. Pages are returned as plain HTML strings — the
same inline-HTML, no-build-step pattern used elsewhere in enlace
(`enlace.frontend._NOT_FOUND_PAGE`). All pages share one dark, minimal
stylesheet so the platform feels consistent from the very first unauthenticated
screen.

`PlatformAuthMiddleware` 303-redirects a blocked browser navigation to
`/auth/login?login_required=1&next=<path>`; [`render_login_page()`](#enlace_auth.auth.pages.render_login_page) is the
page that redirect lands on, and it threads `next` back through after sign-in.

### Functions

| [`fill_template`](#enlace_auth.auth.pages.fill_template)(template, /, \*\*values)             | Fill `{name}` placeholders in *template* with HTML-escaped *values*.   |
|-----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| [`render_account_page`](#enlace_auth.auth.pages.render_account_page)(\*, email[, error])            | Render the signed-in user's "change my password" form.                 |
| [`render_forgot_page`](#enlace_auth.auth.pages.render_forgot_page)(\*[, error, ...])               | Render the "request a password-reset link" form.                       |
| [`render_login_page`](#enlace_auth.auth.pages.render_login_page)(\*[, next_url, error, ...])      | Render the sign-in form.                                               |
| [`render_notice_page`](#enlace_auth.auth.pages.render_notice_page)(\*, title, heading, ...[, ...]) | Render a centered notice card.                                         |
| [`render_reset_page`](#enlace_auth.auth.pages.render_reset_page)(\*, token[, error])              | Render the "set a new password" form for a reset `token`.              |
| [`render_shared_login_page`](#enlace_auth.auth.pages.render_shared_login_page)(\*, app[, next_url, ...]) | Render the shared-password form for a `protected:shared` app.          |
| [`safe_next`](#enlace_auth.auth.pages.safe_next)(raw, \*[, default])                      | Return a same-origin path safe to redirect to, or `default`.           |

### enlace_auth.auth.pages.fill_template(template, , \*\*values)

Fill `{name}` placeholders in *template* with HTML-escaped *values*.

The escaping boundary for any page that interpolates request- or
user-supplied data into HTML. Escaping happens **here**, once, rather than
at each interpolation site: a value cannot reach the markup without passing
through [`html.escape()`](https://docs.python.org/3/library/html.html#html.escape), so a placeholder added later is safe by
construction instead of by the author remembering. Note that `_page()`
escapes only the page *title* — the body it receives is inserted verbatim,
so a body built by string interpolation must come through this function.

`quote=True` covers both sinks used here: element text, and attribute
values in either quote style.

*template* is trusted, static markup and must contain no literal braces
other than its placeholders ([`str.format()`](https://docs.python.org/3/builtins/stdtypes.html#str.format) rules apply). Compose a
page from several `fill_template` results rather than leaving an
un-escaped hole in one big template.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

```pycon
>>> fill_template('<input value="{v}">', v='" onx=1')
'<input value="&quot; onx=1">'
```

Only *values* are escaped; the template’s own markup passes through as-is:

```pycon
>>> fill_template("<p>{who} &amp; {what}</p>", who="a<b", what="c>d")
'<p>a&lt;b &amp; c&gt;d</p>'
```

### enlace_auth.auth.pages.render_account_page(, email, error=None)

Render the signed-in user’s “change my password” form.

Posts to `/auth/me/password`, which requires the *current* password —
so this page is safe to leave reachable on a shared machine: possession of
a live session alone doesn’t let someone change the password out from
under the owner.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.pages.render_forgot_page(, error=None, email_delivery_configured=True)

Render the “request a password-reset link” form.

* **Parameters:**
  * **error** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]) – optional error banner.
  * **email_delivery_configured** ([`bool`](https://docs.python.org/3/builtins/functions.html#bool)) – whether the platform has a mail sender
    wired. When it does not, the page says so and points at the admin
    instead of inviting the user to watch an inbox nothing will arrive
    in. This is a property of the deployment, not of any account, so
    showing it leaks nothing about who is registered — the *submit*
    response stays identical either way.
* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.pages.render_login_page(, next_url='/', error=None, show_register_hint=True)

Render the sign-in form.

* **Parameters:**
  * **next_url** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – where to send the browser after a successful login. Already
    sanitized by the caller via [`safe_next()`](#enlace_auth.auth.pages.safe_next).
  * **error** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]) – optional error banner (e.g. a stale-session note).
  * **show_register_hint** ([`bool`](https://docs.python.org/3/builtins/functions.html#bool)) – whether to show the “ask an admin” footnote.
* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.pages.render_notice_page(, title, heading, message, links, wide=False)

Render a centered notice card.

* **Parameters:**
  * **title** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – `<title>` text.
  * **heading** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – the card’s `<h1>`.
  * **message** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – a sentence or two of explanation (HTML-escaped here).
  * **links** ([`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`tuple`](https://docs.python.org/3/builtins/stdtypes.html#tuple)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`bool`](https://docs.python.org/3/builtins/functions.html#bool)]]) – `(label, href, is_primary)` tuples rendered as a row of
    actions; primary links get the filled-button style.
  * **wide** ([`bool`](https://docs.python.org/3/builtins/functions.html#bool)) – use the wider card (for longer content).
* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.pages.render_reset_page(, token, error=None)

Render the “set a new password” form for a reset `token`.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.pages.render_shared_login_page(, app, next_url='/', error=None)

Render the shared-password form for a `protected:shared` app.

Unlike [`render_login_page()`](#enlace_auth.auth.pages.render_login_page) this asks for a single shared password
(no email) and posts to `/auth/shared-login` with the `app` id, so a
browser hitting a password-gated app with no frontend has something to
fill in.

* **Parameters:**
  * **app** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – the app id whose shared password is being entered. Shown to the
    user and threaded into the POST body.
  * **next_url** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – where to send the browser after success. Already sanitized
    by the caller via [`safe_next()`](#enlace_auth.auth.pages.safe_next).
  * **error** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]) – optional error banner.
* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.pages.safe_next(raw, , default='/')

Return a same-origin path safe to redirect to, or `default`.

Guards against open-redirect: only local absolute paths are accepted —
no scheme, no `//host` form, no control characters. This is applied to
every `?next=` value before it reaches a page or a redirect.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)
