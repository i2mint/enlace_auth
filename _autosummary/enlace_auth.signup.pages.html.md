# enlace_auth.signup.pages

Markup for the sign-up flow: the “continue with email” step, the link page,
and the account-deletion card.

Every dynamic value reaches the markup through
[`enlace_auth.auth.pages.fill_template()`](enlace_auth.auth.pages.html.md#enlace_auth.auth.pages.fill_template) (HTML) or `_js_string` (inline
script), the same escaping boundary as the rest of the auth pages. The step is
handed to [`render_login_page()`](enlace_auth.auth.pages.html.md#enlace_auth.auth.pages.render_login_page) as its
`email_section`; it carries its own script, which reuses the page’s
`postJSON` CSRF helper.

### Functions

| [`render_delete_section`](#enlace_auth.signup.pages.render_delete_section)(\*, lang, email)             | The account page's "delete my account" card: send a code, then confirm.   |
|-----------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| [`render_email_section`](#enlace_auth.signup.pages.render_email_section)(\*, lang, next_url, app, ...) | The "continue with email" step: address, then the 6-digit code.           |
| [`render_link_page`](#enlace_auth.signup.pages.render_link_page)(\*, lang)                         | The page an emailed link opens: one button that spends the token by POST. |

### enlace_auth.signup.pages.render_delete_section(, lang, email)

The account page’s “delete my account” card: send a code, then confirm.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.signup.pages.render_email_section(, lang, next_url, app, challenge, min_seconds, mode, code_minutes, terms_url=None, privacy_url=None, providers=())

The “continue with email” step: address, then the 6-digit code.

*mode* (the sign-up policy of *app*) picks the note under the form: an open
policy says who may sign up (15 and over), an invite or allowlist policy
says sign-up is by invitation, a closed one says accounts come from the
admin. *providers* are `(label, href)` pairs for external sign-in.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.signup.pages.render_link_page(, lang)

The page an emailed link opens: one button that spends the token by POST.

The token is in the URL fragment, which the browser never sends, so a GET of
this page (a mail scanner’s preview) spends nothing.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)
