# enlace_auth.signup.texts

What the sign-up flow says, in English and French: page text and emails.

Plain dictionaries, one per language, so a translation is a reviewable diff and
a missing key falls back to English rather than raising. [`pick_lang()`](#enlace_auth.signup.texts.pick_lang)
chooses from the request’s `Accept-Language` (or an explicit `lang`).

```pycon
>>> pick_lang("fr-FR,fr;q=0.9,en;q=0.8"), pick_lang("de, en;q=0.5"), pick_lang(None)
('fr', 'en', 'en')
>>> t("fr", "continue")
'Continuer avec mon e-mail'
```

### Functions

| [`code_email`](#enlace_auth.signup.texts.code_email)(lang, \*, code, link, site, minutes)   | `(subject, body)` of the mail carrying a sign-in code.                      |
|----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| [`delete_email`](#enlace_auth.signup.texts.delete_email)(lang, \*, code, site, minutes)       | `(subject, body)` of the mail confirming an account deletion.               |
| [`pick_lang`](#enlace_auth.signup.texts.pick_lang)(accept_language, \*[, explicit])        | The first supported language in *explicit*, else in `Accept-Language`.      |
| [`refused_email`](#enlace_auth.signup.texts.refused_email)(lang, \*, site)                     | `(subject, body)` of the mail to an address the policy does not admit.      |
| [`t`](#enlace_auth.signup.texts.t)(lang, key, \*\*values)                          | The *key* string in *lang* (English when missing), formatted with *values*. |

### enlace_auth.signup.texts.code_email(lang, , code, link, site, minutes)

`(subject, body)` of the mail carrying a sign-in code.

* **Return type:**
  [`tuple`](https://docs.python.org/3/builtins/stdtypes.html#tuple)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.signup.texts.delete_email(lang, , code, site, minutes)

`(subject, body)` of the mail confirming an account deletion.

* **Return type:**
  [`tuple`](https://docs.python.org/3/builtins/stdtypes.html#tuple)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.signup.texts.pick_lang(accept_language, , explicit=None)

The first supported language in *explicit*, else in `Accept-Language`.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.signup.texts.refused_email(lang, , site)

`(subject, body)` of the mail to an address the policy does not admit.

* **Return type:**
  [`tuple`](https://docs.python.org/3/builtins/stdtypes.html#tuple)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.signup.texts.t(lang, key, \*\*values)

The *key* string in *lang* (English when missing), formatted with *values*.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)
