# enlace_auth.passkeys.texts

The passkey screens’ copy and notification mails, in English and French.

Same shape as [`enlace_auth.signup.texts`](enlace_auth.signup.texts.html.md#module-enlace_auth.signup.texts): `t(lang, key, **fields)`, with
English as the fallback for a missing language or key.

### Functions

| [`t`](#enlace_auth.passkeys.texts.t)(lang, key, \*\*fields)   | The text *key* in *lang* (English when missing), with *fields* filled in.   |
|-----------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| [`texts_for`](#enlace_auth.passkeys.texts.texts_for)(lang, keys)      | `{key: text}` for the client script of a page.                              |

### enlace_auth.passkeys.texts.t(lang, key, \*\*fields)

The text *key* in *lang* (English when missing), with *fields* filled in.

```pycon
>>> t("fr", "remove"), t("de", "remove")
('Supprimer', 'Remove')
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.passkeys.texts.texts_for(lang, keys)

`{key: text}` for the client script of a page.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]
