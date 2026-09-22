# enlace_auth.appmeta

Editable app-metadata overlay: the write surface for the launcher.

enlace core owns the *read* model for launcher metadata (title / description /
keywords / icon) — it harvests app-declared values and serves `/_apps` and the
icon endpoint. But the *editable* layer — an owner-curated overlay of added
keywords and icon/title/description overrides, mutated live from the launcher UI
— needs authentication, CSRF, an admin allowlist, and durable per-app storage.
Those are exactly the concerns enlace core delegates to this plugin, so the
overlay lives here, mirroring the runtime-grants pattern
([`enlace_auth.auth.grants`](enlace_auth.auth.grants.md#module-enlace_auth.auth.grants)).

The contract with core is two dependency-injection slots on the parent app’s
`state` (read by core, written here):

- `app_meta_overlay`  — a `MutableMapping[str, dict]` of per-app overlay
  records; core reads it when resolving `/_apps` and the icon.
- `app_meta_can_edit` — `Callable[[Optional[str]], bool]` deciding whether
  an email may edit; core surfaces the result as `can_edit_meta`.

Without this plugin (or on an older enlace_auth), those slots default in core to
an empty overlay and “nobody can edit”, so the launcher still works read-only.

Overlay record schema (one JSON file per app under `<store>/app_meta/{name}`):

```default
{
  "keywords":     ["owner", "added", "tags"],  # additive; unioned by core
  "icon":         "emoji:🎸" | "assets/x.png" | null,
  "display_name": "Override Title" | null,
  "description":  "Override blurb" | null
}
```

Empty records are deleted, so “no overlay” and “empty overlay” coincide.

### Functions

| [`make_appmeta_can_edit`](#enlace_auth.appmeta.make_appmeta_can_edit)(editors)             | Build the `app_meta_can_edit` closure over a normalized editor set.                                                                          |
|---------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| [`make_appmeta_router`](#enlace_auth.appmeta.make_appmeta_router)(\*, apps, config, ...) | Build the `PATCH/DELETE /_apps/{name}/meta` router (CSRF-gated by the plugin's middleware, since `/_apps/*` is not in the CSRF-exempt list). |

### enlace_auth.appmeta.make_appmeta_can_edit(editors)

Build the `app_meta_can_edit` closure over a normalized editor set.

Case-insensitive; an empty editor set means *nobody* can edit (safe default,
so a misconfigured deploy fails closed rather than open).

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]], [`bool`](https://docs.python.org/3/builtins/functions.html#bool)]

### enlace_auth.appmeta.make_appmeta_router(, apps, config, overlay_store, can_edit)

Build the `PATCH/DELETE /_apps/{name}/meta` router (CSRF-gated by the
plugin’s middleware, since `/_apps/*` is not in the CSRF-exempt list).

Editor authz is enforced per request via `can_edit`. The app name is
validated against the known-apps set (unknown ⇒ 404), which also keeps the
store key confined to a real app name — defense-in-depth over the `[^/]+`
path convertor that already blocks traversal.

* **Return type:**
  `APIRouter`
