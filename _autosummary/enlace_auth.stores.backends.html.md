# enlace_auth.stores.backends

MutableMapping-backed store factories for enlace.

The file backend is the MVP default: one directory per named store under a
platform root (`~/.enlace/platform_store/` by default). Values are JSON.

When `dol` is installed (via `enlace[auth]`), `make_file_store_factory`
uses `dol.Files` + a JSON codec. When it isn’t, we fall back to a tiny
stdlib implementation so the core package keeps working.

### Functions

| [`make_file_store_factory`](#enlace_auth.stores.backends.make_file_store_factory)(root, \*[, use_dol])   | Return a `StoreFactory` backed by JSON files under `root`.   |
|-------------------------------------------------------------------------------------------------|--------------------------------------------------------------|

### enlace_auth.stores.backends.make_file_store_factory(root, , use_dol=False)

Return a `StoreFactory` backed by JSON files under `root`.

`factory(name)` returns a `MutableMapping` rooted at `root/name/`.

Defaults to a small stdlib implementation that auto-creates parent
directories on write. Pass `use_dol=True` to use `dol.Files` instead
(pulls in the soft dep and expects flat keys).

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)]
