"""PrefixedStore isolation and key-sanitization tests."""

import pytest

from enlace_auth.stores import PrefixedStore, sanitize_key


@pytest.mark.parametrize(
    "key",
    [
        "..",
        "../etc/passwd",
        "a/../b",
        "a\\b",
        "a\x00b",
        "\n",
        "/etc",
        ".hidden",
        "%2e%2e",
        "a%2fb",
        "",
    ],
)
def test_sanitize_key_rejects_attacks(key):
    with pytest.raises(ValueError):
        sanitize_key(key)


@pytest.mark.parametrize(
    "key",
    ["hello", "foo.json", "under_score", "dash-ok", "a/b/c", "with spaces"],
)
def test_sanitize_key_allows_safe(key):
    assert sanitize_key(key) == key


def test_prefix_isolation():
    base: dict = {}
    alice = PrefixedStore(base, "alice/chord/")
    bob = PrefixedStore(base, "bob/chord/")
    alice["song"] = {"title": "A"}
    bob["song"] = {"title": "B"}
    assert alice["song"]["title"] == "A"
    assert bob["song"]["title"] == "B"
    # Underlying keys are fully qualified.
    assert set(base.keys()) == {"alice/chord/song", "bob/chord/song"}


def test_prefixed_store_iteration_strips_prefix():
    base = {"alice/x/a": 1, "alice/x/b": 2, "bob/x/c": 3}
    s = PrefixedStore(base, "alice/x/")
    assert set(iter(s)) == {"a", "b"}
    assert len(s) == 2
    assert "a" in s and "c" not in s


def test_prefixed_store_delete():
    base = {"u/app/k": 1}
    s = PrefixedStore(base, "u/app/")
    del s["k"]
    assert "u/app/k" not in base


def test_prefixed_store_rejects_traversal_keys():
    s = PrefixedStore({}, "u/app/")
    with pytest.raises(ValueError):
        s["../../etc/passwd"] = 1
    with pytest.raises(ValueError):
        _ = s["../secret"]


def test_prefix_must_be_safe():
    with pytest.raises(ValueError):
        PrefixedStore({}, "../evil/")
    with pytest.raises(ValueError):
        PrefixedStore({}, "")


def test_nested_prefixed_store():
    base: dict = {}
    outer = PrefixedStore(base, "tenant/")
    inner = PrefixedStore(outer, "app/")
    inner["key"] = "value"
    assert base["tenant/app/key"] == "value"


# ---------------------------------------------------------------------- #
# File-store robustness (guards added after an OAuth security review)
# ---------------------------------------------------------------------- #


def test_membership_never_raises_on_a_hostile_key(tmp_path):
    """`in` is a predicate; an exception here turns a lookup into a 500."""
    from enlace_auth.stores.backends import make_file_store_factory

    store = make_file_store_factory(str(tmp_path))("codes")
    for hostile in ("../../etc/passwd", "..", "/abs", ".hidden", "a\x00b", ""):
        assert hostile not in store


def test_a_corrupt_record_is_a_miss_not_a_crash(tmp_path):
    """One truncated file used to 500 every request that touched the store."""
    from enlace_auth.stores.backends import make_file_store_factory

    root = tmp_path / "s"
    store = make_file_store_factory(str(root))("codes")
    store["good"] = {"a": 1}
    (root / "codes" / "broken").write_text("{not json")

    assert store["good"] == {"a": 1}
    with pytest.raises(KeyError):
        store["broken"]
    # and iterating/sweeping past it must not explode
    assert sorted(store) == ["broken", "good"]
