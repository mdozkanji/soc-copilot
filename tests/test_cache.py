from soc_copilot.enrich.cache import SqliteCache


def test_set_then_get_roundtrips(tmp_path):
    cache = SqliteCache(tmp_path / "cache.sqlite3")
    cache.set("k1", {"a": 1}, ttl_seconds=60)
    assert cache.get("k1") == {"a": 1}


def test_get_missing_key_returns_none(tmp_path):
    cache = SqliteCache(tmp_path / "cache.sqlite3")
    assert cache.get("nope") is None


def test_expired_entry_returns_none_and_is_deleted(tmp_path):
    cache = SqliteCache(tmp_path / "cache.sqlite3")
    cache.set("k1", {"a": 1}, ttl_seconds=-1)  # already expired
    assert cache.get("k1") is None
    # confirm it was actually deleted, not just skipped
    with cache._connect() as conn:
        row = conn.execute("SELECT 1 FROM cache WHERE cache_key = ?", ("k1",)).fetchone()
    assert row is None


def test_set_overwrites_existing_key(tmp_path):
    cache = SqliteCache(tmp_path / "cache.sqlite3")
    cache.set("k1", {"a": 1}, ttl_seconds=60)
    cache.set("k1", {"a": 2}, ttl_seconds=60)
    assert cache.get("k1") == {"a": 2}


def test_clear_removes_everything(tmp_path):
    cache = SqliteCache(tmp_path / "cache.sqlite3")
    cache.set("k1", {"a": 1}, ttl_seconds=60)
    cache.set("k2", {"a": 2}, ttl_seconds=60)
    cache.clear()
    assert cache.get("k1") is None
    assert cache.get("k2") is None


def test_cache_persists_across_instances(tmp_path):
    db_path = tmp_path / "cache.sqlite3"
    SqliteCache(db_path).set("k1", {"a": 1}, ttl_seconds=60)
    # a fresh instance pointed at the same file should see the same data
    assert SqliteCache(db_path).get("k1") == {"a": 1}
