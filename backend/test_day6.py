import cache


def test_cache():
    cache.set("unit", "sample", {"ok": True})
    result = cache.get("unit", "sample")
    print("Cached result:", result)
    print("Stats:", cache.get_stats())
    assert result == {"ok": True}


if __name__ == "__main__":
    test_cache()
    print("Day 6 PASS")
