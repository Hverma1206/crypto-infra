from modules.scamdb import check_artifact
from modules.web_mentions import analyze_web_presence


def test_scamdb():
    result = check_artifact("example.com")
    print("ScamDB:", result)
    assert "is_scam" in result


def test_web_mentions():
    result = analyze_web_presence(domain="example.com")
    print("Web mention count:", len(result["results"]))
    assert "results" in result


if __name__ == "__main__":
    test_scamdb()
    test_web_mentions()
    print("Day 5 PASS")
