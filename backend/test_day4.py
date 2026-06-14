from modules.wayback import analyze_domain_wayback


def test_wayback():
    result = analyze_domain_wayback("github.com")
    print("Domain:", result["domain"])
    print("Available:", result["available"])
    print("Snapshots:", result["snapshot_count"])
    print("Timeline:", result["timeline"])
    assert result["domain"] == "github.com"
    assert "timeline" in result


if __name__ == "__main__":
    test_wayback()
    print("Day 4 PASS")
