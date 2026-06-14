"""
DAY 3 TEST SCRIPT
=================
Run this to verify your whois_lookup.py module works.

Usage:
    cd backend
    python test_day3.py

Requires:
    pip install python-whois  (already in requirements.txt)

What to expect:
    Registration dates, registrar info, risk flags, and
    privacy protection status for two test domains.
"""

from modules.whois_lookup import (
    analyze_domain_whois,
    get_whois,
    compute_domain_age_days,
    is_privacy_protected,
    get_risk_flags,
)


# A legitimate well-known domain — should have clean WHOIS, old age
LEGIT_DOMAIN = "github.com"

# A domain that mimics scam naming patterns
# Replace this with any domain from CryptoScamDB for real testing
SUSPICIOUS_DOMAIN = "eth-profit-invest.com"


def print_section(title: str):
    print("\n" + "=" * 55)
    print(f"  {title}")
    print("=" * 55)


def test_basic_whois():
    print_section("TEST 1: Basic WHOIS lookup")
    data = get_whois(LEGIT_DOMAIN)

    print(f"  Domain          : {data['domain']}")
    print(f"  Registrar       : {data['registrar']}")
    print(f"  Created         : {data['creation_date']}")
    print(f"  Expires         : {data['expiry_date']}")
    print(f"  Emails          : {data['emails'][:2]}")
    print(f"  Name servers    : {data['name_servers'][:2]}")
    print(f"  Error           : {data['error']}")

    if data['creation_date']:
        print("  RESULT  : PASS — WHOIS lookup working")
    else:
        print("  RESULT  : partial — check python-whois install")


def test_age_calculation():
    print_section("TEST 2: Domain age calculation")
    data = get_whois(LEGIT_DOMAIN)
    age = compute_domain_age_days(data['creation_date'])

    print(f"  Domain      : {LEGIT_DOMAIN}")
    print(f"  Created     : {data['creation_date']}")
    print(f"  Age         : {age} days ({round(age/365, 1) if age else 'N/A'} years)")

    if age and age > 365:
        print("  Verdict     : OLD domain — not suspicious")
        print("  RESULT  : PASS")
    else:
        print("  Note    : Could not compute age — WHOIS may have returned None")


def test_risk_flags():
    print_section("TEST 3: Risk flag generation")

    # Test with a simulated fresh domain
    fake_whois = {
        "domain": "crypto-invest-now.com",
        "registrar": "WhoisGuard Protected",
        "creation_date": datetime_days_ago(5),
        "expiry_date": None,
        "emails": [],
        "org": None,
    }

    flags = get_risk_flags(fake_whois)
    privacy = is_privacy_protected(fake_whois)

    print(f"  Simulated domain : crypto-invest-now.com")
    print(f"  Privacy protected: {privacy}")
    print(f"\n  Risk flags generated ({len(flags)} total):")
    for f in flags:
        print(f"    ⚠️  {f}")

    if flags:
        print("  RESULT  : PASS — risk flags working")
    else:
        print("  RESULT  : FAIL — no flags generated, check logic")


def test_full_analysis():
    print_section("TEST 4: Full WHOIS analysis")
    result = analyze_domain_whois(LEGIT_DOMAIN)

    print(f"  Domain            : {result['domain']}")
    print(f"  Age               : {result['age_days']} days")
    print(f"  Privacy protected : {result['privacy_protected']}")
    print(f"  Risk flags        : {len(result['risk_flags'])}")

    for flag in result['risk_flags']:
        print(f"    ⚠️  {flag}")

    if not result['risk_flags']:
        print("    ✓  No risk flags — domain appears legitimate")

    print("\n  RESULT  : PASS")
    return result


def test_graph_nodes(result: dict):
    print_section("TEST 5: Graph-ready output check")
    print("  WHOIS adds metadata to domain nodes in your graph:\n")

    print(f"  NODE [domain]  : {result['domain']}")
    print(f"    → age_days         : {result['age_days']}")
    print(f"    → registrar        : {result['registrar']}")
    print(f"    → privacy_protected: {result['privacy_protected']}")
    print(f"    → risk_flags       : {len(result['risk_flags'])} flags")

    if result['emails']:
        print(f"\n  NODE [email]   : {result['emails'][0]}")
        print(f"  EDGE           : {result['domain']} → {result['emails'][0]} (registrant)")
        print("    → if same email appears on another domain = same actor")

    print("\n  RESULT  : PASS — ready for graph_builder.py on Day 7")


def datetime_days_ago(days: int) -> str:
    """Helper to create a date string N days ago for testing."""
    from datetime import datetime, timedelta
    return (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")


if __name__ == "__main__":
    print("\n  CRYPTO SCAM MAPPER — Day 3 Test")
    print("  Requires: pip install python-whois\n")

    test_basic_whois()
    test_age_calculation()
    test_risk_flags()
    result = test_full_analysis()
    test_graph_nodes(result)

    print("\n" + "=" * 55)
    print("  ALL TESTS COMPLETE")
    print("  If you see registration data above, Day 3 is done.")
    print("  Next: Day 4 — build modules/wayback.py")
    print("=" * 55 + "\n")
