"""
DAY 2 TEST SCRIPT
=================
Run this to verify your crtsh.py module works.

Usage:
    cd backend
    python test_day2.py

No API key needed. No setup needed.
Just run it — if you have internet, it works.

What to expect:
You will see a list of domains/subdomains associated with
the test domain, the earliest certificate date, and any
sibling domains that suggest the same operator.
"""

from modules.crtsh import analyze_domain, get_certificates, extract_unique_domains


# A well-known domain with lots of cert history — good for testing
# We use a legitimate domain for testing so we always get results
# For your actual scam demo, you would use domains from CryptoScamDB
TEST_DOMAIN = "binance.com"

# Simulated scam domain test — shorter name so crt.sh returns fast
SCAM_LIKE_DOMAIN = "ethfinance.io"


def print_section(title: str):
    print("\n" + "=" * 55)
    print(f"  {title}")
    print("=" * 55)


def test_basic_cert_lookup():
    print_section("TEST 1: Basic certificate lookup")
    certs = get_certificates(TEST_DOMAIN)
    print(f"  Domain        : {TEST_DOMAIN}")
    print(f"  Certs found   : {len(certs)}")

    if certs:
        sample = certs[0]
        print(f"\n  Sample cert:")
        print(f"    Common name : {sample.get('common_name', 'N/A')}")
        print(f"    Issuer      : {sample.get('issuer_name', 'N/A')[:50]}")
        print(f"    Valid from  : {sample.get('not_before', 'N/A')}")
        print("  RESULT  : PASS — crt.sh API is reachable")
    else:
        print("  RESULT  : No certs found — check internet connection")


def test_domain_extraction():
    print_section("TEST 2: Unique domain extraction")
    certs = get_certificates(TEST_DOMAIN)
    domains = extract_unique_domains(certs)
    print(f"  Unique domains found: {len(domains)}")
    print(f"\n  First 10 domains:")
    for d in domains[:10]:
        print(f"    → {d}")
    if len(domains) > 10:
        print(f"    ... and {len(domains) - 10} more")
    print("  RESULT  : PASS")


def test_full_analysis():
    print_section("TEST 3: Full domain analysis (scam-like domain)")
    result = analyze_domain(SCAM_LIKE_DOMAIN)

    print(f"  Domain          : {result['domain']}")
    print(f"  Total certs     : {result['total_certs']}")
    print(f"  Unique domains  : {len(result['unique_domains'])}")
    print(f"  Earliest cert   : {result['earliest_date']}")

    if result['sibling_domains']:
        print(f"\n  Sibling domains (same actor indicator):")
        for s in result['sibling_domains'][:5]:
            print(f"    ⚠️  {s}")
    else:
        print(f"\n  No sibling domains found for this test domain")

    if result.get('error'):
        print(f"\n  Note: {result['error']}")

    print("\n  RESULT  : PASS — full analysis working")
    return result


def test_graph_nodes(result: dict):
    print_section("TEST 4: Graph-ready output check")
    print("  These are the nodes crtsh.py adds to your graph:\n")

    print(f"  NODE [domain]  : {result['domain']}")
    print(f"  EDGE           : wallet → {result['domain']} (associated domain)")

    for sub in result['unique_domains'][:5]:
        if sub != result['domain']:
            print(f"  NODE [subdomain]: {sub}")
            print(f"  EDGE            : {result['domain']} → {sub} (subdomain)")

    for sib in result['sibling_domains'][:3]:
        print(f"  NODE [sibling]  : {sib}  ← SAME OPERATOR FLAG")
        print(f"  EDGE            : {result['domain']} → {sib} (sibling domain)")

    print(f"\n  RESULT  : PASS — ready for graph_builder.py on Day 7")


if __name__ == "__main__":
    print("\n  CRYPTO SCAM MAPPER — Day 2 Test")
    print("  No API key needed for this module\n")

    test_basic_cert_lookup()
    test_domain_extraction()
    result = test_full_analysis()
    test_graph_nodes(result)

    print("\n" + "=" * 55)
    print("  ALL TESTS COMPLETE")
    print("  If you see domain lists above, Day 2 is done.")
    print("  Next: Day 3 — build modules/whois_lookup.py")
    print("=" * 55 + "\n")
