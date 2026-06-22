import json
from modules.etherscan import analyze_wallet, get_transactions, get_balance

TEST_WALLET = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"

def print_section(title: str):
    print("\n" + "=" * 55)
    print(f"  {title}")
    print("=" * 55)

def test_basic_connection():
    print_section("TEST 1: Basic API connection")
    balance = get_balance(TEST_WALLET)
    print(f"  Wallet  : {TEST_WALLET}")
    print(f"  Balance : {balance} ETH")
    if balance is not None:
        print("  RESULT  : PASS — Etherscan API is reachable")
    else:
        print("  RESULT  : FAIL — check your API key in .env")

def test_transactions():
    print_section("TEST 2: Fetch transactions")
    txs = get_transactions(TEST_WALLET, limit=5)
    print(f"  Fetched {len(txs)} transactions (requested 5)")

    if txs:
        print("\n  Most recent transaction:")
        tx = txs[0]
        eth_value = int(tx.get("value", 0)) / 1e18
        print(f"    Hash   : {tx.get('hash', 'N/A')[:20]}...")
        print(f"    From   : {tx.get('from', 'N/A')[:20]}...")
        print(f"    To     : {tx.get('to', 'N/A')[:20]}...")
        print(f"    Value  : {round(eth_value, 6)} ETH")
        print(f"    Time   : Unix {tx.get('timeStamp', 'N/A')}")
        print("  RESULT  : PASS")
    else:
        print("  RESULT  : No transactions found (wallet may be empty or API issue)")

def test_full_analysis():
    print_section("TEST 3: Full wallet analysis")
    result = analyze_wallet(TEST_WALLET)

    print(f"\n  Address         : {result['address'][:20]}...")
    print(f"  Balance         : {result['balance_eth']} ETH")
    print(f"  Is contract     : {result['contract_info']['is_contract']}")
    if result['contract_info']['deployer']:
        print(f"  Deployed by     : {result['contract_info']['deployer'][:20]}...")
    print(f"  Transactions    : {len(result['transactions'])}")
    print(f"  Connected wallets: {len(result['connected_addresses'])}")

    impact = result['impact']
    print(f"\n  --- Victim Impact ---")
    print(f"  Total ETH received : {impact['total_eth_received']} ETH")
    print(f"  Unique senders     : {impact['unique_senders']} (victim estimate)")
    print(f"  Days active        : {impact['days_active']}")

    print("\n  RESULT  : PASS — full analysis working")
    return result

def test_graph_nodes(result: dict):
    print_section("TEST 4: Graph-ready output check")
    print("  These are the nodes your graph will draw:\n")

    print(f"  NODE [wallet] : {result['address'][:20]}...")

    if result['contract_info']['deployer']:
        print(f"  NODE [deployer]: {result['contract_info']['deployer'][:20]}...")
        print(f"  EDGE : deployer → wallet (deployed)")

    for addr in result['connected_addresses'][:5]:
        print(f"  NODE [wallet]  : {addr[:20]}...")
        print(f"  EDGE : wallet ↔ {addr[:12]}... (transacted)")

    print(f"\n  Total nodes ready: {len(result['connected_addresses']) + 1}")
    print("  RESULT  : PASS — ready for graph_builder.py on Day 7")

if __name__ == "__main__":
    print("\n  CRYPTO SCAM MAPPER — Day 1 Test")
    print("  Make sure your .env file has ETHERSCAN_KEY set\n")

    test_basic_connection()
    test_transactions()
    result = test_full_analysis()
    test_graph_nodes(result)

    print("\n" + "=" * 55)
    print("  ALL TESTS COMPLETE")
    print("  If you see real data above, Day 1 is done.")
    print("  Next: Day 2 — build modules/crtsh.py")
    print("=" * 55 + "\n")