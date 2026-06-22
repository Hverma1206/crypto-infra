"""
Deep Scan — Recursive wallet expansion.

Takes connected wallet addresses from an initial analysis and
runs analyze_wallet() on each one in parallel. Merges the new
nodes and edges into the existing graph. Checks each wallet
against CryptoScamDB.

This is the "one-click expand investigation" feature:
  1. User runs initial analysis on a suspicious wallet
  2. Initial analysis finds 10 connected wallets
  3. Deep Scan automatically investigates all 10
  4. Graph expands with new nodes, edges, and findings
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.etherscan import analyze_wallet
from modules.graph_builder import add_edge, add_node, shorten
from modules.scamdb import check_artifact

logger = logging.getLogger("deep_scan")

MAX_CONCURRENT = 5
MAX_WALLETS = 10


def scan_single_wallet(address: str) -> dict:
    """
    Analyze one connected wallet and check it against ScamDB.
    Returns a combined result dict.
    """
    try:
        wallet_data = analyze_wallet(address)
        scam_check = check_artifact(address)

        return {
            "address": address,
            "wallet_data": wallet_data,
            "scam_check": scam_check,
            "error": None,
        }
    except Exception as exc:
        logger.warning("Deep scan failed for %s: %s", address, exc)
        return {
            "address": address,
            "wallet_data": None,
            "scam_check": None,
            "error": str(exc),
        }


def deep_scan(
    original_analysis: dict,
    wallet_addresses: list[str],
) -> dict:
    """
    MAIN FUNCTION — call from app.py.

    Scans up to MAX_WALLETS connected wallets in parallel, then
    merges new nodes/edges into the existing graph.

    Parameters:
        original_analysis: The full analysis result from /analyze
        wallet_addresses: List of wallet addresses to deep scan

    Returns:
        Updated analysis dict with expanded graph + new findings
    """
    # Limit the number of wallets to scan
    addresses = list(set(wallet_addresses))[:MAX_WALLETS]
    logger.info("Deep scanning %d wallets", len(addresses))

    # Build a mutable copy of nodes/edges
    existing_nodes = {n["id"]: n for n in original_analysis.get("nodes", [])}
    existing_edges = list(original_analysis.get("edges", []))
    existing_findings = list(original_analysis.get("findings", []))

    new_nodes_count = 0
    new_edges_count = 0
    scan_results = []

    # Scan all wallets in parallel
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
        futures = {executor.submit(scan_single_wallet, addr): addr for addr in addresses}

        for future in as_completed(futures):
            result = future.result()
            scan_results.append(result)

            if result["error"] or not result["wallet_data"]:
                continue

            address = result["address"]
            wallet_data = result["wallet_data"]
            scam_check = result["scam_check"]
            wallet_id = f"wallet:{address.lower()}"

            # Update existing node with richer data
            add_node(existing_nodes, wallet_id, "wallet", shorten(address), {
                "deep_scanned": True,
                "balance_eth": wallet_data.get("balance_eth"),
                "impact": wallet_data.get("impact"),
            })

            # Add deployer if found
            contract = wallet_data.get("contract_info") or {}
            deployer = contract.get("deployer")
            if deployer:
                deployer_id = f"wallet:{deployer.lower()}"
                if deployer_id not in existing_nodes:
                    add_node(existing_nodes, deployer_id, "deployer", shorten(deployer), {
                        "address": deployer,
                        "source": "deep_scan",
                    })
                    new_nodes_count += 1
                add_edge(existing_edges, deployer_id, wallet_id, "deployed")
                new_edges_count += 1
                existing_findings.append(f"Deep scan: {shorten(address)} was deployed by {shorten(deployer)}")

            # Add connected addresses from this wallet
            for connected in (wallet_data.get("connected_addresses") or [])[:6]:
                connected_id = f"wallet:{connected.lower()}"
                if connected_id not in existing_nodes:
                    add_node(existing_nodes, connected_id, "wallet", shorten(connected), {
                        "address": connected,
                        "source": "deep_scan",
                    })
                    new_nodes_count += 1
                add_edge(existing_edges, wallet_id, connected_id, "transaction")
                new_edges_count += 1

            # ScamDB hit
            if scam_check and scam_check.get("is_scam"):
                flag_id = f"scamdb:{address.lower()}"
                add_node(existing_nodes, flag_id, "scamdb_flag", "Confirmed scam (deep scan)", scam_check)
                add_edge(existing_edges, wallet_id, flag_id, "confirmed by")
                new_nodes_count += 1
                new_edges_count += 1
                existing_findings.append(f"Deep scan: {shorten(address)} matched CryptoScamDB blacklist")

            # Impact findings
            impact = wallet_data.get("impact") or {}
            if impact.get("unique_senders", 0) >= 5:
                existing_findings.append(
                    f"Deep scan: {shorten(address)} received from {impact['unique_senders']} unique wallets"
                )

    # Build the updated result
    updated = dict(original_analysis)
    updated["nodes"] = list(existing_nodes.values())
    updated["edges"] = existing_edges
    updated["findings"] = existing_findings
    updated["deep_scan"] = {
        "wallets_scanned": len(addresses),
        "wallets_succeeded": sum(1 for r in scan_results if not r["error"]),
        "new_nodes": new_nodes_count,
        "new_edges": new_edges_count,
        "results": [
            {
                "address": r["address"],
                "balance_eth": (r["wallet_data"] or {}).get("balance_eth"),
                "impact": (r["wallet_data"] or {}).get("impact"),
                "is_scam": (r["scam_check"] or {}).get("is_scam", False),
                "error": r["error"],
            }
            for r in scan_results
        ],
    }

    logger.info(
        "Deep scan complete — scanned %d wallets, added %d nodes and %d edges",
        len(addresses),
        new_nodes_count,
        new_edges_count,
    )

    return updated
