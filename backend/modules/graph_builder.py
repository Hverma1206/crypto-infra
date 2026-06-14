from urllib.parse import urlparse


def build_graph(
    input_value: str,
    input_type: str,
    wallet_data: dict | None = None,
    crtsh_data: dict | None = None,
    whois_data: dict | None = None,
    wayback_data: dict | None = None,
    scamdb_data: dict | None = None,
    web_data: dict | None = None,
) -> dict:
    nodes = {}
    edges = []
    findings = []

    primary_id = f"{input_type}:{input_value.lower()}"
    add_node(nodes, primary_id, input_type, input_value, {"primary": True})

    if wallet_data:
        build_wallet_layer(nodes, edges, findings, wallet_data, primary_id)

    if crtsh_data:
        build_crtsh_layer(nodes, edges, findings, crtsh_data, primary_id)

    if whois_data:
        build_whois_layer(nodes, edges, findings, whois_data, primary_id)

    if wayback_data:
        build_wayback_layer(nodes, edges, findings, wayback_data, primary_id)

    if scamdb_data:
        build_scamdb_layer(nodes, edges, findings, scamdb_data, primary_id)

    if web_data:
        build_web_layer(nodes, edges, findings, web_data, primary_id)

    risk = compute_risk_score(wallet_data, whois_data, wayback_data, scamdb_data, web_data)

    return {
        "input": input_value,
        "input_type": input_type,
        "nodes": list(nodes.values()),
        "edges": edges,
        "findings": findings,
        "risk": risk,
        "summary": build_summary(wallet_data, crtsh_data, whois_data, wayback_data, scamdb_data, web_data),
    }


def add_node(nodes: dict, node_id: str, node_type: str, label: str, data: dict | None = None):
    if node_id not in nodes:
        nodes[node_id] = {"id": node_id, "type": node_type, "label": label, "data": data or {}}
    else:
        nodes[node_id]["data"].update(data or {})


def add_edge(edges: list, source: str, target: str, relation: str, data: dict | None = None):
    if source == target:
        return
    edge_id = f"{source}->{target}:{relation}"
    if any(edge["id"] == edge_id for edge in edges):
        return
    edges.append({"id": edge_id, "source": source, "target": target, "relation": relation, "data": data or {}})


def build_wallet_layer(nodes, edges, findings, wallet_data, primary_id):
    wallet = wallet_data.get("address")
    wallet_id = f"wallet:{wallet.lower()}"
    add_node(nodes, wallet_id, "wallet", shorten(wallet), wallet_data)
    if wallet_id != primary_id:
        add_edge(edges, primary_id, wallet_id, "wallet analysis")

    contract = wallet_data.get("contract_info") or {}
    deployer = contract.get("deployer")
    if contract.get("is_contract"):
        findings.append("Input wallet is a smart contract")
    if deployer:
        deployer_id = f"wallet:{deployer.lower()}"
        add_node(nodes, deployer_id, "deployer", shorten(deployer), {"address": deployer})
        add_edge(edges, deployer_id, wallet_id, "deployed")
        findings.append("Contract deployer wallet identified")

    for connected in (wallet_data.get("connected_addresses") or [])[:12]:
        connected_id = f"wallet:{connected.lower()}"
        add_node(nodes, connected_id, "wallet", shorten(connected), {"address": connected})
        add_edge(edges, wallet_id, connected_id, "transaction")

    impact = wallet_data.get("impact") or {}
    if impact.get("unique_senders"):
        findings.append(f"Estimated {impact['unique_senders']} unique sender wallets")


def build_crtsh_layer(nodes, edges, findings, data, primary_id):
    domain = data.get("domain")
    if not domain:
        return
    domain_id = f"domain:{domain.lower()}"
    add_node(nodes, domain_id, "domain", domain, data)
    add_edge(edges, primary_id, domain_id, "associated domain")

    for item in (data.get("unique_domains") or [])[:10]:
        item_id = f"domain:{item.lower()}"
        add_node(nodes, item_id, "subdomain", item, {"source": "crtsh"})
        add_edge(edges, domain_id, item_id, "certificate")

    for item in (data.get("sibling_domains") or [])[:8]:
        item_id = f"domain:{item.lower()}"
        add_node(nodes, item_id, "sibling_domain", item, {"source": "crtsh"})
        add_edge(edges, domain_id, item_id, "possible same operator")

    if data.get("sibling_domains"):
        findings.append(f"Found {len(data['sibling_domains'])} possible sibling domains")


def build_whois_layer(nodes, edges, findings, data, primary_id):
    domain = data.get("domain")
    if domain:
        domain_id = f"domain:{domain.lower()}"
        add_node(nodes, domain_id, "domain", domain, {"whois": data})
        add_edge(edges, primary_id, domain_id, "whois record")

    for email in (data.get("emails") or [])[:5]:
        email_id = f"email:{email.lower()}"
        add_node(nodes, email_id, "email", email, {"source": "whois"})
        if domain:
            add_edge(edges, f"domain:{domain.lower()}", email_id, "registrant")

    for flag in data.get("risk_flags") or []:
        findings.append(flag)


def build_wayback_layer(nodes, edges, findings, data, primary_id):
    domain = data.get("domain")
    if not domain:
        return
    domain_id = f"domain:{domain.lower()}"
    add_node(nodes, domain_id, "domain", domain, {"wayback": data})
    add_edge(edges, primary_id, domain_id, "archive lookup")

    closest = data.get("closest_snapshot") or {}
    if closest.get("url"):
        snapshot_id = f"snapshot:{closest['url']}"
        add_node(nodes, snapshot_id, "snapshot", "Wayback snapshot", closest)
        add_edge(edges, domain_id, snapshot_id, "archived page")

    for flag in data.get("risk_flags") or []:
        findings.append(flag)


def build_scamdb_layer(nodes, edges, findings, data, primary_id):
    for item in data.get("confirmed") or []:
        flag_id = f"scamdb:{item['normalized']}"
        add_node(nodes, flag_id, "scamdb_flag", "Confirmed scam report", item)
        target_id = infer_artifact_node_id(item["normalized"])
        if target_id in nodes:
            add_edge(edges, target_id, flag_id, "confirmed by")
        else:
            add_edge(edges, primary_id, flag_id, "confirmed by")

    if data.get("confirmed_count"):
        findings.append(f"{data['confirmed_count']} artifacts matched CryptoScamDB")


def build_web_layer(nodes, edges, findings, data, primary_id):
    for result in data.get("results") or []:
        link = result.get("link")
        if not link:
            continue
        source = result.get("source") or urlparse(link).netloc or "web"
        node_id = f"mention:{link}"
        add_node(nodes, node_id, "web_mention", result.get("title") or source, result)
        add_edge(edges, primary_id, node_id, f"mentioned on {source}")

    for flag in data.get("risk_flags") or []:
        findings.append(flag)


def compute_risk_score(wallet_data, whois_data, wayback_data, scamdb_data, web_data):
    score = 0
    reasons = []

    if scamdb_data and scamdb_data.get("confirmed_count"):
        score += 40
        reasons.append("Artifact matched public scam database")

    if wallet_data:
        impact = wallet_data.get("impact") or {}
        if impact.get("unique_senders", 0) >= 10:
            score += 15
            reasons.append("High number of unique sender wallets")
        if impact.get("total_eth_received", 0) >= 1:
            score += 10
            reasons.append("Significant ETH received")

    if whois_data:
        age = whois_data.get("age_days")
        if age is not None and age < 30:
            score += 15
            reasons.append("Domain was recently registered")
        if whois_data.get("privacy_protected"):
            score += 10
            reasons.append("Domain registrant is privacy protected")

    if wayback_data and (wayback_data.get("timeline") or {}).get("operational_days", 0) <= 30 and wayback_data.get("snapshot_count"):
        score += 10
        reasons.append("Short archived activity window")

    if web_data and web_data.get("risk_flags"):
        score += 10
        reasons.extend(web_data["risk_flags"])

    score = min(score, 100)
    level = "LOW"
    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"

    return {"score": score, "level": level, "reasons": reasons}


def build_summary(wallet_data, crtsh_data, whois_data, wayback_data, scamdb_data, web_data):
    return {
        "wallet": {
            "balance_eth": (wallet_data or {}).get("balance_eth"),
            "impact": (wallet_data or {}).get("impact"),
            "connected_wallets": len((wallet_data or {}).get("connected_addresses") or []),
        },
        "domain": {
            "certificates": (crtsh_data or {}).get("total_certs"),
            "sibling_domains": len((crtsh_data or {}).get("sibling_domains") or []),
            "age_days": (whois_data or {}).get("age_days"),
            "wayback_snapshots": (wayback_data or {}).get("snapshot_count"),
        },
        "scamdb": {
            "checked": (scamdb_data or {}).get("checked_count", 0),
            "confirmed": (scamdb_data or {}).get("confirmed_count", 0),
        },
        "web_mentions": len((web_data or {}).get("results") or []),
    }


def infer_artifact_node_id(value: str) -> str:
    if value.startswith("0x"):
        return f"wallet:{value.lower()}"
    return f"domain:{value.lower()}"


def shorten(value: str, left: int = 8, right: int = 6) -> str:
    if not value or len(value) <= left + right + 3:
        return value
    return f"{value[:left]}...{value[-right:]}"
