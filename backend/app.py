import os
import re
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

import cache
from modules.crtsh import analyze_domain
from modules.etherscan import analyze_wallet
from modules.graph_builder import build_graph
from modules.scamdb import analyze_all_artifacts
from modules.wayback import analyze_domain_wayback
from modules.web_mentions import analyze_web_presence
from modules.whois_lookup import analyze_domain_whois


load_dotenv()

app = Flask(__name__)
CORS(app)


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/cache/stats")
def cache_stats():
    return jsonify(cache.get_stats())


@app.post("/analyze")
def analyze():
    payload = request.get_json(silent=True) or {}
    input_value = (payload.get("input") or "").strip()
    domain = (payload.get("domain") or "").strip()

    if not input_value:
        return jsonify({"error": "input is required"}), 400

    cache_key = f"{input_value}|{domain}"
    cached = cache.get("analysis", cache_key)
    if cached:
        return jsonify(cached)

    input_type = detect_input_type(input_value)
    wallet_data = None
    crtsh_data = None
    whois_data = None
    wayback_data = None

    if input_type == "wallet":
        wallet_data = analyze_wallet(input_value)
    else:
        domain = normalize_domain(input_value)

    if domain:
        crtsh_data = analyze_domain(domain)
        whois_data = analyze_domain_whois(domain)
        wayback_data = analyze_domain_wayback(domain)

    domains = []
    if domain:
        domains.append(domain)
    if crtsh_data:
        domains.extend((crtsh_data.get("sibling_domains") or [])[:10])

    scamdb_data = analyze_all_artifacts(
        wallet=input_value if input_type == "wallet" else None,
        domains=domains,
        connected_wallets=(wallet_data or {}).get("connected_addresses") or [],
    )
    web_data = analyze_web_presence(
        wallet=input_value if input_type == "wallet" else None,
        domain=domain or None,
    )

    result = build_graph(
        input_value=input_value,
        input_type=input_type,
        wallet_data=wallet_data,
        crtsh_data=crtsh_data,
        whois_data=whois_data,
        wayback_data=wayback_data,
        scamdb_data=scamdb_data,
        web_data=web_data,
    )
    result["raw"] = {
        "wallet": wallet_data,
        "crtsh": crtsh_data,
        "whois": whois_data,
        "wayback": wayback_data,
        "scamdb": scamdb_data,
        "web_mentions": web_data,
    }

    cache.set("analysis", cache_key, result)
    return jsonify(result)


@app.post("/report")
def report():
    payload = request.get_json(silent=True) or {}
    analysis = payload.get("analysis") or {}
    findings = analysis.get("findings") or []
    risk = analysis.get("risk") or {}
    summary = analysis.get("summary") or {}

    text = {
        "title": "Investigation Summary",
        "risk_level": risk.get("level", "UNKNOWN"),
        "risk_score": risk.get("score", 0),
        "narrative": build_local_narrative(analysis, findings, risk, summary),
    }
    return jsonify(text)


def build_local_narrative(analysis: dict, findings: list, risk: dict, summary: dict) -> str:
    input_value = analysis.get("input", "the submitted artifact")
    level = risk.get("level", "UNKNOWN")
    score = risk.get("score", 0)
    top_findings = findings[:5]
    sentence = f"The submitted artifact {input_value} was assessed at {level} risk with a score of {score}/100."
    if top_findings:
        sentence += " Key indicators include " + "; ".join(top_findings) + "."
    if summary.get("scamdb", {}).get("confirmed"):
        sentence += " At least one artifact matched a public scam database."
    return sentence


def detect_input_type(value: str) -> str:
    if re.fullmatch(r"0x[a-fA-F0-9]{40}", value):
        return "wallet"
    return "domain"


def normalize_domain(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return (parsed.netloc or parsed.path.split("/")[0]).lower().strip()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
