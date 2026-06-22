from __future__ import annotations

import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, send_file
from flask_cors import CORS

import cache
from modules.crtsh import analyze_domain
from modules.deep_scan import deep_scan
from modules.etherscan import analyze_wallet
from modules.graph_builder import build_graph
from modules.report_pdf import generate_pdf
from modules.scamdb import analyze_all_artifacts
from modules.wayback import analyze_domain_wayback
from modules.web_mentions import analyze_web_presence
from modules.whois_lookup import analyze_domain_whois


load_dotenv()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("app")

# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------
app = Flask(__name__)

# CORS — allow all origins unconditionally
CORS(app, origins="*")

MAX_INPUT_LENGTH = 256


# ---------------------------------------------------------------------------
# Global error handler — always return JSON, never raw HTML stack traces
# ---------------------------------------------------------------------------
@app.errorhandler(Exception)
def handle_exception(exc):
    logger.exception("Unhandled exception during request")
    return jsonify({"error": "Internal server error"}), 500


@app.errorhandler(404)
def handle_404(_exc):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(405)
def handle_405(_exc):
    return jsonify({"error": "Method not allowed"}), 405


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.get("/cache/stats")
def cache_stats():
    return jsonify(cache.get_stats())


# ---------------------------------------------------------------------------
# Standard analysis (sequential, backwards-compatible)
# ---------------------------------------------------------------------------
@app.post("/analyze")
def analyze():
    payload = request.get_json(silent=True) or {}
    input_value = (payload.get("input") or "").strip()
    domain = (payload.get("domain") or "").strip()

    if not input_value:
        return jsonify({"error": "input is required"}), 400

    if len(input_value) > MAX_INPUT_LENGTH or len(domain) > MAX_INPUT_LENGTH:
        return jsonify({"error": f"Input must be under {MAX_INPUT_LENGTH} characters"}), 400

    logger.info("Analyze request — input=%s  domain=%s", input_value, domain or "(none)")

    cache_key = f"{input_value}|{domain}"
    cached = cache.get("analysis", cache_key)
    if cached:
        logger.info("Returning cached result for %s", input_value)
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
    logger.info("Analysis complete — nodes=%d  edges=%d  risk=%s",
                len(result.get("nodes", [])), len(result.get("edges", [])),
                result.get("risk", {}).get("level", "UNKNOWN"))
    return jsonify(result)


# ---------------------------------------------------------------------------
# Streaming analysis (parallel + SSE live progress)
# ---------------------------------------------------------------------------
@app.post("/analyze/stream")
def analyze_stream():
    payload = request.get_json(silent=True) or {}
    input_value = (payload.get("input") or "").strip()
    domain = (payload.get("domain") or "").strip()

    if not input_value:
        return jsonify({"error": "input is required"}), 400

    if len(input_value) > MAX_INPUT_LENGTH or len(domain) > MAX_INPUT_LENGTH:
        return jsonify({"error": f"Input must be under {MAX_INPUT_LENGTH} characters"}), 400

    input_type = detect_input_type(input_value)
    if input_type != "wallet":
        domain = normalize_domain(input_value)

    def generate():
        """Generator that yields SSE events as each source completes."""
        # Yield 2KB of padding to bypass Vercel/Nginx proxy buffering
        yield f": {' ' * 2048}\n\n"

        wallet_data = None
        crtsh_data = None
        whois_data = None
        wayback_data = None
        scamdb_data = None
        web_data = None

        results = {}

        def run_source(name, fn, *args, **kwargs):
            start = time.time()
            try:
                data = fn(*args, **kwargs)
                duration = round(time.time() - start, 2)
                return name, data, duration, None
            except Exception as exc:
                duration = round(time.time() - start, 2)
                return name, None, duration, str(exc)

        # Build task list based on input type
        tasks = []
        if input_type == "wallet":
            tasks.append(("etherscan", analyze_wallet, input_value))
        if domain:
            tasks.append(("crtsh", analyze_domain, domain))
            tasks.append(("whois", analyze_domain_whois, domain))
            tasks.append(("wayback", analyze_domain_wayback, domain))

        # Send initial event with source list
        source_names = [t[0] for t in tasks] + ["scamdb", "web_mentions"]
        yield f"data: {json.dumps({'event': 'sources', 'sources': source_names})}\n\n"

        # Run primary sources in parallel
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(run_source, name, fn, *args): name
                for name, fn, *args in tasks
            }

            for future in as_completed(futures):
                name, data, duration, error = future.result()
                results[name] = data

                yield f"data: {json.dumps({'event': 'source_done', 'source': name, 'duration': duration, 'error': error})}\n\n"

        # Extract results
        wallet_data = results.get("etherscan")
        crtsh_data = results.get("crtsh")
        whois_data = results.get("whois")
        wayback_data = results.get("wayback")

        # If wallet analysis returned, we might need domain sources
        if input_type == "wallet" and domain and not crtsh_data:
            domain_tasks = [
                ("crtsh", analyze_domain, domain),
                ("whois", analyze_domain_whois, domain),
                ("wayback", analyze_domain_wayback, domain),
            ]
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = {
                    executor.submit(run_source, name, fn, *args): name
                    for name, fn, *args in domain_tasks
                }
                for future in as_completed(futures):
                    name, data, duration, error = future.result()
                    results[name] = data
                    yield f"data: {json.dumps({'event': 'source_done', 'source': name, 'duration': duration, 'error': error})}\n\n"

            crtsh_data = results.get("crtsh")
            whois_data = results.get("whois")
            wayback_data = results.get("wayback")

        # ScamDB + Web mentions (depend on previous results)
        domains = []
        if domain:
            domains.append(domain)
        if crtsh_data:
            domains.extend((crtsh_data.get("sibling_domains") or [])[:10])

        scamdb_kwargs = {
            "wallet": input_value if input_type == "wallet" else None,
            "domains": domains,
            "connected_wallets": (wallet_data or {}).get("connected_addresses") or [],
        }
        web_kwargs = {
            "wallet": input_value if input_type == "wallet" else None,
            "domain": domain or None,
        }

        with ThreadPoolExecutor(max_workers=2) as executor:
            future_scamdb = executor.submit(run_source, "scamdb", analyze_all_artifacts, **scamdb_kwargs)
            future_web = executor.submit(run_source, "web_mentions", analyze_web_presence, **web_kwargs)

            for future in as_completed([future_scamdb, future_web]):
                name, data, duration, error = future.result()
                if name == "scamdb":
                    scamdb_data = data
                elif name == "web_mentions":
                    web_data = data
                yield f"data: {json.dumps({'event': 'source_done', 'source': name, 'duration': duration, 'error': error})}\n\n"

        # Build graph
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

        # Cache the result
        cache_key = f"{input_value}|{domain}"
        cache.set("analysis", cache_key, result)

        # Send final result
        yield f"data: {json.dumps({'event': 'complete', 'result': result}, default=str)}\n\n"

    return Response(generate(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    })


# ---------------------------------------------------------------------------
# Report (narrative text)
# ---------------------------------------------------------------------------
@app.post("/report")
def report():
    payload = request.get_json(silent=True) or {}
    analysis = payload.get("analysis") or {}
    findings = analysis.get("findings") or []
    risk = analysis.get("risk") or {}
    summary = analysis.get("summary") or {}
    gemini_narrative = build_gemini_narrative(analysis, findings, risk, summary)

    text = {
        "title": "Investigation Summary",
        "risk_level": risk.get("level", "UNKNOWN"),
        "risk_score": risk.get("score", 0),
        "narrative": gemini_narrative or build_local_narrative(analysis, findings, risk, summary),
        "provider": "gemini" if gemini_narrative else "local",
    }
    return jsonify(text)


# ---------------------------------------------------------------------------
# Report (PDF download)
# ---------------------------------------------------------------------------
@app.post("/report/pdf")
def report_pdf():
    payload = request.get_json(silent=True) or {}
    analysis = payload.get("analysis") or {}
    narrative = payload.get("narrative")

    try:
        pdf_bytes = generate_pdf(analysis, report_narrative=narrative)
    except Exception as exc:
        logger.exception("PDF generation failed")
        return jsonify({"error": f"PDF generation failed: {exc}"}), 500

    import io
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"scam_report_{analysis.get('input', 'unknown')[:30]}.pdf",
    )


# ---------------------------------------------------------------------------
# Deep Scan — recursive wallet expansion
# ---------------------------------------------------------------------------
@app.post("/deep-scan")
def deep_scan_endpoint():
    payload = request.get_json(silent=True) or {}
    analysis = payload.get("analysis") or {}
    addresses = payload.get("addresses") or []

    if not analysis or not addresses:
        return jsonify({"error": "analysis and addresses are required"}), 400

    if len(addresses) > 20:
        return jsonify({"error": "Maximum 20 addresses allowed"}), 400

    try:
        result = deep_scan(analysis, addresses)
        return jsonify(result)
    except Exception as exc:
        logger.exception("Deep scan failed")
        return jsonify({"error": f"Deep scan failed: {exc}"}), 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def build_gemini_narrative(analysis: dict, findings: list, risk: dict, summary: dict) -> str | None:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return None

    try:
        from google import genai

        client = genai.Client(api_key=api_key)
        model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        report_context = {
            "input": analysis.get("input"),
            "input_type": analysis.get("input_type"),
            "risk": risk,
            "summary": summary,
            "findings": findings[:10],
        }
        prompt = (
            "Write one concise OSINT investigation narrative paragraph for a crypto scam "
            "infrastructure report. Use only the provided JSON facts, avoid speculation, "
            "and do not use markdown.\n\n"
            f"{json.dumps(report_context, default=str)}"
        )
        response = client.models.generate_content(model=model, contents=prompt)
        narrative = getattr(response, "text", None)
        return narrative.strip() if narrative else None
    except Exception as exc:
        logger.warning("Gemini report generation failed: %s", exc)
        return None


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
    # Ethereum: 0x + 40 hex chars
    if re.fullmatch(r"0x[a-fA-F0-9]{40}", value):
        return "wallet"
    # Bitcoin Bech32 / Bech32m: bc1 followed by 25-87 alphanumeric chars
    if re.fullmatch(r"bc1[a-zA-HJ-NP-Za-km-z0-9]{25,87}", value):
        return "wallet"
    # Bitcoin legacy (P2PKH): starts with 1, 25-34 chars base58
    if re.fullmatch(r"1[a-km-zA-HJ-NP-Z1-9]{24,33}", value):
        return "wallet"
    # Bitcoin P2SH: starts with 3, 25-34 chars base58
    if re.fullmatch(r"3[a-km-zA-HJ-NP-Z1-9]{24,33}", value):
        return "wallet"
    return "domain"


def normalize_domain(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return (parsed.netloc or parsed.path.split("/")[0]).lower().strip()


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")
    logger.info("Starting server on port %d (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)
