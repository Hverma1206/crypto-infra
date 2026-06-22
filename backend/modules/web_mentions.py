from __future__ import annotations

import logging
import os
from base64 import b64encode
from urllib.parse import quote_plus

import requests
from dotenv import load_dotenv

logger = logging.getLogger("web_mentions")


load_dotenv()

REDDIT_TOKEN_URL = "https://www.reddit.com/api/v1/access_token"
REDDIT_SEARCH_URL = "https://oauth.reddit.com/search"


def get_reddit_token() -> str | None:
    client_id = os.getenv("REDDIT_CLIENT_ID")
    secret = os.getenv("REDDIT_SECRET")
    if not client_id or not secret:
        return None

    auth = b64encode(f"{client_id}:{secret}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth}",
        "User-Agent": "crypto-scam-infrastructure-mapper/1.0",
    }
    data = {"grant_type": "client_credentials"}

    try:
        response = requests.post(REDDIT_TOKEN_URL, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        return response.json().get("access_token")
    except (requests.RequestException, ValueError):
        return None


def search_reddit(query: str, limit: int = 5) -> list:
    token = get_reddit_token()
    if not token:
        return []

    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "crypto-scam-infrastructure-mapper/1.0",
    }
    params = {"q": query, "limit": limit, "sort": "relevance", "type": "link"}

    try:
        response = requests.get(REDDIT_SEARCH_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        children = response.json().get("data", {}).get("children", [])
    except (requests.RequestException, ValueError):
        return []

    results = []
    for child in children:
        data = child.get("data", {})
        results.append(
            {
                "title": data.get("title"),
                "link": f"https://reddit.com{data.get('permalink')}",
                "snippet": data.get("selftext", "")[:240],
                "source": "reddit",
                "subreddit": data.get("subreddit"),
                "created_utc": data.get("created_utc"),
            }
        )
    return results


def build_external_search_links(query: str) -> list:
    encoded = quote_plus(query)
    return [
        {
            "title": "Search ChainAbuse reports",
            "link": f"https://www.chainabuse.com/search?term={encoded}",
            "snippet": "Manual verification link for public abuse reports.",
            "source": "chainabuse",
        },
        {
            "title": "Search Etherscan",
            "link": f"https://etherscan.io/search?f=0&q={encoded}",
            "snippet": "Manual verification link for public Ethereum records.",
            "source": "etherscan",
        },
    ]


def classify_results(results: list) -> dict:
    categories = {"reddit": [], "chainabuse": [], "etherscan": [], "other": []}
    for result in results:
        source = (result.get("source") or "").lower()
        if source in categories:
            categories[source].append(result)
        else:
            categories["other"].append(result)
    return categories


def analyze_web_presence(wallet: str | None = None, domain: str | None = None) -> dict:
    query_parts = [item for item in [wallet, domain] if item]
    query = " ".join(query_parts)
    if not query:
        return {"query": "", "results": [], "categories": {}, "risk_flags": []}

    reddit_results = search_reddit(f'"{query}" crypto scam')
    external_links = build_external_search_links(query)
    categories = classify_results(reddit_results)
    flags = []

    if reddit_results:
        flags.append(f"Found {len(reddit_results)} Reddit discussions mentioning this artifact")

    return {
        "query": query,
        "results": reddit_results,
        "external_links": external_links,
        "categories": categories,
        "risk_flags": flags,
    }
