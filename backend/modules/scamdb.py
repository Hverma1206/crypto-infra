import json
from pathlib import Path

import requests


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
LOCAL_CACHE = DATA_DIR / "scamdb_cache.json"
BLACKLIST_URL = "https://api.cryptoscamdb.org/v1/blacklist"


def normalize_artifact(value: str) -> str:
    return str(value or "").strip().lower().replace("https://", "").replace("http://", "").rstrip("/")


def fetch_blacklist() -> list:
    try:
        response = requests.get(BLACKLIST_URL, timeout=15)
        response.raise_for_status()
        data = response.json()
    except (requests.RequestException, ValueError):
        return []

    result = data.get("result", data)
    if isinstance(result, list):
        return [normalize_artifact(item) for item in result if item]
    return []


def load_local_dataset() -> list:
    if not LOCAL_CACHE.exists():
        return []
    try:
        data = json.loads(LOCAL_CACHE.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    if isinstance(data, dict):
        items = data.get("result") or data.get("blacklist") or data.get("items") or []
    else:
        items = data

    return [normalize_artifact(item) for item in items if item]


def save_local_dataset(items: list):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOCAL_CACHE.write_text(json.dumps({"result": sorted(set(items))}, indent=2))


def get_blacklist() -> list:
    local = load_local_dataset()
    if local:
        return local

    remote = fetch_blacklist()
    if remote:
        save_local_dataset(remote)
    return remote


def check_artifact(value: str) -> dict:
    artifact = normalize_artifact(value)
    blacklist = get_blacklist()
    matched = artifact in blacklist

    if not matched and "." in artifact:
        matched = any(artifact == item or artifact.endswith(f".{item}") for item in blacklist)

    return {
        "artifact": value,
        "normalized": artifact,
        "is_scam": matched,
        "source": "CryptoScamDB",
        "type": "domain" if "." in artifact and not artifact.startswith("0x") else "address",
        "matched_entries": [item for item in blacklist if artifact == item or item in artifact][:10],
    }


def analyze_all_artifacts(wallet: str | None = None, domains: list | None = None, connected_wallets: list | None = None) -> dict:
    artifacts = []
    if wallet:
        artifacts.append(wallet)
    artifacts.extend(domains or [])
    artifacts.extend(connected_wallets or [])

    checks = [check_artifact(item) for item in artifacts if item]
    confirmed = [item for item in checks if item["is_scam"]]

    return {
        "checked_count": len(checks),
        "confirmed_count": len(confirmed),
        "confirmed": confirmed,
        "checks": checks,
    }
