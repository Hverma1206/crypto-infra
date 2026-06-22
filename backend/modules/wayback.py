from __future__ import annotations

import logging
from datetime import datetime
from urllib.parse import urlparse

import requests

logger = logging.getLogger("wayback")


AVAILABLE_URL = "https://archive.org/wayback/available"
CDX_URL = "https://web.archive.org/cdx"


def normalize_domain(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return parsed.netloc or parsed.path.split("/")[0]


def check_availability(domain: str) -> dict:
    domain = normalize_domain(domain)
    if not domain:
        return {"available": False, "url": None, "timestamp": None, "date": None}

    try:
        response = requests.get(AVAILABLE_URL, params={"url": domain}, timeout=5)
        response.raise_for_status()
        archived = response.json().get("archived_snapshots", {}).get("closest", {})
    except requests.RequestException as exc:
        return {"available": False, "url": None, "timestamp": None, "date": None, "error": str(exc)}

    timestamp = archived.get("timestamp")
    return {
        "available": bool(archived.get("available")),
        "url": archived.get("url"),
        "timestamp": timestamp,
        "date": _format_timestamp(timestamp),
        "status": archived.get("status"),
    }


def get_snapshots(domain: str, limit: int = 20) -> list:
    domain = normalize_domain(domain)
    if not domain:
        return []

    params = {
        "url": domain,
        "output": "json",
        "fl": "timestamp,original,statuscode,mimetype",
        "filter": "statuscode:200",
        "collapse": "timestamp:8",
        "limit": limit,
    }

    try:
        response = requests.get(f"{CDX_URL}/search/cdx", params=params, timeout=5)
        response.raise_for_status()
        rows = response.json()
    except (requests.RequestException, ValueError):
        return []

    if not rows or len(rows) < 2:
        return []

    snapshots = []
    for row in rows[1:]:
        timestamp = row[0]
        snapshots.append(
            {
                "timestamp": timestamp,
                "date": _format_timestamp(timestamp),
                "original": row[1],
                "status": row[2],
                "mimetype": row[3],
                "archive_url": f"https://web.archive.org/web/{timestamp}/{row[1]}",
            }
        )

    return snapshots


def build_timeline(snapshots: list) -> dict:
    dates = [s["date"] for s in snapshots if s.get("date")]
    if not dates:
        return {"first_seen": None, "last_seen": None, "operational_days": 0}

    first_seen = min(dates)
    last_seen = max(dates)
    try:
        first_dt = datetime.strptime(first_seen, "%Y-%m-%d")
        last_dt = datetime.strptime(last_seen, "%Y-%m-%d")
        operational_days = max(1, (last_dt - first_dt).days)
    except ValueError:
        operational_days = 0

    return {
        "first_seen": first_seen,
        "last_seen": last_seen,
        "operational_days": operational_days,
    }


def get_risk_flags(timeline: dict) -> list:
    flags = []
    days = timeline.get("operational_days") or 0
    if days and days <= 7:
        flags.append(f"Archived activity window is only {days} days")
    elif days and days <= 30:
        flags.append(f"Archived activity window is short: {days} days")
    return flags


def analyze_domain_wayback(domain: str) -> dict:
    domain = normalize_domain(domain)
    available = check_availability(domain)
    snapshots = get_snapshots(domain)
    timeline = build_timeline(snapshots)
    flags = get_risk_flags(timeline)

    return {
        "domain": domain,
        "available": available.get("available", False),
        "closest_snapshot": available,
        "snapshots": snapshots,
        "snapshot_count": len(snapshots),
        "timeline": timeline,
        "risk_flags": flags,
    }


def _format_timestamp(timestamp: str | None) -> str | None:
    if not timestamp or len(timestamp) < 8:
        return None
    return f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}"
