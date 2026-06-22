from __future__ import annotations

import json
import logging
from datetime import datetime

import requests

logger = logging.getLogger("crtsh")


def get_certificates(domain: str) -> list:
    """
    Queries crt.sh — the public Certificate Transparency log database.
    No API key needed. Completely free. No rate limits for normal use.

    What are Certificate Transparency logs?
    ----------------------------------------
    Every time anyone registers an SSL certificate for a website,
    it gets logged permanently in a public database. This was created
    so that nobody can secretly issue fake certificates. We exploit this
    for investigation — scammers can't hide their domains from this log.

    Returns a list of certificate records, each containing:
      - domain      : the domain name on the certificate
      - issuer      : who issued the cert (Let's Encrypt, Comodo, etc.)
      - not_before  : when the cert became valid (tells us domain birth date)
      - not_after   : when it expires
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        if not response.text.strip():
            return []

        certs = response.json()
        return certs

    except requests.exceptions.Timeout:
        logger.warning("Timeout querying %s", domain)
        return []
    except requests.exceptions.RequestException as e:
        logger.warning("Request error: %s", e)
        return []
    except json.JSONDecodeError:
        logger.warning("Could not parse response for %s", domain)
        return []


def extract_unique_domains(certs: list) -> list:
    """
    From the raw certificate list, extract all unique domain names.

    Why this matters for investigation:
    A scammer running moonprofit.com might also have registered:
      - app.moonprofit.com      (login portal)
      - trade.moonprofit.com    (fake trading page)
      - moonprofit2.com         (next scam, already prepared)
      - moonprofit-airdrop.com  (phishing variant)

    All of these show up in the certificate logs.
    This function pulls out every unique domain name found.

    Returns a sorted list of unique domain strings.
    """
    domains = set()

    for cert in certs:
        # Each cert record has a 'common_name' field
        name = cert.get("common_name", "").strip()

        if not name:
            continue

        # Skip wildcard certs (*.domain.com) — not useful as specific leads
        if name.startswith("*"):
            name = name.lstrip("*.")

        # Skip empty or clearly invalid entries
        if "." not in name or len(name) < 4:
            continue

        domains.add(name.lower())

    return sorted(list(domains))


def get_earliest_cert_date(certs: list) -> str | None:
    """
    Find the earliest certificate issue date across all certs.

    Why this matters:
    Scammers register domains just before launching a scam.
    If a domain's earliest cert was issued 3 days before
    the first victim transaction, that's a strong indicator
    of when the operation started — useful for the timeline.

    Returns a human-readable date string or None.
    """
    dates = []

    for cert in certs:
        date_str = cert.get("not_before", "")
        if not date_str:
            continue
        try:
            # crt.sh format is like: "2024-01-15T10:30:00"
            dt = datetime.fromisoformat(date_str.replace("Z", ""))
            dates.append(dt)
        except ValueError:
            continue

    if not dates:
        return None

    earliest = min(dates)
    return earliest.strftime("%Y-%m-%d")


def find_sibling_domains(domain: str, all_domains: list) -> list:
    """
    Find domains that are likely run by the same operator.

    Logic:
    If the input is 'moonprofit.com', sibling domains are ones that
    share the same root name but are different variations — strong sign
    of the same actor running multiple operations.

    Example:
      Input domain     : moonprofit.com
      Siblings found   : ['moonprofit2.com', 'moonprofit-trade.com',
                          'moonprofittoken.com']

    Returns list of sibling domain strings.
    """
    # Extract the root word from the domain (without .com/.io/etc.)
    root = domain.split(".")[0].lower()

    siblings = []
    for d in all_domains:
        # Must contain the root word but not be the exact same domain
        if root in d and d != domain:
            siblings.append(d)

    return siblings


def analyze_domain(domain: str) -> dict:
    """
    MAIN FUNCTION — call this from app.py and graph_builder.py.

    Given a domain name, returns everything your tool needs:
      - domain           : the input domain
      - total_certs      : how many certs were ever issued (high = old/established)
      - unique_domains   : all unique domains found in the cert logs
      - sibling_domains  : domains likely run by the same actor
      - earliest_date    : when the first cert was issued (operation start date)
      - raw_certs        : first 20 raw cert records (for detailed view if needed)
    """
    logger.info("Analyzing domain: %s", domain)

    certs = get_certificates(domain)

    if not certs:
        return {
            "domain": domain,
            "total_certs": 0,
            "unique_domains": [],
            "sibling_domains": [],
            "earliest_date": None,
            "raw_certs": [],
            "error": "No certificates found — domain may not exist or have no SSL history"
        }

    unique_domains = extract_unique_domains(certs)
    sibling_domains = find_sibling_domains(domain, unique_domains)
    earliest_date = get_earliest_cert_date(certs)

    return {
        "domain": domain,
        "total_certs": len(certs),
        "unique_domains": unique_domains,
        "sibling_domains": sibling_domains,
        "earliest_date": earliest_date,
        "raw_certs": certs[:20],
    }
