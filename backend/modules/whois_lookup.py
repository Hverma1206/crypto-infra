from __future__ import annotations

import logging
from datetime import datetime, timezone

import whois

logger = logging.getLogger("whois")


def _normalize_date(date_val) -> str | None:
    """
    WHOIS dates come back in many formats depending on the registrar.
    Sometimes a single datetime, sometimes a list of datetimes,
    sometimes a string, sometimes None.
    This helper normalizes all of that into one clean date string.
    """
    if date_val is None:
        return None

    # Sometimes it's a list — take the first valid one
    if isinstance(date_val, list):
        date_val = next((d for d in date_val if d is not None), None)
        if date_val is None:
            return None

    # If it's already a datetime object
    if isinstance(date_val, datetime):
        return date_val.strftime("%Y-%m-%d")

    # If it's a string, try to parse it
    if isinstance(date_val, str):
        for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"]:
            try:
                return datetime.strptime(date_val[:19], fmt).strftime("%Y-%m-%d")
            except ValueError:
                continue

    return str(date_val)[:10]


def _normalize_list(val) -> list:
    """
    WHOIS fields like emails and name_servers sometimes return
    a single string instead of a list. Normalize everything to a list.
    """
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v).lower().strip() for v in val if v]
    return [str(val).lower().strip()]


def get_whois(domain: str) -> dict:
    """
    Fetches WHOIS registration data for a domain.

    What is WHOIS?
    --------------
    When someone buys a domain (like moonprofit.com), they must
    provide registration details — name, email, organization, phone.
    These are stored in public WHOIS databases maintained by registrars.
    Many scammers use fake details, but patterns still leak through:
    same email across multiple scam domains, same registrar, same
    registration window just before a scam launched.

    Returns a dict with:
      - domain          : input domain
      - registrar       : company they bought the domain from
      - creation_date   : when domain was first registered
      - expiry_date     : when registration expires
      - emails          : registrant contact emails (key investigative lead)
      - name_servers    : DNS servers (shared hosting = same operator)
      - country         : registrant country if available
      - raw_text        : raw WHOIS text for reference
    """
    logger.info("Looking up: %s", domain)

    try:
        w = whois.whois(domain)

        return {
            "domain": domain,
            "registrar": str(w.registrar) if w.registrar else None,
            "creation_date": _normalize_date(w.creation_date),
            "expiry_date": _normalize_date(w.expiration_date),
            "updated_date": _normalize_date(w.updated_date),
            "emails": _normalize_list(w.emails),
            "name_servers": _normalize_list(w.name_servers),
            "country": str(w.country) if w.country else None,
            "org": str(w.org) if w.org else None,
            "error": None,
        }

    except Exception as e:
        error_name = type(e).__name__
        if "pywhois" in error_name.lower() or "whois" in error_name.lower():
            msg = "Domain not found in WHOIS — may be unregistered or privacy-protected"
        else:
            msg = f"WHOIS lookup failed: {e}"
        logger.warning("WHOIS error for %s: %s", domain, e)
        return {
            "domain": domain,
            "registrar": None,
            "creation_date": None,
            "expiry_date": None,
            "updated_date": None,
            "emails": [],
            "name_servers": [],
            "country": None,
            "org": None,
            "error": msg,
        }



def compute_domain_age_days(creation_date_str: str | None) -> int | None:
    """
    Computes how many days old a domain is from its creation date.

    Why this matters for investigation:
    Scammers register domains days or weeks before launching.
    A domain less than 30 days old at the time of a scam complaint
    is a strong red flag. Your risk scoring uses this number.

    Returns number of days, or None if date unavailable.
    """
    if not creation_date_str:
        return None

    try:
        created = datetime.strptime(creation_date_str, "%Y-%m-%d")
        today = datetime.now()
        return (today - created).days
    except ValueError:
        return None


def is_privacy_protected(whois_data: dict) -> bool:
    """
    Checks if the domain registration is privacy-protected
    (registrant hid their details using a privacy service).

    Privacy protection is normal for personal sites but
    is a significant red flag for a financial/investment platform
    that claims to be a legitimate business.

    Common privacy services: WhoisGuard, Domains By Proxy,
    Privacy Protect, Contact Privacy Inc.
    """
    privacy_keywords = [
        "whoisguard", "privacy", "protect", "proxy",
        "redacted", "withheld", "gdpr", "not disclosed"
    ]

    registrar = (whois_data.get("registrar") or "").lower()
    emails = " ".join(whois_data.get("emails") or []).lower()
    org = (whois_data.get("org") or "").lower()

    combined = f"{registrar} {emails} {org}"

    return any(kw in combined for kw in privacy_keywords)


def get_risk_flags(whois_data: dict) -> list:
    """
    Generates a list of plain-English risk flags from WHOIS data.
    These feed directly into your risk score and the AI report.

    Returns a list of flag strings, empty list if no flags.
    """
    flags = []
    age_days = compute_domain_age_days(whois_data.get("creation_date"))

    if age_days is not None:
        if age_days < 7:
            flags.append(f"Domain registered only {age_days} days ago — extremely new")
        elif age_days < 30:
            flags.append(f"Domain registered {age_days} days ago — recently created")
        elif age_days < 90:
            flags.append(f"Domain registered {age_days} days ago — less than 3 months old")

    if is_privacy_protected(whois_data):
        flags.append("Registrant identity hidden behind privacy service")

    if not whois_data.get("emails"):
        flags.append("No registrant email found — possible data redaction")

    if not whois_data.get("org"):
        flags.append("No organization listed — not registered as a business")

    expiry = whois_data.get("expiry_date")
    if expiry:
        try:
            exp_date = datetime.strptime(expiry, "%Y-%m-%d")
            days_until_expiry = (exp_date - datetime.now()).days
            if days_until_expiry < 60:
                flags.append(f"Domain expires in {days_until_expiry} days — operator may be planning to abandon it")
        except ValueError:
            pass

    return flags


def analyze_domain_whois(domain: str) -> dict:
    """
    MAIN FUNCTION — call this from app.py and graph_builder.py.

    Combines WHOIS data + age calculation + risk flags into
    one complete dict ready for graph building and risk scoring.

    Returns:
      - all fields from get_whois()
      - age_days      : how old the domain is in days
      - risk_flags    : list of human-readable red flags
      - privacy_protected : True/False
    """
    data = get_whois(domain)
    age_days = compute_domain_age_days(data.get("creation_date"))
    flags = get_risk_flags(data)
    privacy = is_privacy_protected(data)

    data["age_days"] = age_days
    data["risk_flags"] = flags
    data["privacy_protected"] = privacy

    return data
