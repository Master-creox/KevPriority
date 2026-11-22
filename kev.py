"""Load the CISA Known Exploited Vulnerabilities (KEV) catalog.

The KEV catalog is a public list, maintained by CISA, of vulnerabilities
that are *confirmed* to have been exploited in the wild. That is the key
idea behind KevPriority: a CVE that is in this list is not a theoretical
risk, it is something attackers are already using.

Public feed (JSON, no key needed):
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Each entry in the feed looks like this (field names are CISA's own):
    {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j2",
        "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
        "dateAdded": "2021-12-10",
        "shortDescription": "...",
        "requiredAction": "Apply updates per vendor instructions ...",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known",
        "notes": "..."
    }

Only the standard library is used here (urllib + json).
"""

import json
import urllib.request
from datetime import date

# Official public KEV feed. No API key, no account, no login.
KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# A plain User-Agent keeps the request looking like a normal client.
USER_AGENT = "KevPriority/1.0 (vulnerability prioritization; +https://github.com)"


def fetch_kev_catalog(url=KEV_FEED_URL, timeout=60):
    """Download the live KEV catalog and return the parsed JSON dict.

    Raises URLError / TimeoutError if the network or the feed is down.
    The caller decides what to do then (usually: print a clear message
    and suggest --demo).
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
    return json.loads(raw)


def load_kev_file(path):
    """Load a KEV catalog from a local JSON file (same format as the feed)."""
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _parse_date(text):
    """Turn a 'YYYY-MM-DD' string into a date, or None if it is missing/bad."""
    if not text:
        return None
    try:
        year, month, day = (int(part) for part in text.strip().split("-"))
        return date(year, month, day)
    except (ValueError, AttributeError):
        return None


def parse_kev_catalog(data):
    """Turn raw KEV JSON into a simple dict: CVE ID -> details.

    Returns a dict like:
        {
            "CVE-2021-44228": {
                "vendor": "Apache",
                "product": "Log4j2",
                "name": "Apache Log4j2 Remote Code Execution Vulnerability",
                "date_added": date(2021, 12, 10),
                "due_date": date(2021, 12, 24),
                "ransomware_use": True,
                "description": "...",
            },
            ...
        }

    Entries without a usable CVE ID are skipped. A missing due date is
    kept as None (it only means "no CISA deadline on file").
    """
    entries = {}
    for item in data.get("vulnerabilities", []):
        cve_id = (item.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        entries[cve_id] = {
            "vendor": item.get("vendorProject", ""),
            "product": item.get("product", ""),
            "name": item.get("vulnerabilityName", ""),
            "date_added": _parse_date(item.get("dateAdded")),
            "due_date": _parse_date(item.get("dueDate")),
            # CISA writes "Known" when the CVE is tied to ransomware.
            "ransomware_use": (item.get("knownRansomwareCampaignUse") or "")
            .strip()
            .lower()
            == "known",
            "description": item.get("shortDescription", ""),
        }
    return entries
