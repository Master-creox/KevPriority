"""Fetch and parse EPSS scores from FIRST.org.

EPSS (Exploit Prediction Scoring System) is a free, public score that
estimates the probability that a vulnerability will be exploited in the
next 30 days. It is a number between 0 and 1:

    0.95  -> about a 95% chance of exploitation in the next 30 days
    0.02  -> about a 2% chance

EPSS is a *probability*, not a guarantee. A low EPSS does not mean "safe",
and a high EPSS does not mean "you will be attacked tomorrow". KevPriority
uses it only to order vulnerabilities, never as a yes/no verdict.

Public API (no key needed, JSON):
    https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2023-4966

One request returns:
    {
        "status": "OK",
        "data": [
            {"cve": "CVE-2021-44228", "epss": "0.97546",
             "percentile": "0.99967", "date": "2026-11-21"}
        ]
    }

Only the standard library is used here (urllib + json + csv).
"""

import csv
import json
import urllib.parse
import urllib.request

# Official public EPSS API. No API key, no account, no login.
EPSS_API_URL = "https://api.first.org/data/v1/epss"

USER_AGENT = "KevPriority/1.0 (vulnerability prioritization; +https://github.com)"

# The API accepts at most 100 CVEs per request, so large lists are split.
API_BATCH_SIZE = 100


def fetch_epss_scores(cve_ids, timeout=60, batch_size=API_BATCH_SIZE):
    """Ask the EPSS API for scores and return {CVE ID: details}.

    Details look like: {"epss": 0.975, "percentile": 0.999, "date": "2026-11-21"}
    CVEs the API does not know are simply left out of the result.
    Raises URLError / TimeoutError if the API cannot be reached.
    """
    scores = {}
    cve_ids = sorted({cve.strip().upper() for cve in cve_ids if cve})
    for start in range(0, len(cve_ids), batch_size):
        batch = cve_ids[start:start + batch_size]
        query = urllib.parse.urlencode({"cve": ",".join(batch)})
        request = urllib.request.Request(
            EPSS_API_URL + "?" + query, headers={"User-Agent": USER_AGENT}
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        scores.update(parse_epss_response(payload))
    return scores


def parse_epss_response(payload):
    """Parse one EPSS API response dict into {CVE ID: details}."""
    scores = {}
    for row in payload.get("data", []):
        cve_id = (row.get("cve") or "").strip().upper()
        try:
            epss = float(row.get("epss"))
        except (TypeError, ValueError):
            continue
        scores[cve_id] = {
            "epss": epss,
            "percentile": _safe_float(row.get("percentile")),
            "date": row.get("date", ""),
        }
    return scores


def _safe_float(value):
    """Convert to float, or None when the value is missing/not a number."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def load_epss_file(path):
    """Load EPSS scores from a local file.

    Two formats are accepted:
    1. JSON: either {"CVE-2021-44228": {"epss": 0.95, ...}, ...}
       or {"data": [{"cve": "CVE-2021-44228", "epss": "0.95"}, ...]}
       or a plain list [{"cve": "...", "epss": 0.95}, ...].
    2. CSV: a header row with at least the columns "cve" and "epss"
       (the official daily EPSS CSV has "cve,epss,percentile").

    Returns {CVE ID: {"epss": float, "percentile": float|None, "date": str}}.
    """
    path = str(path)  # accept both str and pathlib.Path
    if path.lower().endswith(".csv"):
        return _load_epss_csv(path)
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict) and "data" in data:
        return parse_epss_response(data)
    if isinstance(data, list):
        return parse_epss_response({"data": data})
    scores = {}
    for cve_id, details in data.items():
        if isinstance(details, dict):
            try:
                epss = float(details.get("epss"))
            except (TypeError, ValueError):
                continue
            scores[cve_id.strip().upper()] = {
                "epss": epss,
                "percentile": _safe_float(details.get("percentile")),
                "date": details.get("date", ""),
            }
        else:
            try:
                scores[cve_id.strip().upper()] = {
                    "epss": float(details),
                    "percentile": None,
                    "date": "",
                }
            except (TypeError, ValueError):
                continue
    return scores


def _load_epss_csv(path):
    """Load EPSS scores from a CSV file with 'cve' and 'epss' columns."""
    scores = {}
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            cve_id = (row.get("cve") or "").strip().upper()
            try:
                epss = float(row.get("epss"))
            except (TypeError, ValueError):
                continue
            if cve_id:
                scores[cve_id] = {
                    "epss": epss,
                    "percentile": _safe_float(row.get("percentile")),
                    "date": row.get("date", ""),
                }
    return scores
