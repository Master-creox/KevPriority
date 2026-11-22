"""The ranking logic: which vulnerability do you patch FIRST?

KevPriority follows the same priority CISA itself recommends:

    1. Fix confirmed-exploited vulnerabilities first (the KEV list).
    2. Among those, fix the ones whose CISA due date is nearest first.
    3. Among everything else, fix the ones most likely to be exploited
       next (highest EPSS score) first.

Why not CVSS alone? CVSS measures how bad a vulnerability *would* be, not
whether anyone is actually exploiting it. A "Critical" CVE nobody uses can
safely wait behind a "High" CVE that is already being exploited in the
wild. KEV tells you what is exploited *now*; EPSS tells you what is
*likely* to be exploited next. Together they answer "what first?".

How the priority score (0-100) is built
---------------------------------------
Every CVE gets one score. KEV entries always score above non-KEV entries,
so a confirmed-exploited CVE can never sit below a merely-predicted one:

    KEV + due date already passed (overdue) :  90 + 10 x EPSS   (90-100)
    KEV + due within the next 7 days        :  80 + 10 x EPSS   (80-90)
    KEV + due later, or no due date on file :  70 + 10 x EPSS   (70-80)
    Not in KEV                              :  EPSS x 70        (0-70)

Bands (labels only, the score is what orders the list):
    90-100  ACT NOW   - exploited in the wild and overdue (or nearly so)
    70-89   HIGH      - in the KEV list, patch in this cycle
    30-69   MEDIUM    - not confirmed exploited, but EPSS says likely
    0-29    LOW       - no confirmed exploitation, low predicted chance

Ties are broken by CVE ID so the output is stable run after run.
"""

from datetime import date

# Days before a KEV due date that count as "due soon".
DUE_SOON_DAYS = 7


def score_item(cve_id, kev_entry, epss, today=None):
    """Score one CVE and explain why it ranks where it does.

    Args:
        cve_id: e.g. "CVE-2021-44228".
        kev_entry: the dict from kev.parse_kev_catalog for this CVE,
            or None when the CVE is not in the KEV list.
        epss: the EPSS score (0-1), or None when no EPSS value is known.
        today: reference date (defaults to today; tests pass a fixed date).

    Returns a dict with cve, in_kev, epss, due date, score, band and a
    one-line human-readable reason.
    """
    today = today or date.today()
    epss_value = epss if epss is not None else 0.0

    if kev_entry is None:
        score = round(epss_value * 70, 1)
        band = _band(score)
        if epss is None:
            reason = (
                "Not in the CISA KEV list and no EPSS score available; "
                "no evidence of exploitation, so it waits."
            )
        else:
            reason = (
                "Not in the CISA KEV list, but EPSS estimates a "
                f"{epss_value:.0%} chance of exploitation in the next 30 days."
            )
        return {
            "cve": cve_id,
            "in_kev": False,
            "epss": epss,
            "due_date": None,
            "score": score,
            "band": band,
            "reason": reason,
        }

    # The CVE is in KEV: confirmed exploited. The due date decides the tier.
    due = kev_entry.get("due_date")
    if due is not None and due < today:
        tier_base, tier_label = 90, "overdue"
    elif due is not None and (due - today).days <= DUE_SOON_DAYS:
        tier_base, tier_label = 80, "due soon"
    else:
        tier_base, tier_label = 70, "due later"

    score = round(tier_base + 10 * epss_value, 1)
    score = min(score, 100.0)  # never above 100, even for EPSS = 1.0
    band = _band(score)

    due_text = due.isoformat() if due else "no due date on file"
    ransomware = ""
    if kev_entry.get("ransomware_use"):
        ransomware = " Linked to a known ransomware campaign."
    if epss is None:
        epss_text = "no EPSS score available"
    else:
        epss_text = f"EPSS {epss_value:.2f} ({epss_value:.0%} in 30 days)"
    reason = (
        f"In the CISA KEV list - confirmed exploited in the wild; "
        f"due {due_text} ({tier_label}); {epss_text}.{ransomware}"
    )
    return {
        "cve": cve_id,
        "in_kev": True,
        "epss": epss,
        "due_date": due.isoformat() if due else None,
        "vendor": kev_entry.get("vendor", ""),
        "product": kev_entry.get("product", ""),
        "name": kev_entry.get("name", ""),
        "ransomware_use": bool(kev_entry.get("ransomware_use")),
        "score": score,
        "band": band,
        "reason": reason,
    }


def _band(score):
    """Turn a 0-100 score into a plain-English band label."""
    if score >= 90:
        return "ACT NOW"
    if score >= 70:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def rank_items(cve_ids, kev_entries, epss_scores, today=None):
    """Rank a list of CVE IDs and return the ranked items, best first.

    cve_ids: list of CVE IDs to rank.
    kev_entries: dict from kev.parse_kev_catalog (CVE -> details).
    epss_scores: dict from epss (CVE -> {"epss": float, ...}).
    today: reference date for due-date math (defaults to today).
    """
    today = today or date.today()
    ranked = []
    for cve_id in cve_ids:
        cve_id = cve_id.strip().upper()
        if not cve_id:
            continue
        epss_entry = epss_scores.get(cve_id, {})
        epss = epss_entry.get("epss")
        ranked.append(
            score_item(cve_id, kev_entries.get(cve_id), epss, today=today)
        )
    # Highest score first. Ties are broken by due date (most overdue
    # first), then CVE ID, so the output is deterministic.
    def sort_key(item):
        due = item.get("due_date") or "9999-12-31"  # no due date sorts last
        return (-item["score"], due, item["cve"])

    ranked.sort(key=sort_key)
    return ranked
