"""Write the ranked results as a plain-text report and a JSON report.

Both files contain exactly the same ranking; the text file is for humans
(terminal, chat, interview demo) and the JSON file is for tools that want
to read the result automatically (dashboards, scripts, CI).

Nothing here talks to the network. These functions only format data.
"""

import json
from datetime import datetime

TEXT_FILENAME = "kevpriority-report.txt"
JSON_FILENAME = "kevpriority-report.json"


def build_text_report(ranked, source_label, kev_total, epss_total, generated_at=None):
    """Build the plain-text report and return it as one string."""
    generated_at = generated_at or datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = []
    lines.append("KevPriority - Patch This First")
    lines.append("=" * 60)
    lines.append(f"Generated : {generated_at}")
    lines.append(f"Source    : {source_label}")
    lines.append(f"KEV CVEs loaded : {kev_total}")
    lines.append(f"EPSS scores loaded : {epss_total}")
    lines.append(f"CVEs ranked : {len(ranked)}")
    lines.append("")
    lines.append("Rank  Score  Band     CVE              KEV   EPSS    Due date")
    lines.append("-" * 60)
    for index, item in enumerate(ranked, start=1):
        kev_flag = "YES" if item["in_kev"] else "no"
        epss_text = f"{item['epss']:.2f}" if item["epss"] is not None else "n/a"
        due_text = item["due_date"] or "-"
        lines.append(
            f"{index:<5} {item['score']:>5}  {item['band']:<8} "
            f"{item['cve']:<16} {kev_flag:<5} {epss_text:<7} {due_text}"
        )
    lines.append("")
    lines.append("Why each CVE ranks here:")
    lines.append("-" * 60)
    for index, item in enumerate(ranked, start=1):
        lines.append(f"{index}. {item['cve']} (score {item['score']}, {item['band']})")
        lines.append(f"   {item['reason']}")
    lines.append("")
    lines.append("How to read this:")
    lines.append("  ACT NOW  - exploited in the wild and overdue. Patch first.")
    lines.append("  HIGH     - in the CISA KEV list. Patch in this cycle.")
    lines.append("  MEDIUM   - not confirmed exploited, but EPSS says likely.")
    lines.append("  LOW      - no confirmed exploitation, low predicted chance.")
    lines.append("")
    lines.append(
        "Honest limits: EPSS is a probability, not a guarantee. The KEV list "
        "covers only confirmed-exploited CVEs, so a new CVE can be dangerous "
        "before it appears there. Always check your own asset exposure too."
    )
    return "\n".join(lines) + "\n"


def build_json_report(ranked, source_label, kev_total, epss_total, generated_at=None):
    """Build the JSON report dict (same ranking as the text report)."""
    generated_at = generated_at or datetime.now().strftime("%Y-%m-%d %H:%M")
    return {
        "tool": "KevPriority",
        "generated_at": generated_at,
        "source": source_label,
        "kev_cves_loaded": kev_total,
        "epss_scores_loaded": epss_total,
        "ranked_count": len(ranked),
        "results": ranked,
    }


def write_reports(ranked, output_dir, source_label, kev_total, epss_total):
    """Write both report files into output_dir and return their paths."""
    output_dir.mkdir(parents=True, exist_ok=True)
    text_path = output_dir / TEXT_FILENAME
    json_path = output_dir / JSON_FILENAME
    text_path.write_text(
        build_text_report(ranked, source_label, kev_total, epss_total),
        encoding="utf-8",
    )
    json_path.write_text(
        json.dumps(
            build_json_report(ranked, source_label, kev_total, epss_total),
            indent=2,
        ),
        encoding="utf-8",
    )
    return text_path, json_path
