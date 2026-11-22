#!/usr/bin/env python3
"""KevPriority - patch the exploited vulnerabilities FIRST.

Usage:
    python kevpriority.py                  # live run: CISA KEV + EPSS, top 20
    python kevpriority.py --demo           # demo run on bundled sample data
    python kevpriority.py --top 10         # show only the top 10
    python kevpriority.py --kev-file data/sample_kev.json --epss-file data/sample_epss.json
    python kevpriority.py --output-dir my_reports

What it does, in one line: it downloads the public CISA KEV catalog
(confirmed-exploited vulnerabilities) and free EPSS scores (probability of
exploitation in the next 30 days), then ranks CVEs so the ones attackers
are already using come first.

No API keys, no accounts, no paid services. Python 3.10+ and the standard
library only - nothing to install.
"""

import argparse
import sys
from pathlib import Path

from epss import fetch_epss_scores, load_epss_file
from kev import fetch_kev_catalog, load_kev_file, parse_kev_catalog
from ranking import rank_items
from report import write_reports

# Sample files bundled with the project so --demo works with no internet.
BASE_DIR = Path(__file__).resolve().parent
SAMPLE_KEV_FILE = BASE_DIR / "data" / "sample_kev.json"
SAMPLE_EPSS_FILE = BASE_DIR / "data" / "sample_epss.json"


def build_parser():
    """Define the command-line options."""
    parser = argparse.ArgumentParser(
        description=(
            "Rank vulnerabilities by what attackers actually exploit: "
            "CISA KEV first, then EPSS score."
        )
    )
    parser.add_argument(
        "--kev-file",
        help="Use a local KEV JSON file instead of downloading the live feed.",
    )
    parser.add_argument(
        "--epss-file",
        help="Use a local EPSS file (JSON or CSV) instead of the live API.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run on the bundled sample data. No internet needed.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="How many top-ranked CVEs to show (default: 20).",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Where to write the text + JSON reports (default: reports).",
    )
    return parser


def load_inputs(args):
    """Load KEV entries and EPSS scores, from files or live sources.

    Returns (kev_entries, epss_scores, source_label).
    Raises SystemExit with a clear message when a live source is down.
    """
    if args.demo:
        kev_data = load_kev_file(SAMPLE_KEV_FILE)
        epss_scores = load_epss_file(SAMPLE_EPSS_FILE)
        label = "SAMPLE DATA (demo run - bundled sample files, not live data)"
        return parse_kev_catalog(kev_data), epss_scores, label

    # --- KEV catalog: local file wins, otherwise download the live feed. ---
    if args.kev_file:
        kev_data = load_kev_file(args.kev_file)
        kev_label = f"local KEV file: {args.kev_file}"
    else:
        try:
            kev_data = fetch_kev_catalog()
        except Exception as error:  # network down, feed moved, timeout, ...
            print(
                "ERROR: could not download the live CISA KEV catalog.\n"
                f"Reason: {error}\n"
                "Check your internet connection, or run with --demo to use\n"
                "the bundled sample data instead.",
                file=sys.stderr,
            )
            raise SystemExit(2)
        kev_label = "live CISA KEV feed"
    kev_entries = parse_kev_catalog(kev_data)
    if not kev_entries:
        print("ERROR: no CVE entries found in the KEV data.", file=sys.stderr)
        raise SystemExit(2)

    # --- EPSS scores: local file wins, otherwise ask the live API. ---
    if args.epss_file:
        epss_scores = load_epss_file(args.epss_file)
        epss_label = f"local EPSS file: {args.epss_file}"
    else:
        try:
            epss_scores = fetch_epss_scores(list(kev_entries))
        except Exception as error:
            # EPSS is the tie-breaker, not the core: keep going with KEV
            # order alone and say so clearly, instead of failing outright.
            print(
                "WARNING: could not reach the EPSS API "
                f"({error}). Ranking by KEV due date only.",
                file=sys.stderr,
            )
            epss_scores = {}
        epss_label = "live EPSS API (FIRST.org)"
    return kev_entries, epss_scores, f"{kev_label} + {epss_label}"


def run(argv=None):
    """Run the tool. Returns an exit code (0 = ok)."""
    args = build_parser().parse_args(argv)
    if args.top < 1:
        print("ERROR: --top must be at least 1.", file=sys.stderr)
        return 2

    kev_entries, epss_scores, source_label = load_inputs(args)

    # Rank every CVE we know about: all KEV CVEs, plus any CVE that has
    # an EPSS score (so --epss-file can add CVEs that are not in KEV).
    cve_ids = sorted(set(kev_entries) | set(epss_scores))
    ranked = rank_items(cve_ids, kev_entries, epss_scores)
    total_considered = len(ranked)
    ranked = ranked[: args.top]

    text_path, json_path = write_reports(
        ranked,
        Path(args.output_dir),
        source_label,
        kev_total=len(kev_entries),
        epss_total=len(epss_scores),
    )

    # Print the text report to the terminal as well.
    print(text_path.read_text(encoding="utf-8"))
    print(f"Showing top {len(ranked)} of {total_considered} CVEs considered.")
    print(f"Reports written to:\n  {text_path}\n  {json_path}")
    return 0


def main():
    raise SystemExit(run())


if __name__ == "__main__":
    main()
