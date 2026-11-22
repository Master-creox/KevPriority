"""Unit tests for KevPriority (standard library unittest only).

Run from the project root:
    python -m unittest discover -s tests -v

The tests use a fixed reference date (2026-11-22) so due-date behaviour
is deterministic no matter when the suite runs.
"""

import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

# Make the project root importable (tests live in tests/).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from epss import load_epss_file, parse_epss_response  # noqa: E402
from kev import load_kev_file, parse_kev_catalog  # noqa: E402
from ranking import rank_items, score_item  # noqa: E402
from report import build_json_report, build_text_report, write_reports  # noqa: E402
from kevpriority import run  # noqa: E402

TODAY = date(2026, 11, 22)
ROOT = Path(__file__).resolve().parent.parent


def make_kev_entry(due=None, ransomware=False):
    """Build a minimal KEV entry dict for tests."""
    return {
        "vendor": "Test",
        "product": "Test",
        "name": "Test Vulnerability",
        "due_date": due,
        "ransomware_use": ransomware,
        "description": "",
    }


class TestRankingOrder(unittest.TestCase):
    def test_kev_beats_non_kev_even_with_lower_epss(self):
        """A KEV CVE with EPSS 0.10 must outrank a non-KEV CVE with EPSS 0.99."""
        ranked = rank_items(
            ["CVE-2021-0001", "CVE-2021-0002"],
            {"CVE-2021-0001": make_kev_entry(due=date(2027, 1, 1))},
            {"CVE-2021-0001": {"epss": 0.10}, "CVE-2021-0002": {"epss": 0.99}},
            today=TODAY,
        )
        self.assertEqual(ranked[0]["cve"], "CVE-2021-0001")
        self.assertEqual(ranked[1]["cve"], "CVE-2021-0002")

    def test_higher_epss_ranks_higher_within_same_tier(self):
        ranked = rank_items(
            ["CVE-2021-0001", "CVE-2021-0002"],
            {
                "CVE-2021-0001": make_kev_entry(due=date(2027, 1, 1)),
                "CVE-2021-0002": make_kev_entry(due=date(2027, 1, 1)),
            },
            {"CVE-2021-0001": {"epss": 0.20}, "CVE-2021-0002": {"epss": 0.80}},
            today=TODAY,
        )
        self.assertEqual(
            [item["cve"] for item in ranked], ["CVE-2021-0002", "CVE-2021-0001"]
        )

    def test_overdue_kev_beats_due_later_kev(self):
        ranked = rank_items(
            ["CVE-2021-0001", "CVE-2021-0002"],
            {
                "CVE-2021-0001": make_kev_entry(due=date(2026, 11, 1)),  # overdue
                "CVE-2021-0002": make_kev_entry(due=date(2027, 6, 1)),  # later
            },
            {"CVE-2021-0001": {"epss": 0.10}, "CVE-2021-0002": {"epss": 0.90}},
            today=TODAY,
        )
        self.assertEqual(ranked[0]["cve"], "CVE-2021-0001")

    def test_due_soon_kev_beats_due_later_kev(self):
        ranked = rank_items(
            ["CVE-2021-0001", "CVE-2021-0002"],
            {
                "CVE-2021-0001": make_kev_entry(due=date(2026, 11, 25)),  # in 3 days
                "CVE-2021-0002": make_kev_entry(due=date(2027, 6, 1)),
            },
            {"CVE-2021-0001": {"epss": 0.10}, "CVE-2021-0002": {"epss": 0.90}},
            today=TODAY,
        )
        self.assertEqual(ranked[0]["cve"], "CVE-2021-0001")

    def test_tie_broken_by_earliest_due_date(self):
        """Equal scores: the CVE whose due date passed first ranks first."""
        ranked = rank_items(
            ["CVE-2021-0001", "CVE-2021-0002"],
            {
                "CVE-2021-0001": make_kev_entry(due=date(2026, 11, 1)),
                "CVE-2021-0002": make_kev_entry(due=date(2026, 10, 1)),
            },
            {"CVE-2021-0001": {"epss": 0.90}, "CVE-2021-0002": {"epss": 0.90}},
            today=TODAY,
        )
        self.assertEqual(
            [item["cve"] for item in ranked], ["CVE-2021-0002", "CVE-2021-0001"]
        )

    def test_score_boundaries(self):
        """KEV scores are always >= 70; non-KEV scores are always <= 70."""
        kev_item = score_item(
            "CVE-2021-0001", make_kev_entry(due=None), 0.0, today=TODAY
        )
        non_kev_item = score_item("CVE-2021-0002", None, 1.0, today=TODAY)
        self.assertEqual(kev_item["score"], 70.0)
        self.assertEqual(non_kev_item["score"], 70.0)

    def test_missing_epss_is_treated_as_zero(self):
        item = score_item("CVE-2021-0001", None, None, today=TODAY)
        self.assertEqual(item["score"], 0.0)
        self.assertEqual(item["band"], "LOW")

    def test_bands(self):
        self.assertEqual(
            score_item(
                "CVE-2021-0001",
                make_kev_entry(due=date(2026, 11, 1)),
                0.95,
                today=TODAY,
            )["band"],
            "ACT NOW",
        )
        self.assertEqual(score_item("CVE-2021-0002", None, 0.5, today=TODAY)["band"], "MEDIUM")

    def test_reason_mentions_kev_and_due_date(self):
        item = score_item(
            "CVE-2021-0001",
            make_kev_entry(due=date(2026, 11, 1), ransomware=True),
            0.5,
            today=TODAY,
        )
        self.assertIn("KEV", item["reason"])
        self.assertIn("2026-11-01", item["reason"])
        self.assertIn("ransomware", item["reason"].lower())


class TestParsing(unittest.TestCase):
    def test_sample_kev_file_parses(self):
        entries = parse_kev_catalog(load_kev_file(ROOT / "data" / "sample_kev.json"))
        self.assertEqual(len(entries), 6)
        self.assertIn("CVE-2021-44228", entries)
        self.assertEqual(entries["CVE-2021-44228"]["due_date"], date(2022, 12, 24))
        self.assertTrue(entries["CVE-2021-44228"]["ransomware_use"])

    def test_sample_epss_file_parses(self):
        scores = load_epss_file(ROOT / "data" / "sample_epss.json")
        self.assertEqual(len(scores), 8)
        self.assertAlmostEqual(scores["CVE-2021-44228"]["epss"], 0.95)

    def test_epss_csv_parses(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".csv", delete=False, encoding="utf-8"
        ) as handle:
            handle.write("cve,epss,percentile\nCVE-2021-0001,0.42,0.77\n")
            path = handle.name
        try:
            scores = load_epss_file(path)
            self.assertAlmostEqual(scores["CVE-2021-0001"]["epss"], 0.42)
        finally:
            Path(path).unlink()

    def test_epss_api_response_parses(self):
        scores = parse_epss_response(
            {
                "status": "OK",
                "data": [
                    {"cve": "CVE-2021-44228", "epss": "0.97546", "percentile": "0.99967"}
                ],
            }
        )
        self.assertAlmostEqual(scores["CVE-2021-44228"]["epss"], 0.97546)


class TestReports(unittest.TestCase):
    def test_text_and_json_reports_agree(self):
        ranked = rank_items(
            ["CVE-2021-0001", "CVE-2021-0002"],
            {"CVE-2021-0001": make_kev_entry(due=date(2026, 11, 1))},
            {"CVE-2021-0001": {"epss": 0.9}, "CVE-2021-0002": {"epss": 0.1}},
            today=TODAY,
        )
        text = build_text_report(ranked, "TEST", 1, 2)
        data = build_json_report(ranked, "TEST", 1, 2)
        self.assertIn("CVE-2021-0001", text)
        self.assertEqual(data["results"][0]["cve"], "CVE-2021-0001")
        self.assertEqual(data["ranked_count"], 2)

    def test_write_reports_creates_both_files(self):
        ranked = rank_items(
            ["CVE-2021-0001"],
            {"CVE-2021-0001": make_kev_entry(due=date(2026, 11, 1))},
            {"CVE-2021-0001": {"epss": 0.9}},
            today=TODAY,
        )
        with tempfile.TemporaryDirectory() as tmp:
            text_path, json_path = write_reports(
                ranked, Path(tmp), "TEST", 1, 1
            )
            self.assertTrue(text_path.exists())
            self.assertTrue(json_path.exists())
            self.assertIn("CVE-2021-0001", text_path.read_text(encoding="utf-8"))
            stored = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(stored["results"][0]["cve"], "CVE-2021-0001")


class TestDemoMode(unittest.TestCase):
    def test_demo_run_succeeds_and_orders_correctly(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = run(["--demo", "--output-dir", tmp])
            self.assertEqual(code, 0)
            stored = json.loads(
                (Path(tmp) / "kevpriority-report.json").read_text(encoding="utf-8")
            )
            order = [item["cve"] for item in stored["results"]]
            self.assertEqual(
                order,
                [
                    "CVE-2021-44228",
                    "CVE-2023-4966",
                    "CVE-2024-21893",
                    "CVE-2023-20198",
                    "CVE-2022-22965",
                    "CVE-2023-48795",
                    "CVE-2024-6387",
                    "CVE-2023-38408",
                ],
            )
            self.assertIn("SAMPLE", stored["source"])

    def test_top_flag_limits_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = run(["--demo", "--top", "3", "--output-dir", tmp])
            self.assertEqual(code, 0)
            stored = json.loads(
                (Path(tmp) / "kevpriority-report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(stored["results"]), 3)


if __name__ == "__main__":
    unittest.main()
