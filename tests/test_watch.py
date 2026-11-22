"""Unit tests for KevPriority watch mode (standard library unittest only).

Run from the project root:
    python -m unittest discover -s tests -v

Watch tests never touch the network: every cycle is fed by an injected
scan function returning canned ranked lists. The fixed reference date
(2026-11-22) keeps due-date behaviour deterministic.
"""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from datetime import date, datetime
from pathlib import Path

# Make the project root importable (tests live in tests/).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ranking import rank_items  # noqa: E402
from watch import (  # noqa: E402
    diff_snapshots,
    load_state,
    run_watch_cycle,
    snapshot_from_ranked,
    watch_loop,
)

TODAY = date(2026, 11, 22)
NOW = datetime(2026, 11, 22, 16, 30, 0)


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


def make_ranked(kev_entries, epss_scores):
    """Rank a canned KEV/EPSS pair and return the ranked list."""
    cve_ids = sorted(set(kev_entries) | set(epss_scores))
    return rank_items(cve_ids, kev_entries, epss_scores, today=TODAY)


def make_scan(ranked):
    """Build a scan function returning a fixed ranked list."""
    def scan():
        return ranked, "TEST", len(ranked), len(ranked)

    return scan


def kinds_for(changes, cve):
    """The set of change kinds reported for one CVE."""
    return {change["kind"] for change in changes if change["cve"] == cve}


class TestDiffSnapshots(unittest.TestCase):
    def test_new_kev_cve_detected(self):
        old = snapshot_from_ranked(
            make_ranked(
                {"CVE-2021-0001": make_kev_entry(due=date(2026, 11, 1))},
                {"CVE-2021-0001": {"epss": 0.5}},
            )
        )
        new = snapshot_from_ranked(
            make_ranked(
                {
                    "CVE-2021-0001": make_kev_entry(due=date(2026, 11, 1)),
                    "CVE-2026-0001": make_kev_entry(due=date(2026, 12, 1)),
                },
                {"CVE-2021-0001": {"epss": 0.5},
                 "CVE-2026-0001": {"epss": 0.9}},
            )
        )
        changes = diff_snapshots(old, new)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["kind"], "new_in_kev")
        self.assertEqual(changes[0]["cve"], "CVE-2026-0001")

    def test_cve_joining_kev_detected(self):
        old = snapshot_from_ranked(
            make_ranked({}, {"CVE-2021-0002": {"epss": 0.5}})
        )
        new = snapshot_from_ranked(
            make_ranked(
                {"CVE-2021-0002": make_kev_entry(due=date(2027, 1, 1))},
                {"CVE-2021-0002": {"epss": 0.5}},
            )
        )
        changes = diff_snapshots(old, new)
        # Joining KEV also sets a due date where there was none.
        self.assertEqual(
            kinds_for(changes, "CVE-2021-0002"),
            {"new_in_kev", "due_changed"},
        )

    def test_epss_jump_detected(self):
        old = snapshot_from_ranked(
            make_ranked(
                {"CVE-2021-0001": make_kev_entry(due=date(2027, 1, 1))},
                {"CVE-2021-0001": {"epss": 0.50}},
            )
        )
        new = snapshot_from_ranked(
            make_ranked(
                {"CVE-2021-0001": make_kev_entry(due=date(2027, 1, 1))},
                {"CVE-2021-0001": {"epss": 0.75}},
            )
        )
        changes = diff_snapshots(old, new)
        self.assertEqual(kinds_for(changes, "CVE-2021-0001"), {"epss_jump"})
        self.assertIn("+0.25", changes[0]["detail"])

    def test_small_epss_rise_ignored(self):
        old = snapshot_from_ranked(
            make_ranked(
                {"CVE-2021-0001": make_kev_entry(due=date(2027, 1, 1))},
                {"CVE-2021-0001": {"epss": 0.50}},
            )
        )
        new = snapshot_from_ranked(
            make_ranked(
                {"CVE-2021-0001": make_kev_entry(due=date(2027, 1, 1))},
                {"CVE-2021-0001": {"epss": 0.65}},
            )
        )
        self.assertEqual(diff_snapshots(old, new), [])

    def test_no_change_cycle_reports_nothing(self):
        ranked = make_ranked(
            {"CVE-2021-0001": make_kev_entry(due=date(2027, 1, 1))},
            {"CVE-2021-0001": {"epss": 0.5}},
        )
        snapshot = snapshot_from_ranked(ranked)
        self.assertEqual(diff_snapshots(snapshot, snapshot_from_ranked(ranked)), [])

    def test_moved_to_act_now_detected(self):
        old = snapshot_from_ranked(
            make_ranked(
                {"CVE-2021-0001": make_kev_entry(due=date(2027, 6, 1))},
                {"CVE-2021-0001": {"epss": 0.10}},
            )
        )
        new = snapshot_from_ranked(
            make_ranked(
                {"CVE-2021-0001": make_kev_entry(due=date(2026, 11, 1))},
                {"CVE-2021-0001": {"epss": 0.10}},
            )
        )
        changes = diff_snapshots(old, new)
        # The due date moved into the past, which also moved the band.
        self.assertEqual(
            kinds_for(changes, "CVE-2021-0001"),
            {"moved_to_act_now", "due_changed"},
        )

    def test_due_date_change_detected(self):
        old = snapshot_from_ranked(
            make_ranked(
                {"CVE-2021-0001": make_kev_entry(due=date(2027, 1, 1))},
                {"CVE-2021-0001": {"epss": 0.5}},
            )
        )
        new = snapshot_from_ranked(
            make_ranked(
                {"CVE-2021-0001": make_kev_entry(due=date(2027, 2, 1))},
                {"CVE-2021-0001": {"epss": 0.5}},
            )
        )
        changes = diff_snapshots(old, new)
        self.assertEqual(kinds_for(changes, "CVE-2021-0001"), {"due_changed"})

    def test_non_kev_newcomer_not_reported(self):
        old = snapshot_from_ranked(
            make_ranked(
                {"CVE-2021-0001": make_kev_entry(due=date(2027, 1, 1))},
                {"CVE-2021-0001": {"epss": 0.5}},
            )
        )
        new = snapshot_from_ranked(
            make_ranked(
                {"CVE-2021-0001": make_kev_entry(due=date(2027, 1, 1))},
                {"CVE-2021-0001": {"epss": 0.5},
                 "CVE-2024-9999": {"epss": 0.5}},
            )
        )
        # A CVE that merely gained an EPSS score (not KEV) is not news.
        self.assertEqual(diff_snapshots(old, new), [])


class TestWatchCycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state_path = self.root / "state.json"
        self.out_dir = self.root / "reports"

    def tearDown(self):
        self.tmp.cleanup()

    def base_ranked(self):
        return make_ranked(
            {"CVE-2021-0001": make_kev_entry(due=date(2027, 1, 1))},
            {"CVE-2021-0001": {"epss": 0.5}},
        )

    def run_cycle(self, scan, cycle, now=NOW):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = run_watch_cycle(
                scan, self.state_path, self.out_dir, cycle, now=now
            )
        return result, stdout.getvalue()

    def test_first_run_is_baseline_not_spam(self):
        (changes, ok), output = self.run_cycle(make_scan(self.base_ranked()), 1)
        self.assertTrue(ok)
        self.assertEqual(changes, [])
        self.assertIn("baseline saved", output.lower())
        self.assertIn("1 CVEs tracked", output)
        state = load_state(self.state_path)
        self.assertEqual(set(state), {"CVE-2021-0001"})
        stored = json.loads(
            (self.out_dir / "changes-20261122-163000.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertTrue(stored["baseline"])
        self.assertEqual(stored["changes_count"], 0)

    def test_second_run_reports_new_cve(self):
        self.run_cycle(make_scan(self.base_ranked()), 1)
        extended = make_ranked(
            {
                "CVE-2021-0001": make_kev_entry(due=date(2027, 1, 1)),
                "CVE-2026-0001": make_kev_entry(due=date(2026, 12, 1)),
            },
            {"CVE-2021-0001": {"epss": 0.5}, "CVE-2026-0001": {"epss": 0.9}},
        )
        later = datetime(2026, 11, 22, 22, 30, 0)
        (changes, ok), output = self.run_cycle(make_scan(extended), 2, now=later)
        self.assertTrue(ok)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["kind"], "new_in_kev")
        self.assertEqual(changes[0]["cve"], "CVE-2026-0001")
        # Changes report + log line exist; state now tracks both CVEs.
        stored = json.loads(
            (self.out_dir / "changes-20261122-223000.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(stored["changes_count"], 1)
        self.assertFalse(stored["baseline"])
        self.assertEqual(set(load_state(self.state_path)),
                         {"CVE-2021-0001", "CVE-2026-0001"})
        log_lines = (self.out_dir / "watch.log").read_text(
            encoding="utf-8"
        ).strip().splitlines()
        self.assertEqual(len(log_lines), 2)
        self.assertIn("1 changes", log_lines[1])

    def test_failed_scan_keeps_old_state(self):
        self.run_cycle(make_scan(self.base_ranked()), 1)
        state_before = self.state_path.read_bytes()
        reports_before = sorted(self.out_dir.glob("changes-*.txt"))

        def failing_scan():
            raise RuntimeError("network down")

        (changes, ok), output = self.run_cycle(failing_scan, 2)
        self.assertFalse(ok)
        self.assertEqual(changes, [])
        self.assertEqual(self.state_path.read_bytes(), state_before)
        self.assertEqual(sorted(self.out_dir.glob("changes-*.txt")),
                         reports_before)
        log = (self.out_dir / "watch.log").read_text(encoding="utf-8")
        self.assertIn("FAILED", log)

    def test_watch_loop_runs_n_cycles(self):
        sleeps = []
        code = watch_loop(
            make_scan(self.base_ranked()),
            self.state_path,
            self.out_dir,
            interval_hours=6,
            max_cycles=2,
            sleep_fn=lambda seconds: sleeps.append(seconds),
        )
        self.assertEqual(code, 0)
        self.assertEqual(sleeps, [6 * 3600])  # sleep once, between cycles
        log_lines = (self.out_dir / "watch.log").read_text(
            encoding="utf-8"
        ).strip().splitlines()
        self.assertEqual(len(log_lines), 2)


if __name__ == "__main__":
    unittest.main()
