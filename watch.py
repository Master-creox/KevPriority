"""Watch mode: run KevPriority on a loop and report only what changed.

Why this exists: the one-shot run (`python kevpriority.py`) answers
"what should I patch first, right now?". Watch mode answers the next
question: "what is NEW since I last looked?" You start it once, leave it
running, and every cycle it scans the live CISA KEV feed + EPSS scores,
compares the result with the previous run, and tells you only what
changed. Nothing new means a quiet cycle — no spam.

What counts as a change (compared with the last successful run):
    new_in_kev        - a CVE appeared in the CISA KEV list (or joined it)
    moved_to_act_now  - a CVE's band moved up into ACT NOW
    epss_jump         - a CVE's EPSS score rose by 0.20 or more
    due_changed       - a CVE's CISA due date changed

How it remembers: a state file (state.json, next to kevpriority.py)
stores CVE -> {score, band, epss, due, in_kev} from the last successful
run. The first watch run only saves this baseline — it does NOT report
every CVE as "new". The state file is local only and gitignored; it is
never uploaded anywhere.

What each cycle writes (into the reports folder):
    changes-YYYYMMDD-HHMMSS.txt   - human-readable "what changed" report
    changes-YYYYMMDD-HHMMSS.json  - the same changes as JSON
    watch.log                     - one short line per cycle (audit trail)

A cycle whose scan fails (network down, feed moved) does NOT update the
state file and does NOT write a changes report — it logs the failure and
tries again next cycle. A failed scan can never make real changes look
like "nothing changed".

Only the standard library is used here. Nothing here talks to the
network itself; the scan function is injected by the caller
(kevpriority.py), so tests can feed it canned data.
"""

import json
import time
from datetime import datetime
from pathlib import Path

# An EPSS rise of this much (or more) counts as a jump worth reporting.
EPSS_JUMP_THRESHOLD = 0.20

STATE_FILENAME = "state.json"
LOG_FILENAME = "watch.log"
CHANGES_TEXT_PREFIX = "changes-"
CHANGES_JSON_PREFIX = "changes-"

# Fixed order for the changes report: most urgent first.
KIND_ORDER = {
    "new_in_kev": 0,
    "moved_to_act_now": 1,
    "epss_jump": 2,
    "due_changed": 3,
}

KIND_TITLES = {
    "new_in_kev": "NEW IN KEV",
    "moved_to_act_now": "MOVED TO ACT NOW",
    "epss_jump": "EPSS JUMP",
    "due_changed": "DUE DATE CHANGED",
}


def snapshot_from_ranked(ranked):
    """Turn a ranked list into a state snapshot: CVE -> tracked fields.

    Only the fields the diff needs are kept, so the state file stays
    small and readable.
    """
    snapshot = {}
    for item in ranked:
        snapshot[item["cve"]] = {
            "score": item["score"],
            "band": item["band"],
            "epss": item["epss"],
            "due": item["due_date"],
            "in_kev": item["in_kev"],
        }
    return snapshot


def load_state(state_path):
    """Load the state file. Returns the snapshot dict, or None when the
    file is missing, empty, or not valid JSON (a corrupt state is treated
    as "no baseline yet" so the next run re-baselines instead of crashing).
    """
    try:
        raw = Path(state_path).read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    entries = data.get("cves")
    if not isinstance(entries, dict):
        return None
    return entries


def save_state(state_path, snapshot, generated_at=None):
    """Write the state file: the snapshot plus when it was taken."""
    generated_at = generated_at or datetime.now().strftime("%Y-%m-%d %H:%M")
    payload = {"generated_at": generated_at, "cves": snapshot}
    state_path = Path(state_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _epss_of(entry):
    """The EPSS value from a snapshot entry, or None when unknown."""
    value = entry.get("epss") if isinstance(entry, dict) else None
    return value if isinstance(value, (int, float)) else None


def diff_snapshots(old, new):
    """Compare two snapshots and return the list of changes.

    Each change is a dict: {cve, kind, detail, old, new}. One CVE can
    produce several changes (e.g. new in KEV *and* moved to ACT NOW) —
    each fact is reported on its own line. The list is ordered by kind
    (most urgent first), then by CVE ID, so output is deterministic.
    """
    changes = []
    for cve in sorted(new):
        current = new[cve]
        previous = old.get(cve)
        if previous is None:
            # A CVE we have never seen before. Only KEV additions are
            # news: a CVE that merely gained an EPSS score is not.
            if current["in_kev"]:
                changes.append(
                    {
                        "cve": cve,
                        "kind": "new_in_kev",
                        "detail": (
                            "New in the CISA KEV list - confirmed "
                            "exploited in the wild "
                            f"(score {current['score']}, "
                            f"{current['band']}, due "
                            f"{current['due'] or 'no due date on file'})."
                        ),
                        "old": None,
                        "new": dict(current),
                    }
                )
            continue

        if current["in_kev"] and not previous["in_kev"]:
            changes.append(
                {
                    "cve": cve,
                    "kind": "new_in_kev",
                    "detail": (
                        "Joined the CISA KEV list - confirmed exploited "
                        "in the wild "
                        f"(score {current['score']}, {current['band']}, "
                        f"due {current['due'] or 'no due date on file'})."
                    ),
                    "old": dict(previous),
                    "new": dict(current),
                }
            )

        if current["band"] == "ACT NOW" and previous["band"] != "ACT NOW":
            changes.append(
                {
                    "cve": cve,
                    "kind": "moved_to_act_now",
                    "detail": (
                        "Moved into ACT NOW "
                        f"(was {previous['band']}, score "
                        f"{previous['score']} -> {current['score']})."
                    ),
                    "old": dict(previous),
                    "new": dict(current),
                }
            )

        old_epss = _epss_of(previous)
        new_epss = _epss_of(current)
        if old_epss is not None and new_epss is not None:
            jump = round(new_epss - old_epss, 4)
            if jump >= EPSS_JUMP_THRESHOLD:
                changes.append(
                    {
                        "cve": cve,
                        "kind": "epss_jump",
                        "detail": (
                            f"EPSS {old_epss:.2f} -> {new_epss:.2f} "
                            f"(+{jump:.2f})."
                        ),
                        "old": dict(previous),
                        "new": dict(current),
                    }
                )

        if current["due"] != previous["due"]:
            changes.append(
                {
                    "cve": cve,
                    "kind": "due_changed",
                    "detail": (
                        "Due date "
                        f"{previous['due'] or 'none'} -> "
                        f"{current['due'] or 'none'}."
                    ),
                    "old": dict(previous),
                    "new": dict(current),
                }
            )

    changes.sort(key=lambda change: (KIND_ORDER[change["kind"]], change["cve"]))
    return changes


def build_changes_text(changes, generated_at, tracked_total, cycle, baseline=False):
    """Build the human-readable "what changed" report as one string."""
    lines = []
    lines.append(f"KevPriority - What Changed (watch cycle {cycle})")
    lines.append("=" * 60)
    lines.append(f"Generated : {generated_at}")
    lines.append(f"CVEs tracked : {tracked_total}")
    lines.append(f"Changes found : {len(changes)}")
    lines.append("")
    if baseline:
        lines.append(
            "Baseline saved. This first run only records the current "
            "state - nothing is reported as new."
        )
        lines.append("")
    if not changes:
        if not baseline:
            lines.append("No changes since the last run.")
            lines.append("")
        return "\n".join(lines) + "\n"
    for kind in ("new_in_kev", "moved_to_act_now", "epss_jump", "due_changed"):
        group = [change for change in changes if change["kind"] == kind]
        lines.append(f"{KIND_TITLES[kind]} ({len(group)})")
        for change in group:
            lines.append(f"  - {change['cve']}")
            lines.append(f"    {change['detail']}")
        lines.append("")
    return "\n".join(lines) + "\n"


def build_changes_json(changes, generated_at, tracked_total, cycle, baseline=False):
    """Build the changes report dict (same changes as the text report)."""
    return {
        "tool": "KevPriority",
        "mode": "watch",
        "generated_at": generated_at,
        "cycle": cycle,
        "baseline": baseline,
        "tracked_total": tracked_total,
        "changes_count": len(changes),
        "changes": changes,
    }


def write_changes_reports(changes, output_dir, generated_at, tracked_total, cycle,
                          baseline=False, now=None):
    """Write the timestamped changes report (text + JSON) and return the
    two paths. The filename stamp comes from `now` (defaults to the
    current time) so tests can pin it."""
    now = now or datetime.now()
    stamp = now.strftime("%Y%m%d-%H%M%S")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    text_path = output_dir / f"{CHANGES_TEXT_PREFIX}{stamp}.txt"
    json_path = output_dir / f"{CHANGES_JSON_PREFIX}{stamp}.json"
    text_path.write_text(
        build_changes_text(changes, generated_at, tracked_total, cycle, baseline),
        encoding="utf-8",
    )
    json_path.write_text(
        json.dumps(
            build_changes_json(
                changes, generated_at, tracked_total, cycle, baseline
            ),
            indent=2,
        ),
        encoding="utf-8",
    )
    return text_path, json_path


def append_watch_log(log_path, line):
    """Append one line to the watch log, creating it when needed."""
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(line.rstrip("\n") + "\n")


def run_watch_cycle(scan_fn, state_path, output_dir, cycle, now=None):
    """Run one watch cycle.

    scan_fn is a zero-argument callable returning
    (ranked, source_label, kev_total, epss_total) — the same full scan
    the one-shot run does. It is injected so tests can feed canned data.

    Returns (changes, ok): ok is False when the scan failed, in which
    case the state file is left untouched and no changes report is
    written.
    """
    now = now or datetime.now()
    generated_at = now.strftime("%Y-%m-%d %H:%M")
    output_dir = Path(output_dir)
    log_path = output_dir / LOG_FILENAME
    try:
        ranked, _source_label, _kev_total, _epss_total = scan_fn()
    except (Exception, SystemExit) as error:
        reason = str(error) or type(error).__name__
        print(f"Cycle {cycle}: scan failed ({reason}). State unchanged; "
              "will retry next cycle.", flush=True)
        append_watch_log(
            log_path,
            f"{generated_at} cycle={cycle} FAILED: {reason}",
        )
        return [], False

    snapshot = snapshot_from_ranked(ranked)
    old_state = load_state(state_path)
    baseline = old_state is None
    changes = [] if baseline else diff_snapshots(old_state, snapshot)
    save_state(state_path, snapshot, generated_at)
    text_path, json_path = write_changes_reports(
        changes, output_dir, generated_at, len(snapshot), cycle,
        baseline=baseline, now=now,
    )

    if baseline:
        print(
            f"Cycle {cycle}: baseline saved, {len(snapshot)} CVEs tracked. "
            "Nothing reported as new on the first run.",
            flush=True,
        )
        summary = (
            f"{generated_at} cycle={cycle} baseline saved, "
            f"{len(snapshot)} CVEs tracked, 0 changes"
        )
    elif not changes:
        print(
            f"Cycle {cycle}: no changes since the last run "
            f"({len(snapshot)} CVEs tracked).",
            flush=True,
        )
        summary = (
            f"{generated_at} cycle={cycle} no changes, "
            f"{len(snapshot)} CVEs tracked"
        )
    else:
        print(
            build_changes_text(
                changes, generated_at, len(snapshot), cycle
            ),
            flush=True,
        )
        counts = {
            kind: sum(1 for c in changes if c["kind"] == kind)
            for kind in KIND_ORDER
        }
        summary = (
            f"{generated_at} cycle={cycle} {len(changes)} changes "
            f"({counts['new_in_kev']} new in KEV, "
            f"{counts['moved_to_act_now']} to ACT NOW, "
            f"{counts['epss_jump']} EPSS jumps, "
            f"{counts['due_changed']} due changes), "
            f"{len(snapshot)} CVEs tracked"
        )
    append_watch_log(log_path, summary)
    print(f"Changes report: {text_path} , {json_path}", flush=True)
    return changes, True


def watch_loop(scan_fn, state_path, output_dir, interval_hours,
               max_cycles=0, sleep_fn=time.sleep):
    """Run watch cycles forever (or for max_cycles cycles when > 0).

    interval_hours is the wait between cycles. Ctrl+C stops the loop
    cleanly. Returns 0 on a clean stop.
    """
    print(
        "KevPriority watch mode started - scanning every "
        f"{interval_hours} hour(s). Press Ctrl+C to stop.",
        flush=True,
    )
    cycle = 0
    try:
        while max_cycles == 0 or cycle < max_cycles:
            cycle += 1
            run_watch_cycle(scan_fn, state_path, output_dir, cycle)
            if max_cycles == 0 or cycle < max_cycles:
                sleep_fn(interval_hours * 3600)
    except KeyboardInterrupt:
        print("\nWatch stopped by user.", flush=True)
    return 0
