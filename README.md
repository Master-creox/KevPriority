# KevPriority — Patch This First

KevPriority tells you **which vulnerability to patch first**, using the same
priority CISA itself recommends: the **CISA Known Exploited Vulnerabilities
(KEV)** catalog plus the free **EPSS** score from FIRST.org.

```text
$ python kevpriority.py --demo

Rank  Score  Band     CVE              KEV   EPSS    Due date
------------------------------------------------------------
1     99.5   ACT NOW  CVE-2021-44228   YES   0.95    2022-12-24
2     98.8   ACT NOW  CVE-2023-4966    YES   0.88    2023-11-08
3     87.2   HIGH     CVE-2024-21893   YES   0.72    2026-11-27
4     86.1   HIGH     CVE-2023-20198   YES   0.61    2026-11-29
5     74.5   HIGH     CVE-2022-22965   YES   0.45    2027-03-15
6     73.0   HIGH     CVE-2023-48795   YES   0.30    2027-06-30
7     38.5   MEDIUM   CVE-2024-6387    no    0.55    -
8     5.6    LOW      CVE-2023-38408   no    0.08    -
```

## Why KEV + EPSS, not CVSS alone?

CVSS measures how bad a vulnerability *would* be if exploited. It does not
say whether anyone is actually exploiting it. In practice, teams drown in
"Critical" CVEs and patch in the wrong order.

- **CISA KEV** is the list of vulnerabilities *confirmed* exploited in the
  wild, with a remediation due date. If a CVE is on this list, attackers are
  already using it. That is the strongest possible "patch this first" signal.
- **EPSS** estimates the probability (0–1) that a CVE will be exploited in
  the next 30 days. It orders everything that is not (yet) in KEV.

So the rule is simple: **confirmed exploitation beats predicted risk, and
predicted risk beats severity scores.**

## How the ranking works

Every CVE gets one priority score from 0 to 100. KEV entries always score
above non-KEV entries, so a confirmed-exploited CVE can never sit below a
merely-predicted one.

| Situation | Score |
| --- | --- |
| In KEV, due date already passed (overdue) | 90 + 10 × EPSS |
| In KEV, due within the next 7 days | 80 + 10 × EPSS |
| In KEV, due later (or no due date on file) | 70 + 10 × EPSS |
| Not in KEV | EPSS × 70 |

Bands are labels only — the score is what orders the list:

| Band | Meaning |
| --- | --- |
| ACT NOW (90–100) | Exploited in the wild and overdue. Patch first. |
| HIGH (70–89) | In the CISA KEV list. Patch in this cycle. |
| MEDIUM (30–69) | Not confirmed exploited, but EPSS says likely. |
| LOW (0–29) | No confirmed exploitation, low predicted chance. |

The full logic, with comments, is in `ranking.py`.

## Setup

- Python 3.10 or newer. No packages to install — standard library only.
- Internet access for live runs (the two public feeds). No API key, no
  account, no paid service.

```bash
git clone https://github.com/Master-creox/KevPriority.git
cd KevPriority
python kevpriority.py --demo   # works with no internet
```

## Usage

```bash
# Live run: download the current KEV catalog + EPSS scores, show top 20
python kevpriority.py

# Demo run on the bundled sample data (no internet needed)
python kevpriority.py --demo

# Show only the top 10
python kevpriority.py --top 10

# Use your own files instead of the live sources
python kevpriority.py --kev-file my_kev.json --epss-file my_epss.csv

# Write reports somewhere else
python kevpriority.py --output-dir my_reports
```

Every run prints the ranked list and writes two files into `reports/`:

- `kevpriority-report.txt` — the human-readable ranked report
- `kevpriority-report.json` — the same ranking as JSON, for scripts and
  dashboards

If the EPSS API cannot be reached, the tool warns you and still ranks by
KEV due date alone. If the KEV feed cannot be reached, it stops and tells
you to check your connection or use `--demo`.

## Data sources (both free and public)

| Source | What it is | URL |
| --- | --- | --- |
| CISA KEV catalog | Vulnerabilities confirmed exploited in the wild, with due dates | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| FIRST.org EPSS API | Probability of exploitation in the next 30 days | `https://api.first.org/data/v1/epss?cve=CVE-...` |

The files in `data/` (`sample_kev.json`, `sample_epss.json`) are **samples
for the demo only** — small hand-made files in the real formats, with
illustrative EPSS values. They are clearly marked as samples. Live runs
never use them.

## Project structure

```text
KevPriority/
├── kevpriority.py   # CLI entry point (argparse, orchestration)
├── kev.py           # CISA KEV catalog: download + parse
├── epss.py          # EPSS API + local EPSS files (JSON/CSV)
├── ranking.py       # priority score, bands, reasons
├── report.py        # plain-text + JSON report writers
├── data/
│   ├── sample_kev.json    # demo sample (NOT live data)
│   └── sample_epss.json   # demo sample (illustrative EPSS values)
├── tests/
│   └── test_kevpriority.py  # stdlib unittest, no pytest needed
├── requirements.txt  # empty on purpose: stdlib only
├── LICENSE           # MIT
└── README.md
```

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite covers ranking order (KEV beats non-KEV, higher EPSS ranks
higher, overdue beats due-later), score boundaries, KEV/EPSS parsing,
report generation, and the full demo run.

## Honest limits

- **EPSS is a probability, not a guarantee.** A low EPSS does not mean
  "safe", and a high EPSS does not mean "you will be attacked tomorrow".
- **KEV covers only confirmed-exploited CVEs.** A brand-new CVE can be
  dangerous before it appears there.
- **This tool does not know your assets.** A CVE matters more if the
  affected product is actually running in your environment. Use the ranking
  together with your own asset inventory.
- **Scores are a triage aid, not a compliance verdict.** CISA due dates
  apply to US federal agencies; everyone else treats them as a strong
  recommendation, not a legal deadline.

## LinkedIn-ready description

> KevPriority ranks vulnerabilities by what attackers actually exploit. It
> combines CISA's Known Exploited Vulnerabilities catalog with free EPSS
> scores, so confirmed-exploited CVEs come first and everything else is
> ordered by real exploitation probability — not by CVSS severity alone.
> Built in Python with the standard library only; no keys, no paid APIs,
> and a demo mode that runs fully offline.

## License

MIT — see `LICENSE`.
