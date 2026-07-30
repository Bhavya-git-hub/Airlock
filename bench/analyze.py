#!/usr/bin/env python3
"""Apply the pre-registered analysis rules from docs/BENCHMARK.md section 4.

The rules live in code rather than in a human's head so they cannot drift
between runs. In particular this script will not remove outliers, will not
report a mean as a headline figure, and will not average percentiles — three
mistakes that each make results look better than they are.

Standard library only, on purpose: this runs on a 3.7 GB WSL guest where
importing numpy to take a median is not a good trade.

Usage
-----
    ./bench/analyze.py bench/results/*.samples.json
    ./bench/analyze.py --compare a.samples.json b.samples.json

Input format (one file per benchmark, per repetition group)::

    {
      "benchmark": "decide/allow/8",
      "unit": "ns",
      "repetitions": [[12.1, 12.4, ...], [12.0, ...], ...],
      "sysinfo": { ... }
    }
"""

from __future__ import annotations

import argparse
import json
import random
import statistics as stats
import sys
from pathlib import Path

# From docs/BENCHMARK.md section 4. Changing these changes published claims,
# so they are named constants and any edit shows up in a diff.
MIN_REPETITIONS = 5
CV_UNRELIABLE_THRESHOLD = 0.15  # 15%
BOOTSTRAP_RESAMPLES = 10_000
BOOTSTRAP_CONFIDENCE = 0.95


def percentile(sorted_values: list[float], p: float) -> float:
    """Nearest-rank percentile on an already-sorted list.

    Deliberately not interpolating: for tail latency, reporting a value that
    was actually observed is more defensible than one synthesized between two
    samples.
    """
    if not sorted_values:
        return float("nan")
    k = max(0, min(len(sorted_values) - 1, int(round(p / 100.0 * len(sorted_values) + 0.5)) - 1))
    return sorted_values[k]


def coefficient_of_variation(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = stats.fmean(values)
    return stats.stdev(values) / mean if mean else 0.0


def bootstrap_diff_ci(a: list[float], b: list[float]) -> tuple[float, float]:
    """95% CI on (median(a) - median(b)) by bootstrap resampling.

    Rule 7: if this interval contains zero, the difference is reported as
    "no measurable difference" and NOT as a win.
    """
    rng = random.Random(20260730)  # fixed seed: the CI must be reproducible
    diffs = []
    for _ in range(BOOTSTRAP_RESAMPLES):
        ra = [a[rng.randrange(len(a))] for _ in range(len(a))]
        rb = [b[rng.randrange(len(b))] for _ in range(len(b))]
        diffs.append(stats.median(ra) - stats.median(rb))
    diffs.sort()
    lo_i = int((1 - BOOTSTRAP_CONFIDENCE) / 2 * len(diffs))
    hi_i = int((1 + BOOTSTRAP_CONFIDENCE) / 2 * len(diffs)) - 1
    return diffs[lo_i], diffs[hi_i]


class Result:
    def __init__(self, path: Path):
        data = json.loads(path.read_text())
        self.path = path
        self.name: str = data["benchmark"]
        self.unit: str = data.get("unit", "ns")
        self.reps: list[list[float]] = data["repetitions"]
        self.sysinfo = data.get("sysinfo", {})

        # Rule 3: percentiles come from the MERGED sample set. Averaging
        # per-run percentiles is a common and serious error.
        self.merged: list[float] = sorted(v for rep in self.reps for v in rep)

        # Rule 2: the headline statistic is the median across repetitions.
        self.per_rep_medians = [stats.median(r) for r in self.reps if r]
        self.median = stats.median(self.per_rep_medians) if self.per_rep_medians else float("nan")

        q = stats.quantiles(self.per_rep_medians, n=4) if len(self.per_rep_medians) >= 4 else None
        self.iqr = (q[2] - q[0]) if q else float("nan")
        self.cv = coefficient_of_variation(self.per_rep_medians)

    @property
    def warnings(self) -> list[str]:
        w = []
        if len(self.reps) < MIN_REPETITIONS:
            w.append(f"only {len(self.reps)} repetitions (protocol requires >= {MIN_REPETITIONS})")
        if self.cv > CV_UNRELIABLE_THRESHOLD:
            w.append(f"CV {self.cv:.1%} exceeds {CV_UNRELIABLE_THRESHOLD:.0%} — UNRELIABLE")
        return w

    def row(self) -> str:
        s = self.merged
        return (
            f"| `{self.name}` | {self.median:.1f} | {self.iqr:.1f} | "
            f"{percentile(s, 50):.1f} | {percentile(s, 95):.1f} | "
            f"{percentile(s, 99):.1f} | {percentile(s, 99.9):.1f} | "
            f"{s[-1]:.1f} | {self.cv:.1%} | {len(self.reps)} |"
        )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--compare", nargs=2, metavar=("A", "B"),
                    help="bootstrap CI on the difference between two result files")
    args = ap.parse_args()

    results = [Result(p) for p in args.files if p.exists()]
    if not results:
        print("no result files found", file=sys.stderr)
        return 1

    unit = results[0].unit
    print(f"\n### Results ({unit}); median across repetitions, no outlier removal\n")
    print("| benchmark | median | IQR | p50 | p95 | p99 | p99.9 | max | CV | reps |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for r in results:
        print(r.row())

    flagged = [(r.name, w) for r in results for w in r.warnings]
    if flagged:
        print("\n**Protocol warnings**\n")
        for name, w in flagged:
            print(f"- `{name}`: {w}")

    if args.compare:
        a, b = (Result(Path(p)) for p in args.compare)
        lo, hi = bootstrap_diff_ci(a.merged, b.merged)
        verdict = ("NO MEASURABLE DIFFERENCE (interval contains zero)"
                   if lo <= 0 <= hi else
                   f"{'A slower' if lo > 0 else 'A faster'} by {abs(stats.median(a.merged) - stats.median(b.merged)):.1f} {unit}")
        print(f"\n### Comparison: `{a.name}` vs `{b.name}`\n")
        print(f"- 95% bootstrap CI on median difference: [{lo:.2f}, {hi:.2f}] {unit}")
        print(f"- Verdict: **{verdict}**")

    print("\n_Hardware and threats to validity: see docs/BENCHMARK.md sections 2 and 5._")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
