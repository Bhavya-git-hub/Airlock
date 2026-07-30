#!/usr/bin/env bash
# B2a — decision-function microbenchmark, protocol-compliant runner.
#
# Criterion collects 100 samples inside ONE process. docs/BENCHMARK.md section 4
# rule 1 requires >= 5 *independent* repetitions in *separate* processes,
# because a single process shares one allocator state, one set of warm caches
# and one CPU-affinity accident. Running criterion five times and keeping every
# raw sample is what actually satisfies the rule.
#
# Output: bench/results/<benchmark>.samples.json in the schema bench/analyze.py
# expects, with sysinfo captured before and after embedded in each file.

set -euo pipefail

REPS="${REPS:-5}"
OUT_DIR="bench/results"
CRIT_DIR="${CARGO_TARGET_DIR:-target}/criterion"

cd "$(dirname "$0")/.."
mkdir -p "$OUT_DIR/.raw"

echo "==> B2a: $REPS independent repetitions"
bash bench/sysinfo.sh --json > "$OUT_DIR/.sysinfo.before.json"

for rep in $(seq 1 "$REPS"); do
  echo "    repetition $rep/$REPS"
  # --bench decision, not -p alone: `cargo bench -p X -- args` routes args to
  # the lib test harness first, which rejects criterion's flags.
  cargo bench -p airlock-core --bench decision >/dev/null 2>&1

  # Criterion rewrites <bench>/new/sample.json on every run, so we harvest it
  # immediately rather than juggling saved baselines.
  while IFS= read -r -d '' f; do
    bench_id="${f#"$CRIT_DIR"/}"
    bench_id="${bench_id%/new/sample.json}"
    safe="${bench_id//\//_}"
    mkdir -p "$OUT_DIR/.raw/$safe"
    cp "$f" "$OUT_DIR/.raw/$safe/rep$rep.json"
    # Record the real id. Reversing the flattening with a blind s|_|/|g turns
    # "deny_illegal_flow" into "deny/illegal/flow" — the underscores in a
    # benchmark's own name are indistinguishable from the ones we introduced.
    printf '%s' "$bench_id" > "$OUT_DIR/.raw/$safe/.bench_id"
  done < <(find "$CRIT_DIR" -path "*/new/sample.json" -print0 2>/dev/null)
done

bash bench/sysinfo.sh --json > "$OUT_DIR/.sysinfo.after.json"

echo "==> assembling protocol-compliant result files"
python3 - "$OUT_DIR" <<'PY'
import json, sys, pathlib

out = pathlib.Path(sys.argv[1])
raw = out / ".raw"
if not raw.exists() or not any(raw.iterdir()):
    sys.exit("no raw criterion samples found — did cargo bench run?")

before = json.loads((out / ".sysinfo.before.json").read_text())
after  = json.loads((out / ".sysinfo.after.json").read_text())

for bench_dir in sorted(raw.iterdir()):
    if not bench_dir.is_dir():
        continue
    reps = []
    for rep_file in sorted(bench_dir.glob("rep*.json")):
        d = json.loads(rep_file.read_text())
        # Criterion records total nanoseconds for a batch of `iters`
        # iterations. Per-iteration time is the quotient; keeping every sample
        # rather than a summary is what lets analyze.py compute real
        # percentiles instead of averaging someone else's.
        reps.append([t / i for t, i in zip(d["times"], d["iters"]) if i])
    if not reps:
        continue
    id_file = bench_dir / ".bench_id"
    bench_id = id_file.read_text().strip() if id_file.exists() else bench_dir.name

    doc = {
        "benchmark": bench_id,
        "unit": "ns",
        "repetitions": reps,
        "sysinfo": {"before": before, "after": after},
        "protocol": "docs/BENCHMARK.md section 4",
        "notes": (
            "B2a measures the pure decision function: no token parsing, no "
            "Cedar evaluation, no I/O. This is NOT benchmark B2, which is the "
            "end-to-end broker and will be substantially slower."
        ),
    }
    dest = out / f"{bench_dir.name}.samples.json"
    dest.write_text(json.dumps(doc, indent=2))
    print(f"    {dest.name}: {len(reps)} reps, {sum(len(r) for r in reps)} samples")
PY

rm -rf "$OUT_DIR/.raw" "$OUT_DIR/.sysinfo.before.json" "$OUT_DIR/.sysinfo.after.json"

echo ""
echo "==> analysis (pre-registered rules)"
python3 bench/analyze.py "$OUT_DIR"/*.samples.json
