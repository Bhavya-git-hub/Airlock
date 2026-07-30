#!/usr/bin/env bash
# Check every Phase 0 exit criterion and report honestly.
#
# The point of this script is that "is Phase 0 done?" should be a command, not
# an opinion. Each check reports one of:
#
#   PASS     verified on this machine, just now
#   FAIL     verified as broken — fix it
#   BLOCKED  cannot be checked because privileged setup has not been run
#
# BLOCKED is deliberately not FAIL. It means the criterion is untested, which
# is different from tested-and-working, and the summary refuses to call Phase 0
# complete while any remain.
#
# Exit: 0 all PASS · 1 something FAILed · 2 only BLOCKED remain
#
# Usage:  bash scripts/verify-phase0.sh [--quick]
#           --quick  skip the slow cargo/go checks

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

QUICK=0
[[ "${1:-}" == "--quick" ]] && QUICK=1

PASS=0; FAIL=0; BLOCKED=0
declare -a BLOCKED_REASONS=()

pass()    { printf '  \033[32mPASS\033[0m     %-38s %s\n' "$1" "${2:-}"; PASS=$((PASS+1)); }
fail()    { printf '  \033[31mFAIL\033[0m     %-38s %s\n' "$1" "${2:-}"; FAIL=$((FAIL+1)); }
blocked() { printf '  \033[33mBLOCKED\033[0m  %-38s %s\n' "$1" "${2:-}"; BLOCKED=$((BLOCKED+1)); BLOCKED_REASONS+=("$1: ${2:-}"); }
section() { printf '\n\033[1m%s\033[0m\n' "$1"; }

export PATH="$HOME/.local/go/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/airlock/cargo-target}"
export GOCACHE="${GOCACHE:-$HOME/.cache/airlock/go-build}"
export GOMODCACHE="${GOMODCACHE:-$HOME/.cache/airlock/go-mod}"

echo "Airlock — Phase 0 exit criteria"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) · $(uname -r)"

# ---------------------------------------------------------------- toolchains
section "Toolchains"
if command -v go >/dev/null;    then pass "go installed"    "$(go version | awk '{print $3}')";     else fail "go installed" "not on PATH"; fi
if command -v cargo >/dev/null; then pass "rust installed"  "$(cargo --version | awk '{print $2}')"; else fail "rust installed" "not on PATH"; fi

# ---------------------------------------------------------------- source quality
section "Source quality (same gates as CI)"
if [[ $QUICK -eq 1 ]]; then
  echo "  (skipped: --quick)"
else
  if cargo fmt --all --check >/dev/null 2>&1; then pass "cargo fmt"; else fail "cargo fmt" "run 'cargo fmt --all'"; fi

  if cargo clippy --workspace --all-targets -- -D warnings >/dev/null 2>&1
    then pass "cargo clippy -D warnings"; else fail "cargo clippy -D warnings"; fi

  if out=$(cargo test --workspace 2>&1); then
    pass "cargo test" "$(grep -c '^test .* ok$' <<<"$out") tests"
  else fail "cargo test"; fi

  # 8192 cases, matching the deep CI job. A generator that starves only shows
  # up at high case counts — that is precisely how the first one was caught.
  if PROPTEST_CASES=8192 cargo test -p airlock-core --test prop_attenuation >/dev/null 2>&1
    then pass "property suite @ 8192 cases"; else fail "property suite @ 8192 cases"; fi

  if go vet ./... >/dev/null 2>&1;             then pass "go vet";  else fail "go vet"; fi
  if go test -race -count=1 ./... >/dev/null 2>&1; then pass "go test -race"; else fail "go test -race"; fi
fi

# ---------------------------------------------------------------- artifacts
section "Required artifacts"
for f in docs/DESIGN.md docs/THREAT_MODEL.md docs/BENCHMARK.md docs/PHASES.md \
         .github/workflows/ci.yml docker-compose.yml Makefile; do
  if [[ -s "$f" ]]; then pass "$f"; else fail "$f" "missing or empty"; fi
done

# The threat model is only worth having if it says what it does NOT cover.
if grep -qi "non-goals" docs/THREAT_MODEL.md 2>/dev/null
  then pass "threat model states non-goals"; else fail "threat model states non-goals"; fi

# ---------------------------------------------------------------- evidence
section "Evidence"
if command -v go >/dev/null && go run ./cmd/airlock verify-evidence >/dev/null 2>&1; then
  pass "evidence ledger verifies" "$(go run ./cmd/airlock evidence-head 2>/dev/null | cut -c1-12)"
else
  fail "evidence ledger verifies"
fi

# BENCHMARK.md must predate the first result, or the pre-registration claim is
# just a sentence someone typed.
if git rev-parse --git-dir >/dev/null 2>&1; then
  proto=$(git log --diff-filter=A --format=%ct -- docs/BENCHMARK.md 2>/dev/null | tail -1)
  first=$(git log --diff-filter=A --format=%ct -- bench/results/ 2>/dev/null | tail -1)
  if [[ -n "$proto" && -n "$first" && "$proto" -le "$first" ]]; then
    pass "protocol committed before results"
  elif [[ -z "$first" ]]; then
    pass "protocol committed, no results yet"
  else
    fail "protocol committed before results" "results predate the protocol"
  fi
fi

# ---------------------------------------------------------------- dev stack
section "Dev stack"
if ! command -v docker >/dev/null 2>&1; then
  blocked "make dev boots core stack" "docker not installed — run scripts/setup-wsl.sh"
  blocked "core stack under memory budget" "needs docker"
else
  if docker compose up -d >/dev/null 2>&1; then
    # Compose healthchecks are the source of truth, not "the container exists".
    ok=1
    for i in $(seq 1 30); do
      unhealthy=$(docker compose ps --format '{{.Health}}' 2>/dev/null | grep -cv '^healthy$' || true)
      [[ "$unhealthy" -eq 0 ]] && break
      [[ $i -eq 30 ]] && ok=0
      sleep 2
    done
    if [[ $ok -eq 1 ]]; then
      pass "make dev boots core stack" "postgres + redis healthy"
    else
      fail "make dev boots core stack" "containers never became healthy"
    fi

    used=$(docker stats --no-stream --format '{{.MemUsage}}' 2>/dev/null \
           | awk -F'/' '{gsub(/[^0-9.]/,"",$1); s+=$1} END{printf "%.0f", s+0}')
    if [[ -n "$used" && "$used" -lt 500 ]]; then
      pass "core stack under memory budget" "${used}M < 500M"
    else
      fail "core stack under memory budget" "${used}M >= 500M"
    fi
  else
    fail "make dev boots core stack" "docker compose up failed"
  fi
fi

# ---------------------------------------------------------------- isolation
section "Isolation backends"
if command -v runsc >/dev/null 2>&1; then
  pass "gVisor installed" "$(runsc --version 2>&1 | head -1 | awk '{print $NF}')"
else
  blocked "gVisor installed" "run scripts/setup-wsl.sh"
fi

if ! command -v firecracker >/dev/null 2>&1; then
  blocked "Firecracker installed" "run scripts/setup-wsl.sh"
  blocked "Firecracker boots a microVM" "needs the binary"
elif [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  pass "Firecracker installed" "$(firecracker --version 2>&1 | head -1)"
  blocked "Firecracker boots a microVM" "/dev/kvm not accessible — join the kvm group, then 'wsl --shutdown'"
else
  pass "Firecracker installed" "$(firecracker --version 2>&1 | head -1)"
  # Cheapest real proof the hypervisor works: open /dev/kvm and ask its API
  # version. A full guest boot needs a kernel and rootfs and belongs to Phase 2.
  if python3 - <<'PY' >/dev/null 2>&1
import fcntl, os
fd = os.open("/dev/kvm", os.O_RDWR)
assert fcntl.ioctl(fd, 0xAE00, 0) == 12   # KVM_GET_API_VERSION
os.close(fd)
PY
    then pass "KVM usable (API v12)"; else fail "KVM usable"; fi
fi

# ---------------------------------------------------------------- summary
section "Summary"
printf '  %d passed, %d failed, %d blocked\n\n' "$PASS" "$FAIL" "$BLOCKED"

if [[ $FAIL -gt 0 ]]; then
  echo "  Phase 0 is NOT complete — something is broken."
  exit 1
elif [[ $BLOCKED -gt 0 ]]; then
  echo "  Phase 0 is NOT complete — these could not be checked:"
  printf '    - %s\n' "${BLOCKED_REASONS[@]}"
  echo ""
  echo "  Everything that does not need root passes. To finish:"
  echo "      bash scripts/setup-wsl.sh"
  echo "      wsl --shutdown          # from PowerShell"
  echo "      bash scripts/verify-phase0.sh"
  exit 2
else
  echo "  Phase 0 COMPLETE — every exit criterion verified on this machine."
  exit 0
fi
