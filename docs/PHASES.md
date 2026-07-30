# Airlock — Phase Tracker

Six phases. Each ends with exit criteria that are **checkable by running
something**, not by deciding they feel done. `bash scripts/verify-phase0.sh`
is the current one; later phases get their own.

A phase is complete when its verifier exits 0. Not before.

---

## Phase 0 — De-risk the platform ⏳ 17/22

Get the toolchain, the dev stack and the evidence pipeline working before
writing anything that depends on them.

| Criterion | Status |
|---|---|
| Go + Rust toolchains | ✅ go1.26.5, rust 1.97.1 |
| `cargo fmt` / `clippy -D warnings` clean | ✅ |
| `cargo test` (19) + property suite @ 8192 cases | ✅ |
| `go vet` + `go test -race` | ✅ |
| DESIGN, THREAT_MODEL, BENCHMARK present | ✅ |
| Threat model states explicit non-goals | ✅ |
| CI green on GitHub Actions | ✅ |
| Evidence ledger verifies | ✅ head `9657db29ad24` |
| Protocol committed before any result | ✅ provable in `git log` |
| `make dev` boots the core stack | ⛔ needs Docker |
| Core stack under the 500 MB budget | ⛔ needs Docker |
| gVisor installed | ⛔ needs root |
| Firecracker installed | ⛔ needs root |
| Firecracker boots a microVM | ⛔ needs `/dev/kvm` |

**Why the last five are blocked, and why that is not a code problem.**
Installing Docker, gVisor and Firecracker needs root, and reading `/dev/kvm`
needs membership in the `kvm` group. Everything that can be done without
privilege is done and verified. To close them out:

```bash
bash scripts/setup-wsl.sh    # docker + gvisor + firecracker + kvm group
wsl --shutdown               # from PowerShell, so the group membership applies
bash scripts/verify-phase0.sh
```

Rootless Docker was considered as a way around this and rejected: it needs
`newuidmap`, which is also a root install. There is no path to a container
runtime on this machine without one privileged command.

---

## Phase 1 — Capability plane ⬜

Biscuit token encoding · Cedar policy engine + compiled-policy cache ·
`tool-broker` (Rust) as the sole egress path · `control-api` (Go) with Postgres.

**Exit:** broker sustains ≥1,000 rps at p99 < 1 ms warm (benchmark B2) ·
forgery, replay and expiry all fail closed · attenuation property suite still
green against the real token format, not just the in-memory model.

## Phase 2 — Isolation plane ⬜

Three backends behind one `Isolator` interface: docker+seccomp, gVisor,
Firecracker. Netns with no route out. Snapshot warm pool.

**Exit:** cold-start table across all three (B3) · concurrent ceiling measured
(B4) · **escape suite green in CI on every commit (B5)** — until B5 passes, the
"no route out" property in DESIGN.md is intent, not fact.

## Phase 3 — Dataflow, ledger, replay ⬜

Label propagation wired through the broker · dataflow graph in Postgres+AGE ·
recorder capturing every nondeterminism source · byte-identical replay ·
`replay --with-policy vNext` diffing a recorded incident against a candidate
policy.

**Exit:** replay determinism over ≥50 recorded runs in CI · a recorded attack
blocked at the exact step by a one-line policy change.

## Phase 4 — AI plane and the headline number ⬜

MCP server surface · AgentDojo integration, four arms · injection detector ·
trajectory anomaly model · least-privilege policy recommender.

**Exit:** benchmark B1 filled in, whichever way it goes. The thesis is
falsifiable and a negative result gets published with the same prominence as a
positive one.

## Phase 5 — Production surface ⬜

Multi-tenancy · OIDC + SPIFFE · secrets injected at egress · Redpanda event
spine · Terraform/Helm/ArgoCD · Prometheus, OTel, Loki.

**Exit:** kind e2e in CI · load test at target concurrency · fail-closed on
policy-engine outage, demonstrated by chaos test.

## Phase 6 — Console, chaos, write-up ⬜

Next.js console with the replay-diff viewer · chaos experiments in
EXPERIMENTS.md · a written post-mortem of a real bug · demo video.
