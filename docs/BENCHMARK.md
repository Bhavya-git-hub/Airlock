# Airlock — Benchmark Protocol and Evidence

**Status:** protocol pre-registered, results not yet collected.
**Last updated:** 2026-07-30

This document is written *before* the measurements exist. That ordering is
deliberate and is the main thing that makes the numbers in it worth reading.
Every analysis rule below — sample sizes, which statistic is reported, how
outliers are handled, what counts as a pass — is fixed here in advance, in
version control, with a timestamp. When the results land, the analysis is
already committed and cannot be quietly reshaped to be more flattering.

If you only read one section, read [Threats to Validity](#threats-to-validity).
A benchmark that does not enumerate its own weaknesses is marketing.

---

## 1. The claim under test

Airlock's thesis is falsifiable and is stated as a claim, not a feature:

> Prompt injection is an authorization and dataflow problem, not a
> text-classification problem. Constraining *effects* (capability scope +
> dataflow taint) blocks a materially larger share of successful exfiltration
> attacks than inspecting *text* (a prompt-injection classifier), at
> comparable benign-task utility and acceptable latency overhead.

Benchmark **B1** tests exactly this. It can fail. If the classifier arm wins,
or if Airlock's utility cost is severe, that result gets published here with
the same prominence as a favourable one. A benchmark you cannot lose is not
evidence.

Benchmarks B2–B5 measure the cost of the mechanism: if the security property
is real but costs 400 ms per tool call, it is not deployable, and that matters.

---

## 2. Hardware and software under test

All numbers in this document, unless explicitly labelled otherwise, come from
one machine. It is a laptop, and saying so plainly is part of the evidence.

| | |
|---|---|
| CPU | Intel Core i5-1235U (2 P-cores + 8 E-cores, 12 threads, base 1.3 GHz) |
| RAM | 8 GB DDR4-3200 (2 × 4 GB SODIMM) |
| Host OS | Windows 11 Home Single Language, 10.0.26200 |
| Guest | WSL2, Ubuntu 24.04.1 LTS, kernel 6.6.87.2-microsoft-standard-WSL2 |
| Guest resources | 12 vCPU visible, 3.7 GB RAM, 1 GB swap |
| Virtualization | `/dev/kvm` present (nested virt via WSL2) |
| Disk | ext4 on virtual disk, 953 GB free |

`make sysinfo` regenerates this table from the live machine into
`bench/results/sysinfo.txt`, and every result file embeds a copy of it. A
number without its hardware is not a number.

**This is a hybrid P-core/E-core CPU.** The scheduler may migrate a benchmark
thread between a performance core and an efficiency core mid-run, which
inflates variance in a way that does not happen on server hardware. This is
handled explicitly in §4 and §7 rather than ignored.

---

## 3. The five benchmarks

### B1 — Prompt-injection resistance *(the headline)*

**Question:** does effect-constraint beat text-classification at blocking
exfiltration, and what does it cost in utility?

**Harness:** [AgentDojo](https://github.com/ethz-spylab/agentdojo) (ETH Zurich),
pinned to a fixed release and vendored into `bench/injection/vendor/`. Chosen
because it is externally authored, peer-reviewed, and measures both attack
success *and* benign task completion — a defense that blocks everything by
breaking the agent is not a defense, and a benchmark that only measures attack
success would hide that.

**Arms** (identical model, prompts, seeds, and task order across all four):

| Arm | Defense |
|---|---|
| A0 | None (undefended baseline) |
| A1 | Prompt-injection classifier only |
| A2 | Airlock capability scope + dataflow taint |
| A3 | Both (defense in depth) |

**Primary metric:** Attack Success Rate (ASR) — the fraction of attack
scenarios where the adversary's objective was achieved. Lower is better.

**Co-primary metric:** Benign Task Utility — the fraction of non-attack tasks
completed correctly. Higher is better. **ASR and utility are reported as a
pair, always.** Reporting ASR alone is the standard way to make a useless
defense look good.

**Secondary:** added p50/p99 latency per tool call; tokens consumed.

**Pre-declared success condition:** the thesis is supported if A2 achieves
lower ASR than A1 by a margin whose 95% bootstrap confidence interval excludes
zero, while retaining benign utility within 10 percentage points of A0.
Anything else is a partial or negative result and will be labelled as such.

**Determinism:** model pinned by exact ID and `temperature=0`. LLM sampling is
still not perfectly reproducible across provider-side changes, so every run is
recorded through Airlock's own recorder (Phase 3) and the raw trajectories are
committed. Reruns replay cached completions, which makes reproduction free and
removes model drift as a confounder between arms.

**Cost:** approximately $10–30 in API calls for a full four-arm run; reruns
from cache are $0.

---

### B2 — Policy decision latency

**Question:** what does an authorization check cost on the hot path?

The tool-broker verifies a Biscuit capability, evaluates a Cedar policy, checks
the taint lattice, and returns allow/deny. This is on every single tool call,
so its tail latency is the tax the whole design pays.

- Load driver: `k6`, closed-loop, fixed concurrency levels {1, 8, 32, 128}.
- 30 s warmup discarded, then 60 s measurement window per level.
- Reported: p50, p95, p99, p99.9, and max, plus achieved throughput.
- Two cache states measured separately: **cold** (policy compile on every
  request) and **warm** (compiled-policy cache hit). Reporting only the warm
  number would be dishonest, since a policy version bump invalidates the cache
  in production.

**Pre-declared target:** p99 < 1 ms warm at 32 concurrent. If it misses, the
miss is published along with the profile showing why.

---

### B3 — Sandbox cold start

**Question:** what does isolation cost in time and memory, per backend?

Three backends, identical trivial workload (`exec /bin/true`), n = 100 launches
each, sequential, with 200 ms spacing to avoid warming effects:

| Backend | Isolation boundary |
|---|---|
| `docker` | namespaces + seccomp + cgroups v2 |
| `gvisor` | userspace kernel (`runsc`, systrap platform) |
| `firecracker` | hardware virtualization via KVM |

Reported per backend: p50, p95, p99 wall-clock from API call to process exit,
**plus steady-state RSS per sandbox** — which on this machine is the binding
constraint, not latency.

---

### B4 — Concurrent sandbox ceiling

**Question:** how many isolated sandboxes actually fit, and what is the per-
sandbox memory floor?

This is where the 8 GB constraint bites, and the honest number is the
interesting one. Ramp concurrent sandboxes until either the OOM killer fires or
p99 launch latency exceeds 5× the B3 baseline. Report the ceiling reached and
the marginal RSS per additional sandbox.

**Expected to be roughly 15–25 Firecracker microVMs on this hardware.** The
original design target was 200. That gap is a property of the laptop, not of
the architecture, and it will be reported as measured with the hardware stated
next to it. A measured 22 with a documented per-VM floor is stronger evidence
of understanding than an unmeasured 200.

---

### B5 — Isolation escape suite *(pass/fail, not timing)*

**Question:** is the "no egress except through the broker" property actually
true, or merely intended?

This is a proof obligation, not a performance measurement. Every technique
below is attempted from inside a sandbox and **must fail**. Each runs in CI on
every commit; a single success is a build failure.

- Direct outbound TCP to a public IP
- DNS resolution / DNS-tunnelled exfiltration
- Raw sockets, ICMP
- Connecting to the host loopback and to other sandboxes' addresses
- Reading `/proc/self/environ`, `/proc/1/*`, host `/sys` and `/dev`
- cgroup v2 escape via `release_agent`
- Writing outside the sandbox rootfs
- Calling the broker with a forged, expired, or over-scoped capability
- Calling the broker with a *valid* capability but tainted session state
  targeting a forbidden sink

Coverage is stated as a count of techniques, never as a claim of completeness.
Passing this suite proves those specific attacks fail. It does not prove the
sandbox is secure, and this document will not say that it does.

---

## 4. Statistical protocol *(fixed in advance)*

1. **Repetitions.** Every timing benchmark runs **n ≥ 5 independent
   repetitions** in separate processes, on separate invocations. Within-run
   sample counts are as specified per benchmark.
2. **Reported statistic.** **Median across repetitions**, with the
   **interquartile range**. Means are not reported as the primary figure —
   latency distributions are right-skewed and a mean flatters nothing useful.
3. **Tail latency.** Percentiles are computed from the merged raw sample set,
   never averaged across runs (averaging percentiles is a common and serious
   error).
4. **Variance disclosure.** The coefficient of variation across repetitions is
   reported next to every number. **CV > 15% is flagged inline as unreliable**
   rather than silently published — expected occasionally on this hybrid-core
   laptop.
5. **Outliers.** No outlier removal. None. The raw sample set is committed and
   the max is always reported. On a laptop, the tail *is* a finding.
6. **Warmup.** Discarded explicitly and the discarded window is stated. Never
   silently trimmed.
7. **Comparisons.** Any claim that X beats Y is accompanied by a **95%
   bootstrap confidence interval on the difference** (10,000 resamples). If
   the interval contains zero, the claim is stated as "no measurable
   difference", not as a win.
8. **Machine state.** Benchmarks run with the dev stack at a documented profile
   (usually core-only), no browser, no VS Code language server. `make sysinfo`
   captures load average and available memory at start and end of every run;
   both are embedded in the result file.

---

## 5. Threats to validity

Stated up front, because the alternative is letting a reader discover them.

**Thermal throttling, and we cannot measure it.** A 15 W laptop CPU under
sustained load will downclock, so long benchmarks measure a slower machine than
short ones. **WSL2 does not expose `/sys/class/thermal`, so package temperature
is unavailable from inside the guest** — `sysinfo.sh` reports `unavailable` and
does not pretend otherwise. This is a genuine gap in the evidence, not a
formality: a benchmark that downclocked mid-run cannot be distinguished from
one that did not, from inside the guest.

Two partial mitigations: B2 measurement windows are capped at 60 s per
concurrency level to limit sustained load, and average core MHz is sampled at
the start and end of every run (`cpu.avg_mhz_at_capture`), which will show a
large drop if throttling occurred even though it cannot show temperature.
A reader who needs thermal certainty should re-run on hardware they can
instrument.

**Hybrid P/E core migration.** Threads may be scheduled onto efficiency cores
mid-measurement, roughly doubling latency for that sample. This widens tails in
a way that does not reflect server behaviour. Not corrected for — corrections
would be a judgement call, and the raw data is published instead.

**WSL2 is a VM.** Every measurement carries virtualization overhead, including
a virtual disk and a virtualized clock. Absolute numbers are therefore *upper
bounds* on latency and *lower bounds* on throughput relative to bare metal.
**Comparisons between arms remain valid** because all arms pay the same tax —
which is why the headline claim (B1) is a *relative* comparison and not an
absolute one.

**Nested virtualization for Firecracker.** microVMs run under KVM inside WSL2's
own hypervisor. Cold-start numbers are expected to be meaningfully worse than
on bare metal and should not be compared against published Firecracker figures.

**Single machine, single operator.** No cross-machine replication. Anyone can
re-run it, and the instructions to do so are in §7.

**Shared host.** Windows continues running underneath. Available memory at
benchmark start is recorded so a reader can see how much headroom existed.

**B1 depends on a third-party model endpoint** whose behaviour can change
without notice. Mitigated by pinning the model ID and committing full recorded
trajectories, so the exact inputs and outputs behind every number are
inspectable.

---

## 6. Provenance — why you should believe the numbers weren't edited

Three independent mechanisms, none of which requires trusting the author:

1. **Raw data is committed.** `bench/results/` holds the complete sample sets,
   not just summary tables. Anyone can recompute every statistic. The analysis
   script (`bench/analyze.py`) is committed alongside.
2. **Results are anchored in Airlock's own Merkle ledger.** `make bench` hashes
   each result file and appends it to the hash-chained ledger; `make
   verify-evidence` recomputes the chain and fails if any committed result was
   altered after the fact. The project's own tamper-evidence mechanism is used
   on the project's own claims — which is also the most honest demo of the
   feature.
3. **Git history is an independent timestamp.** This protocol was committed
   before any result file existed. `git log --diff-filter=A -- docs/BENCHMARK.md`
   versus the first commit under `bench/results/` shows the ordering, and no
   amount of later editing can reverse it.

---

## 7. Reproduction

```bash
# inside WSL Ubuntu
make dev                 # core stack (~384M)
make sysinfo             # capture your hardware into the result set

make bench-policy        # B2  — no API key needed
make bench-coldstart     # B3  — needs gVisor + Firecracker installed
make escape-test         # B5  — pass/fail, no API key needed

export ANTHROPIC_API_KEY=...
make bench-injection     # B1  — ~$10-30 first run, $0 on replay

make bench               # everything, then anchors results in the ledger
make verify-evidence     # confirm nothing was edited post-hoc
```

Expect different absolute numbers on different hardware. That is the point of
§2. If your *relative* B1 ordering differs from what is published here, that is
a finding worth reporting as an issue.

---

## 8. Results

> **None yet.** Tables below are placeholders with their shape fixed in
> advance. Every cell reads `—` until a committed run under `bench/results/`
> fills it, and each filled cell links to the raw file it came from.
>
> No number appears in this document that was not produced by `make bench` on
> the hardware in §2.

### B1 — Prompt-injection resistance

| Arm | Attack Success Rate ↓ | Benign Utility ↑ | Δ p50 latency | Δ p99 latency |
|---|---|---|---|---|
| A0 undefended | — | — | baseline | baseline |
| A1 classifier only | — | — | — | — |
| A2 Airlock cap+taint | — | — | — | — |
| A3 both | — | — | — | — |

95% bootstrap CI on (A1 ASR − A2 ASR): —

### B2 — Policy decision latency

| Concurrency | Cache | p50 | p95 | p99 | p99.9 | max | throughput | CV |
|---|---|---|---|---|---|---|---|---|
| 1 | warm | — | — | — | — | — | — | — |
| 8 | warm | — | — | — | — | — | — | — |
| 32 | warm | — | — | — | — | — | — | — |
| 128 | warm | — | — | — | — | — | — | — |
| 32 | cold | — | — | — | — | — | — | — |

### B3 — Sandbox cold start

| Backend | p50 | p95 | p99 | RSS/sandbox | CV |
|---|---|---|---|---|---|
| docker | — | — | — | — | — |
| gvisor | — | — | — | — | — |
| firecracker | — | — | — | — | — |

### B4 — Concurrent sandbox ceiling

| Backend | Max concurrent | Limiting factor | Marginal RSS/sandbox |
|---|---|---|---|
| gvisor | — | — | — |
| firecracker | — | — | — |

### B5 — Escape suite

| Techniques attempted | Blocked | Escaped | CI status |
|---|---|---|---|
| — | — | — | — |
