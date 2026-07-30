# Airlock — Design

**Status:** living document, written incrementally from Phase 1 onward.
**Last updated:** 2026-07-30

---

## 1. The problem

LLM agents now write code, call internal APIs, and touch production systems.
Four failure modes block their adoption in any environment that has something
worth stealing:

1. **Prompt injection becomes action.** Text read from an untrusted source is
   fed to a model whose output is then executed as a tool call. The trust
   boundary between "data the agent read" and "instructions the agent follows"
   does not exist.
2. **Static, over-broad credentials.** An agent is handed an OAuth token or an
   API key scoped to everything it might ever need, for as long as it exists.
3. **No provenance.** After an incident, nobody can answer "what did the agent
   do at 03:14, on whose authority, and with what data?"
4. **No blast-radius control.** A looping agent can burn thousands of dollars
   or issue thousands of writes before anyone notices.

## 2. The thesis

> **Prompt injection is an authorization and dataflow problem, not a
> text-classification problem.**

Existing defenses inspect *words*: a classifier scores the prompt, or a
guardrail regex scans the output. This can only ever be probabilistic, because
it is trying to infer intent from natural language. It also fails on the case
that matters most — a classifier looking at an outbound HTTP request has no way
to know that the bytes in the body originated from an untrusted web page three
tool calls ago.

Airlock instead constrains *effects*:

- **Capability scope** — an agent physically cannot call an endpoint that its
  capability token does not name. Not "is discouraged from"; cannot.
- **Dataflow taint** — once a session reads untrusted data, the set of
  reachable sinks mechanically shrinks. Declassification requires a human.

This is falsifiable, and [docs/BENCHMARK.md](BENCHMARK.md) §B1 is the
experiment that tests it. It can lose.

## 3. Architecture — three planes

```
                    ┌──────────────────────────────┐
                    │  Console (Next.js)           │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
   POLICY PLANE     │  control-api (Go)            │
                    │  capability-mint · policy    │
                    │  taint-tracker · approvals   │
                    └──────────────┬───────────────┘
                                   │  mints attenuated capability
                    ┌──────────────▼───────────────┐
   DATA PLANE       │  sandbox (gVisor/Firecracker)│
                    │  no network route out        │──X──▶ internet
                    └──────────────┬───────────────┘
                                   │  unix socket / vsock ONLY
                    ┌──────────────▼───────────────┐
                    │  tool-broker (Rust)          │──────▶ upstream tools
                    │  SOLE EGRESS PATH            │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
   FORENSICS PLANE  │  ledger (Merkle) · recorder  │
                    │  replay engine               │
                    └──────────────────────────────┘
```

The load-bearing property is that the sandbox has **no route to anywhere**. Not
a firewall rule, not an allowlist the agent could be tricked into bypassing —
no route. The only file descriptor leading out is a unix socket to the broker.
Egress is structurally impossible, which is why [B5](BENCHMARK.md#b5--isolation-escape-suite-passfail-not-timing)
is a pass/fail proof obligation rather than a policy test.

---

## 4. Rejected alternatives

The reasoning here matters more than the conclusions. Several of these were
forced by running on an 8 GB laptop — and in three of the four cases, the
constraint pushed toward the *better* engineering choice, not a worse one.

### 4.1 Capability tokens: Biscuit over JWT / PASETO / bare OAuth

**Chosen: Biscuit v3.**

JWTs cannot be attenuated offline. To narrow a JWT's scope you must call the
issuer and mint a new one, which puts a network round-trip and a central
dependency on the path of every delegation. Airlock delegates constantly:
agent → subagent → individual tool call, each step narrower than the last.

Biscuit supports offline attenuation by design — a holder can append caveats
to a token, producing a strictly less powerful token, without contacting
anyone. That maps exactly onto the domain, and it makes the central security
property mechanically testable: attenuation must be **monotonically
non-increasing** in authority. That is a property test, not an example test,
and it is the first thing built in Phase 1.

Macaroons were the other serious candidate. Biscuit won on having a real
Datalog authorization language and better-maintained Rust and Go
implementations.

### 4.2 Policy: Cedar over OPA/Rego

**Chosen: Cedar.**

OPA/Rego is more widely known and would arguably look more familiar on a
resume. Cedar was chosen anyway because it is **designed to be analyzable**:
policies can be checked for equivalence and for whether one policy is strictly
more permissive than another. Airlock needs precisely that to answer "would
this new policy have blocked last week's incident?" — the replay-diff feature.
Rego is Turing-complete enough that the same question is undecidable in
general.

Cedar also evaluates in microseconds and compiles to a form cacheable by
`(policy_version, principal, action, resource)`, which is what makes the
[B2](BENCHMARK.md#b2--policy-decision-latency) sub-millisecond target
plausible.

### 4.3 Event spine: Redpanda over Kafka

**Chosen: Redpanda.** *(constraint-driven)*

Kafka needs a JVM. In this deployment that is ~1.5 GB resident before a single
message is produced, on a machine with 3.7 GB total in the WSL guest. Redpanda
is a C++ reimplementation speaking the same wire protocol at ~600 MB with
`--smp=1 --memory=512M`.

Because the protocol is identical, every Kafka client, every `rpk`/`kafkactl`
workflow, and the entire consumer-group model are unchanged. The production
Helm chart can point at MSK without touching application code. This is a
deployment-target swap, not an architecture change, and it costs nothing in
capability.

### 4.4 Graph store: Postgres + Apache AGE over Neo4j

**Chosen: Apache AGE (Postgres extension).** *(constraint-driven)*

Airlock needs a graph for two queries: the capability graph
(`Principal → Capability → Resource`) and the per-run dataflow graph
(`Source → FLOWED_TO → Sink`), used for blast-radius questions.

Neo4j is another JVM (~1.2 GB floor with heap plus page cache) and a second
datastore to operate, back up, and keep consistent with Postgres. AGE gives
openCypher inside the Postgres instance that already exists — one database, one
transaction boundary, one backup.

**Honest assessment:** at genuine scale (billions of edges, deep traversals)
Neo4j is the better engine and this choice would be wrong. At the scale Airlock
actually produces — thousands of nodes per run — AGE is comfortably sufficient,
and keeping the dataflow graph in the *same transaction* as the ledger append
is a real correctness benefit, not merely a memory saving. Neo4j here would
have been partly resume decoration.

### 4.5 Analytics store: partitioned Postgres over ClickHouse

**Chosen: monthly-partitioned Postgres tables, for now.** *(constraint-driven)*

ClickHouse is the right answer at hundreds of millions of rows and the wrong
answer at the volume a single-developer demo generates. Partitioned Postgres
with BRIN indexes on timestamp handles the trajectory-analytics queries at this
scale, and the query interface is abstracted (`internal/analytics`) so
ClickHouse can be swapped in behind it when volume justifies the memory.

Deferred, not rejected — and the abstraction boundary is written now so the
swap stays cheap.

### 4.6 Isolation: pluggable, defaulting to gVisor

**Chosen: three backends behind one `Isolator` interface.**

| Backend | Boundary | Role |
|---|---|---|
| `docker` | namespaces + seccomp + cgroups v2 | CI — fast, weakest isolation |
| `gvisor` | userspace kernel (`runsc`) | default dev — no KVM needed |
| `firecracker` | hardware virtualization (KVM) | the real thing |

A single hardcoded backend would have been less work. Three behind an interface
means the escape suite ([B5](BENCHMARK.md#b5--isolation-escape-suite-passfail-not-timing))
runs against all of them and produces a comparison table, which is a far more
interesting artifact than "it uses Firecracker." It also means CI does not need
nested virtualization.

### 4.7 Docker Engine over Docker Desktop

**Chosen: Docker Engine natively in WSL.** *(constraint-driven)*

Docker Desktop adds roughly 1 GB of resident overhead for a GUI and a VM this
project does not need, on a machine with none to spare. Engine in WSL2 is the
same daemon without the wrapper.

---

## 5. Consequences of the hardware constraint

This project is developed on an 8 GB laptop (full specification in
[BENCHMARK.md §2](BENCHMARK.md#2-hardware-and-software-under-test)). Two
consequences are load-bearing and are stated here rather than buried:

**The concurrent-sandbox ceiling is roughly an order of magnitude below the
design target.** The architecture targets thousands; this machine fits an
expected 15–25 Firecracker microVMs before memory is exhausted. The number
published in B4 will be the measured one, with the hardware printed beside it.
A measured 22 is better evidence than an unmeasured 200.

**Not every component runs at once.** The dev stack is profiled
(`make dev`, `make dev-obs`, `make dev-events`) with hard `mem_limit` on every
container and a documented budget. This is stricter than most production
compose files, and it is enforced rather than hoped for.

Neither of these compromises the thesis. B1 — the claim the project exists to
test — is a *relative* comparison between four arms on identical hardware, so
the absolute capacity of that hardware does not affect its validity.

---

## 6. Explicit non-goals

Recorded here so that the threat model cannot quietly expand to whatever
Airlock happens to do well. See [THREAT_MODEL.md](THREAT_MODEL.md) for the full
treatment.

- **Airlock does not defend against a model that causes harm using only the
  capabilities it was legitimately granted.** If you grant `DELETE /users` and
  the agent deletes users, that is a policy authoring failure. Airlock's job is
  to make the granted set small, explicit, and auditable — not to judge intent.
- **Airlock does not defend against kernel 0-days or CPU side channels.**
  Firecracker narrows the attack surface; it does not eliminate it.
- **Airlock does not guarantee the injection detector catches anything.** It is
  a secondary, probabilistic signal layered on top of the structural
  mechanism, and B1 measures it separately (arm A1) precisely so its
  contribution is visible rather than assumed.
- **Airlock does not make an unsafe agent safe.** It bounds what an agent can
  reach and produces evidence of what it did.
