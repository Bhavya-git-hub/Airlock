# Airlock — Threat Model

**Status:** first draft, Phase 0. Revised at the end of every phase.
**Last updated:** 2026-07-30

A threat model that only lists threats the system happens to handle is
marketing. §6 lists what is currently *not* mitigated, and it is the most
important section here.

---

## 1. Attacker model

Four adversaries, in the order they matter.

### A1 — The injected instruction *(primary)*

An attacker who controls content the agent will read: a web page, an email, a
document in a shared drive, the output of a third-party API, a code comment in
a repository the agent was asked to review.

They cannot run code on the host, modify Airlock's configuration, or forge
tokens. They can only place text where the agent will encounter it.

**Goal:** get the agent to take an action on their behalf — exfiltrate a
credential, POST data somewhere, modify a record.

**Why this is the primary adversary:** it requires no privilege at all. The
attack surface is the entire internet, and the vulnerability is inherent to
running a model that cannot reliably distinguish data from instructions.

### A2 — The confused agent

Not malicious; a model that misinterprets an ambiguous task and does something
destructive within its granted authority. Indistinguishable from A1 at the
point of action, which is why both are handled by the same mechanism rather
than by intent detection.

### A3 — Escaped code

An attacker who achieves arbitrary code execution *inside* a sandbox — the
agent was asked to run untrusted code, and it was hostile. They now hold a
shell inside the isolation boundary and want out, or want network egress.

### A4 — The insider / compromised operator account

A human with console access who wants to widen an agent's authority, exfiltrate
via a policy change, or erase evidence afterwards. Addressed by approvals,
segregation of duties and the tamper-evident ledger, not by isolation.

---

## 2. Assets

| Asset | Why it is worth attacking |
|---|---|
| Upstream credentials (API keys, OAuth tokens) | direct access to systems Airlock fronts |
| Data the agent legitimately reads | the exfiltration target in the A1 attack |
| Capability signing keys | forge authority for any agent, any scope |
| The audit ledger | destroying evidence is the second step of every intrusion |
| Policy definitions | widening a policy is quieter than forging a token |
| Recorded trajectories | contain prompts, responses and tool payloads |

---

## 3. Trust boundaries

```
  UNTRUSTED          │  SANDBOX            │  BROKER           │  UPSTREAM
  web pages, docs,   │  agent code,        │  policy, taint,   │  real APIs
  tool results       │  model output       │  credentials      │  with real data
                     │                     │                   │
        ────(1)─────▶│      ────(2)───────▶│    ────(3)───────▶│
```

**(1) Untrusted → Sandbox.** Everything crossing here is labelled
`Integrity::Untrusted`. The agent may read it; the session is tainted by it.
No filtering is attempted at this boundary, because filtering natural language
for "instructions" is the approach Airlock exists to argue against.

**(2) Sandbox → Broker.** The only channel out. A unix socket / vsock; the
sandbox has no route to any network. Everything here is authenticated by an
attenuated capability and checked against the session's taint label.

**(3) Broker → Upstream.** Credentials are injected *here*, at egress, and
never exist inside the sandbox. Code execution inside the sandbox therefore
does not yield credentials — a property that is directly demonstrable by
dumping sandbox memory and environment.

---

## 4. Mitigations by adversary

### A1 — Injected instruction

| Attack step | Mitigation | Status |
|---|---|---|
| Injected text tells the agent to call an unauthorized endpoint | Capability scope — the endpoint is not in the token | ✅ modelled, property-tested |
| Injected text tells the agent to exfiltrate data it may legitimately read | Taint lattice — the session is `Untrusted` after the read, public egress refuses it | ✅ modelled, property-tested |
| Attacker sequences reads to launder the taint | Join is order-independent and monotonic | ✅ `prop_taint_cannot_be_laundered` |
| Attacker gets the agent to request declassification | Declassification is not expressible in `SessionLabel`; it requires a human approval in the control plane | ⬜ Phase 5 |
| Attacker exhausts budget to cause denial of service | Per-task spend cap in the capability | ✅ modelled |

**Effectiveness of this whole column is what benchmark B1 measures.** It is
not asserted here.

### A3 — Escaped code

| Attack | Mitigation | Status |
|---|---|---|
| Direct network egress | No route exists; only a unix socket to the broker | ⬜ Phase 2, then B5 |
| DNS tunnelling | No resolver, no route | ⬜ Phase 2, then B5 |
| Reading host `/proc`, `/sys` | gVisor userspace kernel; Firecracker hardware boundary | ⬜ Phase 2, then B5 |
| cgroup `release_agent` escape | Read-only cgroup mount, seccomp, unprivileged | ⬜ Phase 2, then B5 |
| Stealing upstream credentials | Credentials injected at the broker, never inside the sandbox | ⬜ Phase 1 |
| Forging a capability | Biscuit signature verification at the broker | ⬜ Phase 1 |
| Replaying a captured capability | Short TTL, revocation list, per-task nonce | ⬜ Phase 1 |

### A4 — Insider

| Attack | Mitigation | Status |
|---|---|---|
| Widening a policy to permit exfiltration | Maker–checker approval; `policy simulate` shows the delta before merge | ⬜ Phase 5 |
| Deleting audit records | Merkle hash chain; `verify-chain` detects any alteration | ⬜ Phase 3 |
| Minting an over-broad capability | Capabilities are bounded by the parent policy; minting is itself audited | ⬜ Phase 1 |

---

## 5. Assumptions

Stated explicitly, because an unstated assumption is a vulnerability nobody is
looking for.

1. The **host kernel is not compromised**. gVisor and Firecracker both
   ultimately rest on it.
2. **Capability signing keys are secret.** Compromise of the minting key
   defeats the entire authorization model. Key custody is a Phase 5 concern
   (KMS / Vault) and is currently a plain file — see §6.
3. **Upstream services enforce their own authorization.** Airlock narrows what
   an agent may attempt; it is not a substitute for authorization at the API
   it calls.
4. **Labels assigned at ingest are correct.** If a tool that fetches web pages
   fails to mark its output `Untrusted`, the lattice is reasoning from bad
   input. Label assignment is per-tool configuration and is therefore a
   correctness-critical piece of policy authoring.
5. **The operator can read a denial reason.** The design assumes a human
   reviews approvals and denials. An operator who reflexively approves
   everything has removed the control.

---

## 6. Currently unmitigated

The honest section. All of these are real today.

- **Signing keys are on disk, unencrypted.** Phase 1 uses a local key file.
  KMS-backed custody is Phase 5. Anyone with filesystem access to the control
  plane can mint arbitrary capabilities right now.
- **No sandbox exists yet.** Phases 0–1 implement the authorization model only.
  The isolation claims in §4 are design intent and remain unverified until
  Phase 2 and benchmark B5.
- **Label assignment is manual and unaudited.** Nothing yet checks that a tool
  declaring itself `Trusted` deserves to.
- **Timing side channels in the decision path are not addressed.** A denial and
  an allow take measurably different times, which leaks policy shape to a
  determined attacker inside the sandbox. Constant-time evaluation is not
  planned; the exposure is judged acceptable and is recorded here so the
  judgement is visible.
- **Model-layer attacks are out of scope entirely.** Jailbreaks that make the
  model produce harmful *text* are not Airlock's concern — only what it can
  *do*.
- **No rate limiting on the broker.** An agent in a loop can generate unbounded
  policy evaluations. Budget caps bound the money, not the request rate.

---

## 7. Non-goals

- **An agent causing harm using only capabilities it was legitimately
  granted.** Grant `DELETE /users` and users will be deleted. Airlock's job is
  to make the granted set small, explicit and auditable — not to infer intent.
- **Kernel 0-days and CPU side channels.** Firecracker narrows the attack
  surface; it does not eliminate it.
- **Guaranteeing the injection classifier catches anything.** It is a secondary
  probabilistic signal layered over a structural mechanism. B1 measures its
  contribution separately (arm A1) so that contribution is visible rather than
  assumed.
- **Making an unsafe agent safe.** Airlock bounds reach and produces evidence.
