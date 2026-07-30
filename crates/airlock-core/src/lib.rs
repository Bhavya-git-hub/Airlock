//! # airlock-core
//!
//! The authorization and dataflow model at the centre of Airlock. Pure logic:
//! no I/O, no clock, no network. Everything here is a total function of its
//! arguments, which is what makes it property-testable, cheap to benchmark,
//! and deterministically replayable.
//!
//! Two mechanisms, and the argument that they compose:
//!
//! - [`capability`] — *what may this agent do?* Authority that can only ever
//!   be narrowed as it is delegated.
//! - [`label`] — *given what this session has read, where may data go?* A
//!   taint lattice whose restrictiveness only ever increases.
//!
//! Neither is novel on its own; both are decades old. The claim Airlock is
//! testing is that applying them at the agent tool-call boundary is a better
//! defense against prompt injection than classifying prompt text, and
//! [`Decision`] is where the two meet — the check the broker runs on every
//! call that leaves a sandbox.
//!
//! See `docs/BENCHMARK.md` for the experiment that can falsify this.

pub mod capability;
pub mod label;

pub use capability::{Attenuation, Capability, Denial, Method, Request, Scope};
pub use label::{Confidentiality, Integrity, Label, Refusal, SessionLabel, SinkClearance};

/// Why a tool call was refused.
///
/// The two mechanisms fail for genuinely different reasons and the distinction
/// is kept all the way to the audit record: `Unauthorized` means the agent
/// never had this authority, `IllegalFlow` means it had the authority but the
/// data it is carrying may not go there. Collapsing them into a single "denied"
/// would make incident review much harder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("unauthorized: {0}")]
    Unauthorized(#[from] Denial),
    #[error("illegal flow: {0}")]
    IllegalFlow(#[from] Refusal),
}

/// The complete egress check.
///
/// Ordering is deliberate: capability first, taint second. A request the agent
/// was never authorized to make is reported as unauthorized even if it would
/// also have been an illegal flow, because "you never had this permission" is
/// the more actionable finding for whoever wrote the policy.
///
/// Both checks are pure and allocation-free on the happy path; `benches/decision.rs`
/// measures them, and `docs/BENCHMARK.md` §B2 is where the number lands.
pub fn decide(
    capability: &Capability,
    session: &SessionLabel,
    req: &Request,
    sink: SinkClearance,
    now: u64,
    spent_micros: u64,
) -> Result<(), Refused> {
    capability.permits(req, now, spent_micros)?;
    session.check_egress(sink)?;
    Ok(())
}

/// A decision plus the reason, for the audit ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub reason: Option<Refused>,
    /// The session label at decision time. Recorded because a later replay
    /// must be able to reconstruct exactly why this call went the way it did,
    /// even after policy has changed.
    pub label_at_decision: Label,
}

impl Decision {
    pub fn evaluate(
        capability: &Capability,
        session: &SessionLabel,
        req: &Request,
        sink: SinkClearance,
        now: u64,
        spent_micros: u64,
    ) -> Self {
        match decide(capability, session, req, sink, now, spent_micros) {
            Ok(()) => Self {
                allowed: true,
                reason: None,
                label_at_decision: session.label(),
            },
            Err(e) => Self {
                allowed: false,
                reason: Some(e),
                label_at_decision: session.label(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_denial_reported_before_flow_violation() {
        // Tainted session AND a request outside scope: the unauthorized
        // verdict wins, because that is the more actionable one.
        let cap = Capability::new(
            [Scope::new(Method::Get, "api.internal", "/v1/")],
            1_000,
            1_000,
        );
        let mut session = SessionLabel::new();
        session.observe(Label::new(Confidentiality::Public, Integrity::Untrusted));

        let d = Decision::evaluate(
            &cap,
            &session,
            &Request::new(Method::Post, "evil.example", "/steal"),
            SinkClearance::PUBLIC_EGRESS,
            0,
            0,
        );
        assert!(!d.allowed);
        assert_eq!(d.reason, Some(Refused::Unauthorized(Denial::OutOfScope)));
    }

    #[test]
    fn authorized_but_tainted_is_an_illegal_flow() {
        let cap = Capability::new(
            [Scope::new(Method::Post, "hooks.example", "/")],
            1_000,
            1_000,
        );
        let mut session = SessionLabel::new();
        session.observe(Label::new(Confidentiality::Public, Integrity::Untrusted));

        let d = Decision::evaluate(
            &cap,
            &session,
            &Request::new(Method::Post, "hooks.example", "/notify"),
            SinkClearance::PUBLIC_EGRESS,
            0,
            0,
        );
        assert!(!d.allowed);
        assert_eq!(d.reason, Some(Refused::IllegalFlow(Refusal::Tainted)));
    }
}
