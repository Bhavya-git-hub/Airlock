//! The taint lattice.
//!
//! This is the mechanism behind Airlock's central claim: that prompt injection
//! is a dataflow problem rather than a text-classification problem. A
//! classifier inspecting an outbound request cannot know that its body
//! originated from an untrusted web page three tool calls ago. A label that
//! travels with the data can.
//!
//! The model is Denning's lattice for confidentiality composed with Biba for
//! integrity. Confidentiality rises as a session reads more sensitive data;
//! integrity falls as it reads less trustworthy data. Both movements are
//! one-way — that irreversibility is the whole point, and
//! [`prop_session_label_is_monotonic`] in the property suite is what holds us
//! to it.

use std::fmt;

/// How secret the data is. Ordered: `Public < Internal < Secret`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Confidentiality {
    #[default]
    Public,
    Internal,
    Secret,
}

/// How much the data can be trusted to influence actions.
///
/// Ordered `Untrusted < Trusted`, so "worse" is *lower*, which is why the join
/// takes the minimum here and the maximum for confidentiality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Integrity {
    /// Came from outside the trust boundary: a fetched web page, an inbound
    /// email, a tool result derived from either. Model output produced *after*
    /// reading such data is itself untrusted.
    Untrusted,
    #[default]
    Trusted,
}

/// A point in the lattice: the security level of a piece of data, or of a
/// session that has read several pieces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Label {
    pub confidentiality: Confidentiality,
    pub integrity: Integrity,
}

impl Label {
    /// The least restrictive label, and the identity element of [`join`].
    ///
    /// [`join`]: Label::join
    pub const BOTTOM: Label = Label {
        confidentiality: Confidentiality::Public,
        integrity: Integrity::Trusted,
    };

    /// The most restrictive label. Nothing may flow out of here.
    pub const TOP: Label = Label {
        confidentiality: Confidentiality::Secret,
        integrity: Integrity::Untrusted,
    };

    pub const fn new(confidentiality: Confidentiality, integrity: Integrity) -> Self {
        Self {
            confidentiality,
            integrity,
        }
    }

    /// Least upper bound — the label a session carries after observing both
    /// `self` and `other`.
    ///
    /// Confidentiality takes the max (having seen a secret is not undone by
    /// later reading something public) and integrity takes the min (having
    /// read untrusted input is not undone by later reading something trusted).
    #[must_use]
    pub fn join(self, other: Self) -> Self {
        Self {
            confidentiality: self.confidentiality.max(other.confidentiality),
            integrity: self.integrity.min(other.integrity),
        }
    }

    /// The lattice partial order: may data at `self` flow to a context at
    /// `other`?
    ///
    /// Note this is a *partial* order — `(Secret, Trusted)` and
    /// `(Public, Untrusted)` are incomparable, neither may flow to the other.
    /// Code that assumes totality here will be subtly wrong.
    #[must_use]
    pub fn flows_to(self, other: Self) -> bool {
        self.confidentiality <= other.confidentiality && self.integrity >= other.integrity
    }

    /// True once the session has touched anything from outside the trust
    /// boundary. The short-hand the broker checks on every egress.
    #[must_use]
    pub fn is_tainted(self) -> bool {
        self.integrity == Integrity::Untrusted
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}/{:?}", self.confidentiality, self.integrity)
    }
}

/// What a sink is willing to accept.
///
/// A sink is anything data can leave through: an HTTP endpoint, a file write,
/// a log line. `max_confidentiality` bounds how secret the outbound data may
/// be; `min_integrity` bounds how tainted the session may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkClearance {
    pub max_confidentiality: Confidentiality,
    pub min_integrity: Integrity,
}

impl SinkClearance {
    /// A sink outside the trust boundary — the public internet. Accepts only
    /// public data, and only from an untainted session.
    ///
    /// This single constant is what defeats the canonical injection attack:
    /// the agent reads a hostile page (session integrity drops to
    /// `Untrusted`), then tries to POST the API key somewhere. Both halves of
    /// the check fail independently.
    pub const PUBLIC_EGRESS: SinkClearance = SinkClearance {
        max_confidentiality: Confidentiality::Public,
        min_integrity: Integrity::Trusted,
    };

    /// An internal service: may receive internal data, still refuses tainted
    /// sessions.
    pub const INTERNAL: SinkClearance = SinkClearance {
        max_confidentiality: Confidentiality::Internal,
        min_integrity: Integrity::Trusted,
    };

    #[must_use]
    pub fn admits(&self, label: Label) -> bool {
        label.confidentiality <= self.max_confidentiality && label.integrity >= self.min_integrity
    }

    /// Why a flow was refused. The broker puts this in the decision record and
    /// the console shows it to a human, so it has to name the specific rule
    /// that failed rather than saying "denied".
    #[must_use]
    pub fn refusal(&self, label: Label) -> Option<Refusal> {
        match (
            label.confidentiality > self.max_confidentiality,
            label.integrity < self.min_integrity,
        ) {
            (false, false) => None,
            (true, false) => Some(Refusal::TooConfidential {
                data: label.confidentiality,
                sink_accepts: self.max_confidentiality,
            }),
            (false, true) => Some(Refusal::Tainted),
            (true, true) => Some(Refusal::TooConfidentialAndTainted {
                data: label.confidentiality,
                sink_accepts: self.max_confidentiality,
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("data is {data:?} but sink accepts at most {sink_accepts:?}")]
    TooConfidential {
        data: Confidentiality,
        sink_accepts: Confidentiality,
    },

    #[error("session has read untrusted input; sink requires trusted integrity")]
    Tainted,

    #[error("data is {data:?} (sink accepts {sink_accepts:?}) and session is tainted")]
    TooConfidentialAndTainted {
        data: Confidentiality,
        sink_accepts: Confidentiality,
    },
}

/// The running taint state of one agent session.
///
/// Deliberately offers no way to lower the label. Declassification is a
/// separate, audited, human-approved operation living in the control plane —
/// not a method on this type. Making it impossible to express here is cheaper
/// than reviewing every call site forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionLabel {
    current: Label,
    observations: u32,
}

impl SessionLabel {
    #[must_use]
    pub fn new() -> Self {
        Self {
            current: Label::BOTTOM,
            observations: 0,
        }
    }

    /// Record that the session has read data at `label`.
    pub fn observe(&mut self, label: Label) {
        self.current = self.current.join(label);
        self.observations = self.observations.saturating_add(1);
    }

    #[must_use]
    pub fn label(&self) -> Label {
        self.current
    }

    #[must_use]
    pub fn observations(&self) -> u32 {
        self.observations
    }

    /// The egress check, called on every tool invocation that leaves the
    /// sandbox.
    pub fn check_egress(&self, sink: SinkClearance) -> Result<(), Refusal> {
        match sink.refusal(self.current) {
            None => Ok(()),
            Some(r) => Err(r),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The attack Airlock exists to stop, as a unit test.
    #[test]
    fn injected_page_blocks_later_exfiltration() {
        let mut session = SessionLabel::new();

        // A benign start: the agent may reach the public internet.
        assert!(session.check_egress(SinkClearance::PUBLIC_EGRESS).is_ok());

        // It reads a web page carrying an injected instruction.
        session.observe(Label::new(Confidentiality::Public, Integrity::Untrusted));

        // ...and then reads an internal secret it is legitimately allowed to read.
        session.observe(Label::new(Confidentiality::Secret, Integrity::Trusted));

        // Exfiltration now fails on both axes at once, with no classifier
        // involved and nothing inspecting the request body.
        assert_eq!(
            session.check_egress(SinkClearance::PUBLIC_EGRESS),
            Err(Refusal::TooConfidentialAndTainted {
                data: Confidentiality::Secret,
                sink_accepts: Confidentiality::Public,
            })
        );
    }

    #[test]
    fn taint_is_irreversible() {
        let mut session = SessionLabel::new();
        session.observe(Label::new(Confidentiality::Public, Integrity::Untrusted));
        // Reading a hundred trustworthy things does not launder the taint.
        for _ in 0..100 {
            session.observe(Label::BOTTOM);
        }
        assert!(session.label().is_tainted());
    }

    #[test]
    fn incomparable_labels_do_not_flow_either_way() {
        let secret_trusted = Label::new(Confidentiality::Secret, Integrity::Trusted);
        let public_tainted = Label::new(Confidentiality::Public, Integrity::Untrusted);
        assert!(!secret_trusted.flows_to(public_tainted));
        assert!(!public_tainted.flows_to(secret_trusted));
    }
}
