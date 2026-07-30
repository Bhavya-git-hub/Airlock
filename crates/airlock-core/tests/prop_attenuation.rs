//! Property tests for the two security invariants.
//!
//! Example-based tests show that the cases an author thought of behave
//! correctly. These generate thousands of capabilities, attenuation chains,
//! read sequences and requests, and assert that the invariants hold across all
//! of them — including the shapes nobody thought of. When one fails, proptest
//! shrinks it to a minimal counterexample.
//!
//! A note on the generators: hosts and paths are drawn from small fixed sets
//! rather than arbitrary strings. With random 30-character hostnames a scope
//! would essentially never match a request, every `permits` would return
//! `OutOfScope`, and the suite would pass while testing nothing. Keeping the
//! domain small is what makes collisions — and therefore the interesting
//! cases — frequent.

use airlock_core::{
    Attenuation, Capability, Confidentiality, Integrity, Label, Method, Request, SessionLabel,
    SinkClearance, Scope,
};
use proptest::prelude::*;
use std::collections::BTreeSet;

// ---------------------------------------------------------------- generators

fn arb_method() -> impl Strategy<Value = Method> {
    prop_oneof![
        Just(Method::Get),
        Just(Method::Post),
        Just(Method::Put),
        Just(Method::Patch),
        Just(Method::Delete),
    ]
}

fn arb_host() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("api.internal".to_string()),
        Just("hooks.example".to_string()),
        Just("evil.example".to_string()),
    ]
}

/// Deliberately overlapping and nested, so the prefix-implication logic is
/// actually exercised.
fn arb_path() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/".to_string()),
        Just("/v1/".to_string()),
        Just("/v1/users".to_string()),
        Just("/v1/users/42".to_string()),
        Just("/v1/orders".to_string()),
        Just("/v2/".to_string()),
    ]
}

fn arb_scope() -> impl Strategy<Value = Scope> {
    (arb_method(), arb_host(), arb_path())
        .prop_map(|(m, h, p)| Scope::new(m, h, p))
}

fn arb_capability() -> impl Strategy<Value = Capability> {
    (
        prop::collection::vec(arb_scope(), 0..6),
        0u64..2_000,
        0u64..100_000,
    )
        .prop_map(|(scopes, expires, budget)| Capability::new(scopes, expires, budget))
}

fn arb_attenuation() -> impl Strategy<Value = Attenuation> {
    (
        prop::option::of(prop::collection::vec(arb_scope(), 0..6)),
        prop::option::of(0u64..2_000),
        prop::option::of(0u64..100_000),
    )
        .prop_map(|(scopes, not_after, budget)| {
            let mut a = Attenuation::new();
            if let Some(s) = scopes {
                a.restrict_to = Some(s.into_iter().collect::<BTreeSet<_>>());
            }
            a.not_after = not_after;
            a.budget_cap = budget;
            a
        })
}

fn arb_request() -> impl Strategy<Value = Request> {
    (arb_method(), arb_host(), arb_path()).prop_map(|(m, h, p)| Request::new(m, h, p))
}

fn arb_label() -> impl Strategy<Value = Label> {
    (
        prop_oneof![
            Just(Confidentiality::Public),
            Just(Confidentiality::Internal),
            Just(Confidentiality::Secret)
        ],
        prop_oneof![Just(Integrity::Untrusted), Just(Integrity::Trusted)],
    )
        .prop_map(|(c, i)| Label::new(c, i))
}

// ---------------------------------------------- invariant 1: attenuation

proptest! {
    /// **The invariant the whole capability model rests on.**
    ///
    /// If a derived capability permits a request, its parent must also have
    /// permitted it. Any counterexample is a privilege-escalation bug.
    #[test]
    fn prop_attenuation_never_widens(
        cap in arb_capability(),
        att in arb_attenuation(),
        req in arb_request(),
        now in 0u64..2_000,
        spent in 0u64..100_000,
    ) {
        let child = cap.attenuate(&att);
        if child.permits(&req, now, spent).is_ok() {
            prop_assert!(
                cap.permits(&req, now, spent).is_ok(),
                "child permitted {req:?} but parent refused it\n  parent: {cap:?}\n  atten:  {att:?}\n  child:  {child:?}"
            );
        }
    }

    /// Authority must not creep back over a long delegation chain — the case a
    /// single-step test would miss.
    #[test]
    fn prop_attenuation_chains_never_widen(
        cap in arb_capability(),
        chain in prop::collection::vec(arb_attenuation(), 1..8),
        req in arb_request(),
        now in 0u64..2_000,
        spent in 0u64..100_000,
    ) {
        let mut current = cap.clone();
        for att in &chain {
            let next = current.attenuate(att);
            if next.permits(&req, now, spent).is_ok() {
                prop_assert!(current.permits(&req, now, spent).is_ok(),
                    "authority grew at a link in the chain");
            }
            current = next;
        }
        // And end to end.
        if current.permits(&req, now, spent).is_ok() {
            prop_assert!(cap.permits(&req, now, spent).is_ok(),
                "authority grew across the full chain of {} steps", chain.len());
        }
    }

    #[test]
    fn prop_ttl_and_budget_are_non_increasing(
        cap in arb_capability(),
        att in arb_attenuation(),
    ) {
        let child = cap.attenuate(&att);
        prop_assert!(child.expires_at()    <= cap.expires_at());
        prop_assert!(child.budget_micros() <= cap.budget_micros());
    }

    /// Attenuating by nothing is the identity — a delegation hop that narrows
    /// nothing must not perturb the capability.
    #[test]
    fn prop_empty_attenuation_is_identity(cap in arb_capability()) {
        prop_assert_eq!(cap.attenuate(&Attenuation::new()), cap.clone());
    }
}

// ---------------------------------------------- invariant 2: the taint lattice

proptest! {
    /// Join must be a genuine least-upper-bound: commutative, associative,
    /// idempotent, with BOTTOM as identity. If these fail, "restrictiveness
    /// only increases" is meaningless because the order itself is broken.
    #[test]
    fn prop_join_is_a_semilattice(a in arb_label(), b in arb_label(), c in arb_label()) {
        prop_assert_eq!(a.join(b), b.join(a),                     "commutativity");
        prop_assert_eq!(a.join(b).join(c), a.join(b.join(c)),     "associativity");
        prop_assert_eq!(a.join(a), a,                             "idempotence");
        prop_assert_eq!(a.join(Label::BOTTOM), a,                 "BOTTOM is identity");
    }

    /// The join of two labels dominates both — it is an *upper* bound.
    #[test]
    fn prop_join_dominates_both_operands(a in arb_label(), b in arb_label()) {
        prop_assert!(a.flows_to(a.join(b)));
        prop_assert!(b.flows_to(a.join(b)));
    }

    /// **The dataflow invariant.** A session's label only ever becomes more
    /// restrictive, no matter what it reads or in what order. This is what
    /// makes taint irreversible, and irreversibility is what a text classifier
    /// fundamentally cannot offer.
    #[test]
    fn prop_session_label_is_monotonic(reads in prop::collection::vec(arb_label(), 0..40)) {
        let mut session = SessionLabel::new();
        let mut previous = session.label();
        for r in reads {
            session.observe(r);
            let now = session.label();
            prop_assert!(previous.flows_to(now),
                "label became less restrictive: {previous} -> {now}");
            previous = now;
        }
    }

    /// Reading order must not change the outcome — otherwise an attacker could
    /// launder taint by sequencing reads cleverly.
    #[test]
    fn prop_session_label_is_order_independent(reads in prop::collection::vec(arb_label(), 0..20)) {
        let fold = |v: &[Label]| v.iter().fold(SessionLabel::new(), |mut s, l| { s.observe(*l); s }).label();
        let forward = fold(&reads);
        let mut reversed = reads.clone();
        reversed.reverse();
        prop_assert_eq!(forward, fold(&reversed));
    }

    /// Once a session has read untrusted input, no amount of subsequent
    /// trustworthy reading restores its access to public egress.
    #[test]
    fn prop_taint_cannot_be_laundered(
        clean_reads in prop::collection::vec(
            arb_label().prop_filter("trusted only", |l| l.integrity == Integrity::Trusted),
            0..30),
    ) {
        let mut session = SessionLabel::new();
        session.observe(Label::new(Confidentiality::Public, Integrity::Untrusted));
        for r in clean_reads {
            session.observe(r);
            prop_assert!(session.label().is_tainted());
            prop_assert!(session.check_egress(SinkClearance::PUBLIC_EGRESS).is_err());
        }
    }

    /// Denial is stable: a session refused egress to a sink is never later
    /// admitted to that same sink.
    #[test]
    fn prop_egress_denial_is_permanent(
        reads in prop::collection::vec(arb_label(), 1..30),
        sink in prop_oneof![
            Just(SinkClearance::PUBLIC_EGRESS),
            Just(SinkClearance::INTERNAL),
        ],
    ) {
        let mut session = SessionLabel::new();
        let mut ever_denied = false;
        for r in reads {
            session.observe(r);
            let denied = session.check_egress(sink).is_err();
            if ever_denied {
                prop_assert!(denied, "a previously denied session was later admitted");
            }
            ever_denied |= denied;
        }
    }
}
