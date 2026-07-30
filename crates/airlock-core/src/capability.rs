//! Capabilities and attenuation.
//!
//! A capability names exactly what an agent may do: which requests, until
//! when, and for how much money. Delegation happens constantly — agent to
//! subagent to individual tool call — and each hop must be able to narrow the
//! authority it passes on *without contacting the issuer*. That requirement is
//! why the wire format is Biscuit rather than JWT (see docs/DESIGN.md §4.1);
//! this module is the authority model those tokens carry.
//!
//! The invariant everything rests on:
//!
//! > Attenuation is monotonically non-increasing in authority.
//!
//! There is no API here that can widen a capability. [`Capability::attenuate`]
//! is the only way to derive one, and it can only intersect, shorten, and
//! shrink. The property suite in `tests/prop_attenuation.rs` generates random
//! capabilities, random attenuation chains, and random requests, and asserts
//! that no derived capability ever permits a request its parent refused.

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

/// One grant: a method, a host, and a path prefix.
///
/// Prefix rather than exact match because real tool surfaces are hierarchical
/// (`/v1/users/*`), and because prefixes give a clean implication relation to
/// define narrowing against.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scope {
    pub method: Method,
    pub host: String,
    pub path_prefix: String,
}

impl Scope {
    pub fn new(method: Method, host: impl Into<String>, path_prefix: impl Into<String>) -> Self {
        Self {
            method,
            host: host.into(),
            path_prefix: path_prefix.into(),
        }
    }

    /// Does `self` grant everything `other` grants?
    ///
    /// Same method, same host, and `self`'s path prefix is a prefix of
    /// `other`'s — so `/v1/` implies `/v1/users`, but not the reverse.
    #[must_use]
    pub fn implies(&self, other: &Scope) -> bool {
        self.method == other.method
            && self.host == other.host
            && other.path_prefix.starts_with(&self.path_prefix)
    }

    #[must_use]
    pub fn matches(&self, req: &Request) -> bool {
        self.method == req.method
            && self.host == req.host
            && req.path.starts_with(&self.path_prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub host: String,
    pub path: String,
}

impl Request {
    pub fn new(method: Method, host: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method,
            host: host.into(),
            path: path.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Denial {
    #[error("no scope in the capability matches this request")]
    OutOfScope,
    #[error("capability expired")]
    Expired,
    #[error("budget exhausted")]
    BudgetExhausted,
}

/// An authority to act, as held by an agent or one of its delegates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    scopes: BTreeSet<Scope>,
    /// Unix seconds. Absolute rather than a duration so that attenuation is a
    /// simple `min` and cannot be gamed by a delegate resetting the clock.
    expires_at: u64,
    /// Spend cap in micro-dollars (1e-6 USD). Integer to keep attenuation
    /// exact — float `min` chains would drift.
    budget_micros: u64,
}

impl Capability {
    #[must_use]
    pub fn new(
        scopes: impl IntoIterator<Item = Scope>,
        expires_at: u64,
        budget_micros: u64,
    ) -> Self {
        Self {
            scopes: scopes.into_iter().collect(),
            expires_at,
            budget_micros,
        }
    }

    /// The empty capability: permits nothing. What a fully attenuated token
    /// decays into, and the correct thing to fall back to on any error.
    #[must_use]
    pub fn nothing() -> Self {
        Self {
            scopes: BTreeSet::new(),
            expires_at: 0,
            budget_micros: 0,
        }
    }

    pub fn scopes(&self) -> impl Iterator<Item = &Scope> {
        self.scopes.iter()
    }

    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[must_use]
    pub fn budget_micros(&self) -> u64 {
        self.budget_micros
    }

    /// The authorization decision, as taken by the broker on every tool call.
    ///
    /// `now` and `spent_micros` are passed in rather than read from ambient
    /// state so that this stays a pure function — which is what makes it
    /// property-testable and deterministically replayable.
    pub fn permits(&self, req: &Request, now: u64, spent_micros: u64) -> Result<(), Denial> {
        if now >= self.expires_at {
            return Err(Denial::Expired);
        }
        if spent_micros >= self.budget_micros {
            return Err(Denial::BudgetExhausted);
        }
        if !self.scopes.iter().any(|s| s.matches(req)) {
            return Err(Denial::OutOfScope);
        }
        Ok(())
    }

    /// Derive a strictly weaker capability.
    ///
    /// Every field can only move one way. There is no code path — here or
    /// anywhere else in the crate — that produces a capability permitting more
    /// than its parent.
    #[must_use]
    pub fn attenuate(&self, a: &Attenuation) -> Capability {
        let scopes = match &a.restrict_to {
            // Keep only requested scopes that some existing scope already
            // implies. A requested scope the parent never held is silently
            // dropped rather than granted — attenuation cannot be a back door
            // for acquiring authority.
            Some(requested) => requested
                .iter()
                .filter(|r| self.scopes.iter().any(|e| e.implies(r)))
                .cloned()
                .collect(),
            None => self.scopes.clone(),
        };

        Capability {
            scopes,
            expires_at: a
                .not_after
                .map_or(self.expires_at, |t| t.min(self.expires_at)),
            budget_micros: a
                .budget_cap
                .map_or(self.budget_micros, |b| b.min(self.budget_micros)),
        }
    }
}

/// A narrowing request. Every field is a ceiling, never a floor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attenuation {
    /// Replace the scope set with these, keeping only what the parent implies.
    pub restrict_to: Option<BTreeSet<Scope>>,
    /// Shorten the lifetime. Ignored if later than the parent's expiry.
    pub not_after: Option<u64>,
    /// Lower the spend cap. Ignored if higher than the parent's.
    pub budget_cap: Option<u64>,
}

impl Attenuation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn restrict_to(mut self, scopes: impl IntoIterator<Item = Scope>) -> Self {
        self.restrict_to = Some(scopes.into_iter().collect());
        self
    }

    #[must_use]
    pub fn not_after(mut self, t: u64) -> Self {
        self.not_after = Some(t);
        self
    }

    #[must_use]
    pub fn budget_cap(mut self, micros: u64) -> Self {
        self.budget_cap = Some(micros);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap() -> Capability {
        Capability::new(
            [
                Scope::new(Method::Get, "api.internal", "/v1/"),
                Scope::new(Method::Post, "api.internal", "/v1/tickets"),
            ],
            1_000,
            50_000,
        )
    }

    #[test]
    fn attenuation_cannot_widen_scope() {
        // Ask for something the parent never held.
        let child = cap().attenuate(&Attenuation::new().restrict_to([Scope::new(
            Method::Delete,
            "api.internal",
            "/v1/",
        )]));
        let req = Request::new(Method::Delete, "api.internal", "/v1/users/1");
        assert_eq!(child.permits(&req, 0, 0), Err(Denial::OutOfScope));
        assert_eq!(child.scopes().count(), 0);
    }

    #[test]
    fn attenuation_narrows_path_prefix() {
        let child = cap().attenuate(&Attenuation::new().restrict_to([Scope::new(
            Method::Get,
            "api.internal",
            "/v1/users",
        )]));
        assert!(child
            .permits(
                &Request::new(Method::Get, "api.internal", "/v1/users/1"),
                0,
                0
            )
            .is_ok());
        // Sibling paths the parent allowed are now gone.
        assert_eq!(
            child.permits(
                &Request::new(Method::Get, "api.internal", "/v1/orders"),
                0,
                0
            ),
            Err(Denial::OutOfScope)
        );
    }

    #[test]
    fn ttl_and_budget_only_shrink() {
        let child = cap().attenuate(&Attenuation::new().not_after(9_999).budget_cap(9_999_999));
        assert_eq!(
            child.expires_at(),
            1_000,
            "expiry must not extend past the parent"
        );
        assert_eq!(
            child.budget_micros(),
            50_000,
            "budget must not exceed the parent"
        );
    }

    #[test]
    fn empty_capability_permits_nothing() {
        let req = Request::new(Method::Get, "api.internal", "/v1/users");
        assert!(Capability::nothing().permits(&req, 0, 0).is_err());
    }
}
