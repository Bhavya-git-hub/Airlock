//! Hot-path microbenchmarks for the authorization decision.
//!
//! Every tool call an agent makes pays this cost, so it is the tax the whole
//! design levies. These are *microbenchmarks* — they measure the pure decision
//! function with no I/O, no token parsing and no network. The end-to-end
//! broker number (which includes Biscuit verification and Cedar evaluation) is
//! benchmark B2 in docs/BENCHMARK.md and will be larger. Do not quote this
//! number as if it were that one.
//!
//! Run with:  cargo bench -p airlock-core

use airlock_core::{
    decide, Capability, Confidentiality, Integrity, Label, Method, Request, SessionLabel,
    SinkClearance, Scope,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn capability_with_scopes(n: usize) -> Capability {
    // The matching scope is placed last so the linear scan is worst-case. A
    // benchmark that puts it first measures nothing useful.
    let mut scopes: Vec<Scope> = (0..n.saturating_sub(1))
        .map(|i| Scope::new(Method::Get, format!("svc{i}.internal"), "/v1/"))
        .collect();
    scopes.push(Scope::new(Method::Post, "api.internal", "/v1/tickets"));
    Capability::new(scopes, u64::MAX, 1_000_000)
}

fn clean_session() -> SessionLabel {
    let mut s = SessionLabel::new();
    s.observe(Label::new(Confidentiality::Public, Integrity::Trusted));
    s
}

fn tainted_session() -> SessionLabel {
    let mut s = SessionLabel::new();
    s.observe(Label::new(Confidentiality::Secret, Integrity::Untrusted));
    s
}

fn bench_decide(c: &mut Criterion) {
    let req = Request::new(Method::Post, "api.internal", "/v1/tickets/new");
    let sink = SinkClearance::INTERNAL;

    let mut g = c.benchmark_group("decide");

    // Scope-set size sweep: shows whether the linear scan is a real cost at
    // realistic policy sizes, or noise.
    for n in [1usize, 8, 64] {
        let cap = capability_with_scopes(n);
        let session = clean_session();
        g.bench_with_input(BenchmarkId::new("allow", n), &n, |b, _| {
            b.iter(|| {
                decide(
                    black_box(&cap),
                    black_box(&session),
                    black_box(&req),
                    black_box(sink),
                    black_box(0),
                    black_box(0),
                )
            })
        });
    }

    // Denial paths matter as much as the happy path: under attack, denials are
    // the common case, and a slow denial is a DoS vector.
    let cap = capability_with_scopes(8);
    let session = clean_session();
    let out_of_scope = Request::new(Method::Delete, "evil.example", "/steal");
    g.bench_function("deny_out_of_scope", |b| {
        b.iter(|| {
            decide(black_box(&cap), black_box(&session), black_box(&out_of_scope),
                   black_box(sink), black_box(0), black_box(0))
        })
    });

    let tainted = tainted_session();
    g.bench_function("deny_illegal_flow", |b| {
        b.iter(|| {
            decide(black_box(&cap), black_box(&tainted), black_box(&req),
                   black_box(sink), black_box(0), black_box(0))
        })
    });

    g.finish();
}

fn bench_taint_propagation(c: &mut Criterion) {
    let mut g = c.benchmark_group("taint");
    let label = Label::new(Confidentiality::Internal, Integrity::Untrusted);

    g.bench_function("observe", |b| {
        b.iter_batched(
            SessionLabel::new,
            |mut s| { s.observe(black_box(label)); s },
            criterion::BatchSize::SmallInput,
        )
    });

    let session = tainted_session();
    g.bench_function("check_egress", |b| {
        b.iter(|| session.check_egress(black_box(SinkClearance::PUBLIC_EGRESS)))
    });

    g.finish();
}

criterion_group!(benches, bench_decide, bench_taint_propagation);
criterion_main!(benches);
