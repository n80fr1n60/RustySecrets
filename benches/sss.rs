use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use rusty_secrets::sss;

mod support;

const CASES: [(&str, u8, u8, bool); 4] = [
    ("1kb_3_5", 3, 5, false),
    ("1kb_3_5_signed", 3, 5, true),
    ("1kb_10_25", 10, 25, false),
    ("1kb_10_25_signed", 10, 25, true),
];

fn bench_generate(c: &mut Criterion) {
    let secret = support::secret_1kb();
    let mut group = c.benchmark_group("sss/generate");

    for (name, k, n, signed) in CASES {
        group.bench_function(name, |b| {
            b.iter(|| {
                let shares = sss::split_secret(k, n, black_box(secret), signed).unwrap();
                black_box(shares);
            });
        });
    }

    group.finish();
}

fn bench_recover(c: &mut Criterion) {
    let secret = support::secret_1kb();
    let mut group = c.benchmark_group("sss/recover");

    for (name, k, n, signed) in CASES {
        let shares = sss::split_secret(k, n, secret, signed)
            .unwrap()
            .into_iter()
            .take(k as usize)
            .collect::<Vec<_>>();

        group.bench_function(name, move |b| {
            b.iter(|| {
                let recovered = sss::recover_secret(black_box(shares.as_slice()), signed).unwrap();
                black_box(recovered);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_generate, bench_recover);
criterion_main!(benches);
