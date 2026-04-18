use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use rusty_secrets::dss::ss1;

mod support;

const CASES: [(&str, u8, u8); 2] = [("1kb_3_5", 3, 5), ("1kb_10_25", 10, 25)];

fn bench_generate(c: &mut Criterion) {
    let secret = support::secret_1kb();
    let mut group = c.benchmark_group("ss1/generate");

    for (name, k, n) in CASES {
        group.bench_function(name, |b| {
            b.iter(|| {
                let shares = ss1::split_secret(
                    k,
                    n,
                    black_box(secret),
                    ss1::Reproducibility::reproducible(),
                    &None,
                )
                .unwrap();
                black_box(shares);
            });
        });
    }

    group.finish();
}

fn bench_recover(c: &mut Criterion) {
    let secret = support::secret_1kb();
    let mut group = c.benchmark_group("ss1/recover");

    for (name, k, n) in CASES {
        let shares = ss1::split_secret(k, n, secret, ss1::Reproducibility::reproducible(), &None)
            .unwrap()
            .into_iter()
            .take(k as usize)
            .collect::<Vec<_>>();

        group.bench_function(name, move |b| {
            b.iter(|| {
                let recovered = ss1::recover_secret(black_box(shares.as_slice())).unwrap();
                black_box(recovered);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_generate, bench_recover);
criterion_main!(benches);
