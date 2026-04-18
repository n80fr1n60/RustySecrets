use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use rusty_secrets::dss::thss;

mod support;

const CASES: [(&str, u8, u8); 2] = [("1kb_3_5", 3, 5), ("1kb_10_25", 10, 25)];

fn bench_generate(c: &mut Criterion) {
    let secret = support::secret_1kb();
    let mut group = c.benchmark_group("thss/generate");

    for (name, k, n) in CASES {
        group.bench_function(name, |b| {
            b.iter(|| {
                let shares = thss::split_secret(k, n, black_box(secret), &None).unwrap();
                black_box(shares);
            });
        });
    }

    group.finish();
}

fn bench_recover(c: &mut Criterion) {
    let secret = support::secret_1kb();
    let mut group = c.benchmark_group("thss/recover");

    for (name, k, n) in CASES {
        let shares = thss::split_secret(k, n, secret, &None)
            .unwrap()
            .into_iter()
            .take(k as usize)
            .collect::<Vec<_>>();

        group.bench_function(name, move |b| {
            b.iter(|| {
                let recovered = thss::recover_secret(black_box(shares.as_slice())).unwrap();
                black_box(recovered);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_generate, bench_recover);
criterion_main!(benches);
