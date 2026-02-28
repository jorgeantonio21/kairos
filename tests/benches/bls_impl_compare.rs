use consensus::crypto::aggregated::{
    BlsPublicKey as ArkPublicKey, BlsSecretKey as ArkSecretKey, BlsSignature as ArkSignature,
};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use crypto::threshold::ThresholdBLS;
use rand::SeedableRng;
use rand::rngs::StdRng;

const MESSAGE: &[u8] = b"benchmark message for bls implementation comparison";
const AGG_VERIFY_N: usize = 32;

fn ark_keys_and_signatures(
    count: usize,
    message: &[u8],
) -> (Vec<ArkPublicKey>, Vec<u64>, Vec<ArkSignature>) {
    let mut rng = StdRng::from_seed([7u8; 32]);
    let mut public_keys = Vec::with_capacity(count);
    let mut peer_ids = Vec::with_capacity(count);
    let mut signatures = Vec::with_capacity(count);

    for _ in 0..count {
        let sk = ArkSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let sig = sk.sign(message);
        peer_ids.push(pk.to_peer_id());
        public_keys.push(pk);
        signatures.push(sig);
    }

    (public_keys, peer_ids, signatures)
}

fn bench_sign_and_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bls/sign_verify");

    let mut ark_rng = StdRng::from_seed([21u8; 32]);
    let ark_sk = ArkSecretKey::generate(&mut ark_rng);
    let ark_pk = ark_sk.public_key();
    let ark_sig = ark_sk.sign(MESSAGE);

    let mut blst_rng = StdRng::from_seed([22u8; 32]);
    let blst_scheme = ThresholdBLS::new(3, 5);
    let (_blst_master_pk, blst_key_shares) = blst_scheme
        .trusted_setup(&mut blst_rng)
        .expect("BLST key setup for sign benchmark failed");
    let blst_share = blst_key_shares
        .first()
        .cloned()
        .expect("Expected at least one BLST key share");
    let blst_partial = ThresholdBLS::partial_sign(&blst_share, MESSAGE)
        .expect("BLST partial signing setup failed");

    group.bench_function("ark/sign", |b| {
        b.iter(|| {
            let sig = ark_sk.sign(black_box(MESSAGE));
            black_box(sig);
        });
    });

    group.bench_function("blst/partial_sign", |b| {
        b.iter(|| {
            let sig = ThresholdBLS::partial_sign(black_box(&blst_share), black_box(MESSAGE))
                .expect("BLST partial signing failed");
            black_box(sig);
        });
    });

    group.bench_function("ark/verify", |b| {
        b.iter(|| {
            let ok = ark_pk.verify(black_box(MESSAGE), black_box(&ark_sig));
            black_box(ok);
        });
    });

    group.bench_function("blst/verify_partial", |b| {
        b.iter(|| {
            let ok = ThresholdBLS::verify(
                black_box(&blst_share.public_key),
                black_box(MESSAGE),
                black_box(&blst_partial.signature),
            )
            .is_ok();
            black_box(ok);
        });
    });

    group.finish();
}

fn bench_aggregate(c: &mut Criterion) {
    let mut group = c.benchmark_group("bls/aggregate");

    for &n in &[8usize, 32, 64] {
        let (_ark_public_keys, ark_peer_ids, ark_signatures) = ark_keys_and_signatures(n, MESSAGE);
        let mut blst_rng = StdRng::from_seed([31u8; 32]);
        let blst_scheme = ThresholdBLS::new(n, n);
        let (_blst_master_pk, blst_key_shares) = blst_scheme
            .trusted_setup(&mut blst_rng)
            .expect("BLST trusted setup failed");
        let blst_partials: Vec<_> = blst_key_shares
            .iter()
            .take(n)
            .map(|share| {
                ThresholdBLS::partial_sign(share, MESSAGE).expect("BLST partial signing failed")
            })
            .collect();

        group.bench_with_input(BenchmarkId::new("ark", n), &n, |b, _| {
            b.iter(|| {
                let partials: Vec<_> = ark_peer_ids
                    .iter()
                    .copied()
                    .zip(ark_signatures.iter().copied())
                    .collect();
                let aggregated =
                    ArkSignature::combine_partials(black_box(&partials)).expect("Threshold combine failed");
                black_box(aggregated);
            });
        });

        group.bench_with_input(BenchmarkId::new("blst_threshold", n), &n, |b, _| {
            b.iter(|| {
                let aggregated = blst_scheme
                    .aggregate(black_box(&blst_partials))
                    .expect("BLST threshold aggregation failed");
                black_box(aggregated);
            });
        });
    }

    group.finish();
}

fn bench_aggregate_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bls/aggregate_verify");

    let (ark_public_keys, ark_peer_ids, ark_signatures) = ark_keys_and_signatures(AGG_VERIFY_N, MESSAGE);
    let ark_public_key_array: [ArkPublicKey; AGG_VERIFY_N] =
        std::array::from_fn(|i| ark_public_keys[i].clone());
    let ark_peer_id_array: [u64; AGG_VERIFY_N] = std::array::from_fn(|i| ark_peer_ids[i]);
    let ark_partials: Vec<_> = ark_peer_ids
        .iter()
        .copied()
        .zip(ark_signatures.iter().copied())
        .collect();
    let ark_aggregated = ArkSignature::combine_partials(&ark_partials).expect("Threshold combine failed");

    let mut blst_rng = StdRng::from_seed([41u8; 32]);
    let blst_scheme = ThresholdBLS::new(AGG_VERIFY_N, AGG_VERIFY_N);
    let (blst_master_pk, blst_key_shares) = blst_scheme
        .trusted_setup(&mut blst_rng)
        .expect("BLST trusted setup failed");
    let blst_partials: Vec<_> = blst_key_shares
        .iter()
        .take(AGG_VERIFY_N)
        .map(|share| ThresholdBLS::partial_sign(share, MESSAGE).expect("BLST partial signing failed"))
        .collect();
    let blst_aggregated = blst_scheme
        .aggregate(&blst_partials)
        .expect("BLST threshold aggregation failed");

    group.bench_function("ark/N32", |b| {
        b.iter(|| {
            let ok = consensus::crypto::aggregated::BlsPublicKey::verify_threshold(
                black_box(&ark_public_key_array),
                black_box(&ark_peer_id_array),
                black_box(MESSAGE),
                black_box(&ark_aggregated),
            );
            black_box(ok);
        });
    });

    group.bench_function("blst_threshold/N32", |b| {
        b.iter(|| {
            let ok = ThresholdBLS::verify(
                black_box(&blst_master_pk),
                black_box(MESSAGE),
                black_box(&blst_aggregated),
            )
            .is_ok();
            black_box(ok);
        });
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(30);
    targets = bench_sign_and_verify, bench_aggregate, bench_aggregate_verify
);
criterion_main!(benches);
