extern crate byteorder;
extern crate core;
extern crate criterion;
extern crate digest;
extern crate libspartan;
extern crate merlin;
extern crate rand;
extern crate sha3;
use libspartan::scalar::Scalar;
use rand::rngs::OsRng;

use libspartan::{
  dense_mlpoly::{DensePolynomial, PolyCommitmentGens, PolyEvalProof},
  group::{GroupElement, VartimeMultiscalarMul, GROUP_BASEPOINT_COMPRESSED},
  random::RandomTape,
  sumcheck::SumcheckInstanceProof,
  Instance, NIZKGens, NIZK,
};
use merlin::Transcript;

use criterion::*;

fn field_add_bench(
  c: &mut Criterion,
  // config: ProverConfig,
  num_instances: usize,
) {
  let mut csprng: OsRng = OsRng;

  let mut group = c.benchmark_group("Crypto");

  let mut alpha = Vec::with_capacity(num_instances);
  for _ in 0..num_instances {
    alpha.push(Scalar::random(&mut csprng));
  }
  group.bench_function("Field_add", |b| {
    let mut res = Scalar::one();
    b.iter(|| {
      for a in alpha.iter() {
        res = res + a;
      }
    })
  });
}

fn field_mul_bench(
  c: &mut Criterion,
  // config: ProverConfig,
  num_instances: usize,
) {
  let mut csprng: OsRng = OsRng;

  let mut group = c.benchmark_group("Crypto");
  let mut alpha = Vec::with_capacity(num_instances);
  // let mut beta = Vec::with_capacity(num_instances);
  for _ in 0..num_instances {
    alpha.push(Scalar::random(&mut csprng));
    // beta.push(E::Fr::rand(&mut rng));
  }
  let d = 0;
  group.bench_with_input(BenchmarkId::new(format!("Field_mul"), d), &d, |b, &d| {
    let mut res = Scalar::one();
    b.iter(|| {
      for a in alpha.iter() {
        res = res * a;
      }
    })
  });
}

fn group_add_bench(
  c: &mut Criterion,
  // config: ProverConfig,
  num_instances: usize,
) {
  let mut csprng: OsRng = OsRng;

  let mut group = c.benchmark_group("Crypto");
  let alpha = GroupElement::random(&mut csprng);
  // let beta = E::G1Projective::rand(&mut rng);
  let d = 0;
  group
    .sample_size(10)
    .bench_with_input(BenchmarkId::new(format!("Group_add"), d), &d, |b, &d| {
      let mut res = GroupElement::random(&mut csprng);
      b.iter(|| {
        for _ in 0..num_instances {
          res = res + alpha;
        }
      })
    });
}

fn group_mul_bench(
  c: &mut Criterion,
  // config: ProverConfig,
  num_instances: usize,
) {
  let mut csprng: OsRng = OsRng;

  let mut group = c.benchmark_group("Crypto");
  let alpha = Scalar::random(&mut csprng);
  // let beta = E::G1Projective::rand(&mut rng);
  let d = 0;
  group
    .sample_size(10)
    .bench_with_input(BenchmarkId::new(format!("Group_mul"), d), &d, |b, &d| {
      let mut res = GroupElement::random(&mut csprng);
      b.iter(|| {
        for _ in 0..num_instances {
          alpha * res;
        }
      })
    });
}

fn group_multi_mul_bench(
  c: &mut Criterion,
  // config: ProverConfig,
  // num_instances: usize,
) {
  let mut csprng: OsRng = OsRng;

  let mut group = c.benchmark_group("Crypto");
  for d in 12..21 {
    let size = 1 << d;
    let mut alpha = Vec::with_capacity(size);
    let mut beta = Vec::with_capacity(size);

    for _ in 0..size {
      alpha.push(Scalar::random(&mut csprng));
      beta.push(GroupElement::random(&mut csprng));
    }

    group
      .sample_size(10)
      .bench_with_input(BenchmarkId::new(format!("MSM"), d), &d, |b, &d| {
        b.iter(|| GroupElement::vartime_multiscalar_mul(alpha.iter(), beta.iter()));
      });
  }
}

fn crypto_benchmark(c: &mut Criterion) {
  field_add_bench(c, 1000);
  field_mul_bench(c, 1000);
  group_add_bench(c, 1000);
  group_mul_bench(c, 1000);
  group_multi_mul_bench(c);
}

fn set_duration() -> Criterion {
  Criterion::default().sample_size(10)
}

criterion_group! {
name = benches_nizk;
config = set_duration();
targets = crypto_benchmark
}

criterion_main!(benches_nizk);
