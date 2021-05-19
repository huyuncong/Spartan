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
  dense_mlpoly::{DensePolynomial, PolyCommitmentGens},
  random::RandomTape,
  sumcheck::SumcheckInstanceProof,
  Instance, NIZKGens, NIZK,
};
use merlin::Transcript;

use criterion::*;

fn poly_commit_helper(
  poly: &DensePolynomial,
  gens_pc: &PolyCommitmentGens,
  random_tape: &mut RandomTape,
) {
  let (comm_vars, blinds_vars) = poly.commit(&gens_pc, Some(random_tape));
}

fn poly_commit_benchmark(c: &mut Criterion) {
  for &s in [12, 13, 14, 15, 16, 17, 18, 19, 20].iter() {
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    let mut group = c.benchmark_group("Sumcheck_prove_benchmark");
    group.plot_config(plot_config);

    let mut csprng: OsRng = OsRng;
    let num_size = 1 << s;
    let num_rounds = s;
    let mut A = Vec::with_capacity(num_size);
    for _ in 0..num_size {
      let tmpA = Scalar::random(&mut csprng);
      A.push(tmpA);
    }

    let gens_pc = PolyCommitmentGens::new(s, b"gens_r1cs_sat");

    let mut poly_A = DensePolynomial::new(A);

    let mut transcript = Transcript::new(b"test");

    let mut random_tape = RandomTape::new(b"proof");

    let name = format!("Poly_commit_{}", s);
    group.bench_function(&name, move |b| {
      b.iter(|| {
        poly_commit_helper(&poly_A, &gens_pc, &mut random_tape);
      });
    });
    group.finish();
  }
}

fn set_duration() -> Criterion {
  Criterion::default().sample_size(10)
}

criterion_group! {
name = benches_nizk;
config = set_duration();
targets = poly_commit_benchmark
}

criterion_main!(benches_nizk);
