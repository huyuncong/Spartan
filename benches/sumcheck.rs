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
  dense_mlpoly::DensePolynomial, sumcheck::SumcheckInstanceProof, Instance, NIZKGens, NIZK,
};
use merlin::Transcript;

use criterion::*;

fn sumcheck_prove_benchmark(c: &mut Criterion) {
  for &s in [12, 13, 14, 15, 16, 17, 18, 19, 20].iter() {
    let plot_config = PlotConfiguration::default().summary_scale(AxisScale::Logarithmic);
    let mut group = c.benchmark_group("Sumcheck_prove_benchmark");
    group.plot_config(plot_config);

    let mut csprng: OsRng = OsRng;
    let num_size = 1 << s;
    let num_rounds = s;
    let mut A = Vec::with_capacity(num_size);
    let mut B = Vec::with_capacity(num_size);
    let mut C = Vec::with_capacity(num_size);

    let mut claim = Scalar::zero();
    for _ in 0..num_size {
      let tmpA = Scalar::random(&mut csprng);
      A.push(tmpA);
      let tmpB = Scalar::random(&mut csprng);
      B.push(tmpB);
      let tmpC = Scalar::random(&mut csprng);
      C.push(tmpC);
      claim += tmpA * tmpB * tmpC;
    }

    let mut poly_A = DensePolynomial::new(A);
    let mut poly_B = DensePolynomial::new(B);
    let mut poly_C = DensePolynomial::new(C);

    let comb_func_prod = |poly_A_comp: &Scalar,
                          poly_B_comp: &Scalar,
                          poly_C_comp: &Scalar|
     -> Scalar { poly_A_comp * poly_B_comp * poly_C_comp };

    let mut transcript = Transcript::new(b"test");

    let name = format!("NIZK_prove_{}", s);
    group.bench_function(&name, move |b| {
      b.iter(|| {
        let mut prover_transcript = Transcript::new(b"example");
        SumcheckInstanceProof::prove_cubic(
          &claim,
          num_rounds,
          &mut poly_A,
          &mut poly_B,
          &mut poly_C,
          comb_func_prod,
          &mut prover_transcript,
        );
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
targets = sumcheck_prove_benchmark
}

criterion_main!(benches_nizk);
