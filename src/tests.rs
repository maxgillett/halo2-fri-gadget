use super::*;
use ff::PrimeField;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use std::time::Instant;
use winter_crypto::{Digest, Hasher};
use winter_fri::FriOptions as WinterFriOptions;

use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::plonk::{
    create_proof as create_plonk_proof, keygen_pk, keygen_vk, verify_proof as verify_plonk_proof,
    Circuit, ConstraintSystem, Error,
};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use rand_core::OsRng;

mod winter;
use winter::eval_rand_polynomial;
use winter::field::bn254::BaseElement;
use winter::hash::poseidon::Poseidon;

// TODO: Test with Goldilocks
//use halo2_arithmetic::goldilocks;
//use winter_math::fields::f64::BaseElement;

type LayerCommitments = Vec<[u8; 32]>;
type Query = FriQueryWitness<Fr>;
type Remainder = Vec<Fr>;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[test]
fn test_verify_winter() {
    init();

    // Polynomial parameters
    let trace_length = 16384;
    let blowup_factor = 2;
    let domain_size = trace_length * blowup_factor;

    // Fri parameters
    let folding_factor = 2;
    let num_queries = 28;
    let max_remainder_degree = 16;
    type HashFn = Poseidon<BaseElement>;

    // Evaluate a random polynomial over the domain
    let evaluations = eval_rand_polynomial(trace_length, domain_size);

    // Build a FRI proof
    let mut channel = winter::DefaultProverChannel::<BaseElement, BaseElement, HashFn>::new(
        domain_size,
        num_queries,
    );
    let (proof, positions) = winter::build_fri_proof(
        evaluations,
        &mut channel,
        WinterFriOptions::new(blowup_factor, folding_factor, max_remainder_degree),
    );

    // Extract witness data from proof
    let (layer_commitments, queries, remainder) = match folding_factor {
        2 => winter::extract_witness::<2, HashFn>(proof, channel, positions, domain_size),
        _ => panic!("unsupported folding factor"),
    };

    let seed = Poseidon::<BaseElement>::hash(&[]);
    let mut bytes = [0u8; 32];
    for (v, b) in bytes.as_mut().iter_mut().zip(seed.as_bytes()) {
        *v = b;
    }
    let public_coin_seed = Fr::from_repr(bytes).unwrap();

    let circuit = FriVerifierCircuit::<
        Fr,
        PoseidonChipBn254_8_58<Fr>,
        RandomCoin<Fr, PoseidonChipBn254_8_58<Fr>>,
    > {
        layer_commitments,
        queries,
        remainder,
        options: FriOptions {
            folding_factor,
            max_remainder_degree,
            log_degree: domain_size.ilog2() as usize,
        },
        public_coin_seed,
        _marker: PhantomData,
    };

    let k = 17;
    let params = ParamsKZG::<Bn256>::new(k);
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("keygen_pk should not fail");

    debug!("Generating proof...");
    let now = Instant::now();
    let mut transcript = <Blake2bWrite<_, _, Challenge255<_>>>::init(vec![]);
    create_plonk_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit.clone()],
        &[],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();
    let elapsed = now.elapsed();
    debug!("Proof generation finished in {:.2?}", elapsed);

    debug!("Verifying proof...");
    let now = Instant::now();
    let verifier_params = params.verifier_params();
    let strategy = AccumulatorStrategy::new(verifier_params);
    let mut transcript = <Blake2bRead<_, _, Challenge255<_>>>::init(&proof[..]);
    let strategy = verify_plonk_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<_>,
        _,
        Blake2bRead<_, _, Challenge255<_>>,
        halo2_proofs::poly::kzg::strategy::AccumulatorStrategy<'_, Bn256>,
    >(verifier_params, &vk, strategy, &[], &mut transcript)
    .unwrap();
    //strategy.finalize();
    let elapsed = now.elapsed();
    debug!("Proof verification finished in {:.2?}", elapsed);
}

#[test]
fn test_mock_verify_winter() {
    init();

    // Polynomial parameters
    let trace_length = 1024;
    let blowup_factor = 2;
    let domain_size = trace_length * blowup_factor;

    // Fri parameters
    let folding_factor = 2;
    let num_queries = 28;
    let max_remainder_degree = 16;
    type HashFn = Poseidon<BaseElement>;

    // Evaluate a random polynomial over the domain
    let evaluations = eval_rand_polynomial(trace_length, domain_size);

    // Build a FRI proof
    let mut channel = winter::DefaultProverChannel::<BaseElement, BaseElement, HashFn>::new(
        domain_size,
        num_queries,
    );
    let (proof, positions) = winter::build_fri_proof(
        evaluations,
        &mut channel,
        WinterFriOptions::new(blowup_factor, folding_factor, max_remainder_degree),
    );

    // Extract witness data from proof
    let (layer_commitments, queries, remainder) = match folding_factor {
        2 => winter::extract_witness::<2, HashFn>(proof, channel, positions, domain_size),
        _ => panic!("unsupported folding factor"),
    };

    let seed = Poseidon::<BaseElement>::hash(&[]);
    let mut bytes = [0u8; 32];
    for (v, b) in bytes.as_mut().iter_mut().zip(seed.as_bytes()) {
        *v = b;
    }
    let public_coin_seed = Fr::from_repr(bytes).unwrap();

    let circuit = FriVerifierCircuit::<
        Fr,
        PoseidonChipBn254_8_58<Fr>,
        RandomCoin<Fr, PoseidonChipBn254_8_58<Fr>>,
    > {
        layer_commitments,
        queries,
        remainder,
        options: FriOptions {
            folding_factor,
            max_remainder_degree,
            log_degree: domain_size.ilog2() as usize,
        },
        public_coin_seed,
        _marker: PhantomData,
    };

    let prover = MockProver::run(17, &circuit, vec![vec![]]).unwrap();
    prover.assert_satisfied();
}

#[test]
fn test_poseidon_hash() {
    init();

    #[derive(Default)]
    struct MyCircuit {}

    const NUM_ADVICE: usize = 6;

    impl<F: FieldExt> Circuit<F> for MyCircuit {
        type Config = FlexGateConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            FlexGateConfig::configure(
                meta,
                GateStrategy::PlonkPlus,
                &[NUM_ADVICE],
                1,
                "default".to_string(),
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "gate",
                |region| {
                    let mut ctx = Context::new(
                        region,
                        ContextParams {
                            num_advice: vec![("default".to_string(), NUM_ADVICE)],
                        },
                    );

                    // Select 5 random field elements, and concat to bytes vector
                    let rng = rand::rngs::mock::StepRng::new(42, 1);
                    let elements = [F::random(rng); 5];
                    let mut bytes = vec![];
                    for e in elements.iter() {
                        for b in e.to_repr().as_ref().iter().cloned() {
                            bytes.push(b);
                        }
                    }

                    // Winterfell digest
                    let digest_winter = Poseidon::<BaseElement>::hash(&bytes);
                    let mut bytes = F::Repr::default();
                    for (v, b) in bytes.as_mut().iter_mut().zip(digest_winter.as_bytes()) {
                        *v = b;
                    }
                    let digest_winter = F::from_repr(bytes).unwrap();

                    // Halo2 digest
                    let mut poseidon_chip = PoseidonChipBn254_8_58::new(&mut ctx, &config);
                    let cells = config.assign_region(
                        &mut ctx,
                        elements
                            .into_iter()
                            .map(|x| Constant(x))
                            .collect::<Vec<_>>(),
                        vec![],
                        None,
                    )?;
                    let digest = poseidon_chip.hash(&mut ctx, &config, &cells)?;

                    // Compare digests
                    digest.to_assigned()[0].value().assert_if_known(|x| {
                        assert_eq!(**x, digest_winter);
                        true
                    });

                    Ok(())
                },
            )
        }
    }

    let circuit = MyCircuit {};
    MockProver::<Fr>::run(12, &circuit, vec![]).unwrap();
}
