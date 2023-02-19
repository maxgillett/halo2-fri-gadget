use super::*;
use crate::fields::{fp::FpChip, fp2::Fp2Chip};
use crate::hash::{
    poseidon_bn254::chip::PoseidonChipBn254_8_58, poseidon_fp64::chip::PoseidonChipFp64_8_22,
};
use crate::random::RandomCoin;
use curves::bn256::{Bn256, Fr};
use ff::PrimeField;
use goldilocks::{fp::Goldilocks as Fp, fp2::GoldilocksExtension as Fp2};
use halo2_base::gates::{
    range::{RangeConfig, RangeStrategy},
    GateInstructions,
};
use halo2_proofs::dev::MockProver;
use halo2_proofs::{
    plonk::{
        create_proof as create_plonk_proof, keygen_pk, keygen_vk,
        verify_proof as verify_plonk_proof, Circuit, ConstraintSystem, Error,
    },
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::AccumulatorStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand_core::OsRng;
use std::time::Instant;
use winter_crypto::{Digest, Hasher};
use winter_fri::FriOptions as WinterFriOptions;
use winter_math::fields::{f64::BaseElement as F64, QuadExtension};
use winter_math::StarkField;

mod winter;
use winter::{
    field::{bn254::BaseElement as BN254, FP64},
    hash::{poseidon_bn254::Poseidon as Poseidon256, poseidon_fp64::Poseidon as Poseidon64},
};

type LayerCommitments = Vec<[u8; 32]>;
type Query<const D: usize, F> = FriQueryInput<D, F>;
type Remainder<F> = Vec<F>;

type PoseidonBn254 = Poseidon256<BN254>;
type PoseidonFp64 = Poseidon64;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[test]
fn test_mock_verify_winter_fp64() {
    init();

    // Polynomial parameters
    let trace_length = 1024;
    let blowup_factor = 2;
    let domain_size = trace_length * blowup_factor;

    // Fri parameters
    let folding_factor = 2;
    let num_queries = 28;
    let max_remainder_degree = 16;

    // Evaluate a random polynomial over the domain
    let evaluations =
        winter::eval_rand_polynomial::<F64, QuadExtension<F64>>(trace_length, domain_size);

    // Build a FRI proof
    let mut channel = winter::DefaultProverChannel::<F64, QuadExtension<F64>, PoseidonFp64>::new(
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
        2 => winter::extract_witness::<
            2,                  // Folding factor
            2,                  // Extension field degree
            Fp,                 // Base field (Halo2)
            F64,                // Base field (Winterfell)
            QuadExtension<F64>, // Extension field (Winterfell)
            PoseidonFp64,       // Hash function (Winterfell)
        >(proof, channel, positions, domain_size),
        _ => panic!("unsupported folding factor"),
    };

    let seed = PoseidonFp64::hash(&[]);
    let public_coin_seed = seed.as_elements().to_vec();

    let circuit = FriVerifierCircuit::<
        2,                         // Extension field degree
        Fp,                        // Base field
        Fp2Chip<Fp>,               // Extension field chip
        PoseidonChipFp64_8_22<Fp>, // Hash function
        RandomCoin<Fp, PoseidonChipFp64_8_22<Fp>>,
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

    let prover = MockProver::run(20, &circuit, vec![vec![]]).unwrap();
    prover.assert_satisfied();
}

#[test]
fn test_mock_verify_winter_bn254() {
    init();

    // Polynomial parameters
    let trace_length = 1024;
    let blowup_factor = 2;
    let domain_size = trace_length * blowup_factor;

    // Fri parameters
    let folding_factor = 2;
    let num_queries = 28;
    let max_remainder_degree = 16;
    type HashFn = PoseidonBn254;

    // Evaluate a random polynomial over the domain
    let evaluations = winter::eval_rand_polynomial(trace_length, domain_size);

    // Build a FRI proof
    let mut channel =
        winter::DefaultProverChannel::<BN254, BN254, HashFn>::new(domain_size, num_queries);
    let (proof, positions) = winter::build_fri_proof(
        evaluations,
        &mut channel,
        WinterFriOptions::new(blowup_factor, folding_factor, max_remainder_degree),
    );

    // Extract witness data from proof
    let (layer_commitments, queries, remainder) = match folding_factor {
        2 => winter::extract_witness::<
            2,      // Folding factor
            1,      // Extension field degree
            Fr,     // Base field (Halo2)
            BN254,  // Base field (Winterfell)
            BN254,  // Extension field (Winterfell)
            HashFn, // Hash function (Winterfell)
        >(proof, channel, positions, domain_size),
        _ => panic!("unsupported folding factor"),
    };

    let seed = PoseidonBn254::hash(&[]);
    let mut bytes = [0u8; 32];
    for (v, b) in bytes.as_mut().iter_mut().zip(seed.as_bytes()) {
        *v = b;
    }
    let public_coin_seed = vec![Fr::from_repr(bytes).unwrap()];

    let circuit = FriVerifierCircuit::<
        1,                          // Extension field degree
        Fr,                         // Base field
        FpChip<Fr>,                 // Extension field chip
        PoseidonChipBn254_8_58<Fr>, // Hash function
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

    let prover = MockProver::run(20, &circuit, vec![vec![]]).unwrap();
    prover.assert_satisfied();
}

//#[test]
//fn test_verify_winter_bn254() {
//    init();
//
//    // Polynomial parameters
//    let trace_length = 512; //16384;
//    let blowup_factor = 2;
//    let domain_size = trace_length * blowup_factor;
//
//    // Fri parameters
//    let folding_factor = 2;
//    let num_queries = 28;
//    let max_remainder_degree = 16;
//    type HashFn = PoseidonBn254;
//
//    // Evaluate a random polynomial over the domain
//    let evaluations = winter::eval_rand_polynomial(trace_length, domain_size);
//
//    // Build a FRI proof
//    let mut channel =
//        winter::DefaultProverChannel::<BN254, BN254, HashFn>::new(domain_size, num_queries);
//    let (proof, positions) = winter::build_fri_proof(
//        evaluations,
//        &mut channel,
//        WinterFriOptions::new(blowup_factor, folding_factor, max_remainder_degree),
//    );
//
//    // Extract witness data from proof
//    let (layer_commitments, queries, remainder) = match folding_factor {
//        2 => winter::extract_witness::<2, Fr, BN254, BN254, HashFn>(
//            proof,
//            channel,
//            positions,
//            domain_size,
//        ),
//        _ => panic!("unsupported folding factor"),
//    };
//
//    let seed = HashFn::hash(&[]);
//    let mut bytes = [0u8; 32];
//    for (v, b) in bytes.as_mut().iter_mut().zip(seed.as_bytes()) {
//        *v = b;
//    }
//    let public_coin_seed = Fr::from_repr(bytes).unwrap();
//
//    let circuit = FriVerifierCircuit::<
//        Fr,
//        PoseidonChipBn254_8_58<Fr>,
//        RandomCoin<Fr, PoseidonChipBn254_8_58<Fr>>,
//    > {
//        layer_commitments,
//        queries,
//        remainder,
//        options: FriOptions {
//            folding_factor,
//            max_remainder_degree,
//            log_degree: domain_size.ilog2() as usize,
//        },
//        public_coin_seed,
//        _marker: PhantomData,
//    };
//
//    let k = 16;
//    let params = ParamsKZG::<Bn256>::new(k);
//    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
//    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("keygen_pk should not fail");
//
//    debug!("Generating proof...");
//    let now = Instant::now();
//    let mut transcript = <Blake2bWrite<_, _, Challenge255<_>>>::init(vec![]);
//    create_plonk_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
//        &params,
//        &pk,
//        &[circuit.clone()],
//        &[],
//        OsRng,
//        &mut transcript,
//    )
//    .expect("proof generation should not fail");
//    let proof = transcript.finalize();
//    let elapsed = now.elapsed();
//    debug!("Proof generation finished in {:.2?}", elapsed);
//
//    debug!("Verifying proof...");
//    let now = Instant::now();
//    let verifier_params = params.verifier_params();
//    let strategy = AccumulatorStrategy::new(verifier_params);
//    let mut transcript = <Blake2bRead<_, _, Challenge255<_>>>::init(&proof[..]);
//    let strategy = verify_plonk_proof::<
//        KZGCommitmentScheme<Bn256>,
//        VerifierSHPLONK<_>,
//        _,
//        Blake2bRead<_, _, Challenge255<_>>,
//        halo2_proofs::poly::kzg::strategy::AccumulatorStrategy<'_, Bn256>,
//    >(verifier_params, &vk, strategy, &[], &mut transcript)
//    .unwrap();
//    //strategy.finalize();
//    let elapsed = now.elapsed();
//    debug!("Proof verification finished in {:.2?}", elapsed);
//}

#[test]
fn test_poseidon_hash_bn254() {
    init();

    #[derive(Default)]
    struct MyCircuit {}

    impl<F: FieldExt> Circuit<F> for MyCircuit {
        type Config = RangeConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            RangeConfig::configure(meta, RangeStrategy::PlonkPlus, &[50], &[1], 1, 3, 0, 15)
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
                            max_rows: config.gate.max_rows,
                            fixed_columns: config.gate.constants.clone(),
                            num_context_ids: 1,
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
                    let digest_winter = PoseidonBn254::hash(&bytes);
                    let mut bytes = F::Repr::default();
                    for (v, b) in bytes.as_mut().iter_mut().zip(digest_winter.as_bytes()) {
                        *v = b;
                    }
                    let digest_winter = F::from_repr(bytes).unwrap();

                    // Halo2 digest
                    let poseidon_chip = PoseidonChipBn254_8_58::new(&mut ctx, &config.gate);
                    let cells = config.gate.assign_region(
                        &mut ctx,
                        elements
                            .into_iter()
                            .map(|x| Constant(x))
                            .collect::<Vec<_>>(),
                        vec![],
                    );
                    let digest = poseidon_chip.hash_elements(&mut ctx, &config.gate, &cells)?;

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
    MockProver::<Fr>::run(15, &circuit, vec![]).unwrap();
}
