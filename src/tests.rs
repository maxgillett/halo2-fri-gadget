use super::*;
use ff::PrimeField;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use winter_crypto::{Digest, ElementHasher, Hasher};
use winter_fri::FriOptions as WinterFriOptions;

mod winter;
use winter::eval_rand_polynomial;
use winter::field::bn254::BaseElement;
use winter::hash::poseidon::Poseidon;

// TODO: Make field generic below, and test with Goldilocks
//use halo2_arithmetic::goldilocks;
//use winter_math::fields::f64::BaseElement;

type LayerCommitments = Vec<[u8; 32]>;
type Query = fri::QueryWitness<Fr>;
type Remainder = Vec<Fr>;

#[test]
fn test_verify_winter() {
    env_logger::init();

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
    let public_coin_seed =
        Fr::from_repr(<[u8; 32]>::try_from(&seed.as_bytes()[..]).unwrap()).unwrap();

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
            log_degree: (domain_size as usize).ilog2() as usize,
        },
        public_coin_seed,
        _marker: PhantomData,
    };

    let public_input = vec![Fr::from(1)];
    let prover = MockProver::run(18, &circuit, vec![public_input]).unwrap();
    prover.assert_satisfied();
}
