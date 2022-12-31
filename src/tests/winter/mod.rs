use super::*;
use core::mem;

use field::bn254::BaseElement;
use halo2_proofs::halo2curves::bn256::Fr;

use winter_crypto::{BatchMerkleProof, Digest, ElementHasher};
use winter_fri::{DefaultProverChannel, FriOptions as WinterFriOptions, FriProof, FriProver};
use winter_math::{fft, FieldElement, StarkField};
use winter_utils::AsBytes;

pub mod field;
pub mod hash;

/// Generate evaluations of a random polynomial over the given domain
pub fn eval_rand_polynomial(trace_length: usize, domain_size: usize) -> Vec<BaseElement> {
    // Evaluate a random polynomial on the given domain
    let mut evaluations = (0..trace_length as u64)
        .map(BaseElement::new)
        .collect::<Vec<_>>();
    evaluations.resize(domain_size, BaseElement::ZERO);
    let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
    fft::evaluate_poly(&mut evaluations, &twiddles);
    evaluations
}

/// Build a FRI proof using the Winterfell package
pub fn build_fri_proof<
    B: StarkField,
    E: FieldElement<BaseField = B>,
    H: ElementHasher<BaseField = B>,
>(
    evaluations: Vec<E>,
    channel: &mut DefaultProverChannel<B, E, H>,
    options: WinterFriOptions,
) -> (FriProof, Vec<usize>) {
    let mut prover = FriProver::<B, E, DefaultProverChannel<B, E, H>, H>::new(options);
    prover.build_layers(channel, evaluations.clone());
    let positions = channel.draw_query_positions();
    let proof = prover.build_proof(&positions);
    (proof, positions)
}

/// Convert FRI proof into usable witness data
pub fn extract_witness<const N: usize, H: ElementHasher<BaseField = BaseElement>>(
    proof: FriProof,
    channel: DefaultProverChannel<BaseElement, BaseElement, H>,
    positions: Vec<usize>,
    domain_size: usize,
) -> (LayerCommitments, Vec<Query>, Remainder) {
    // Read layer commitments
    let layer_commitments = channel
        .layer_commitments()
        .iter()
        .map(|x| x.as_bytes())
        .collect::<Vec<_>>();

    // Parse remainder
    let remainder = proof
        .parse_remainder::<BaseElement>()
        .unwrap()
        .iter()
        .map(|x| base_element_to_fr(*x))
        .collect::<Vec<_>>();

    // Parse layer queries
    let (layer_queries, layer_merkle_proofs) = proof.parse_layers(domain_size, N).unwrap();
    let layer_queries = layer_queries
        .into_iter()
        .map(|query| {
            group_vector_elements::<BaseElement, N>(query)
                .iter()
                .map(|x| x.iter().map(|y| base_element_to_fr(*y)).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<Vec<_>>>();

    // Unbatch layer proofs, indexed first by layer, and then by query
    // position index
    let mut indices = positions.clone();
    let mut source_domain_size = domain_size;
    let layer_proofs = layer_merkle_proofs
        .into_iter()
        .map(|layer_proof: BatchMerkleProof<H>| {
            indices = fold_positions(&indices, source_domain_size, N);
            source_domain_size /= N;
            layer_proof
                .into_paths(&indices)
                .unwrap()
                .iter()
                .map(|paths| {
                    paths
                        .into_iter()
                        .map(|x| <[u8; 32]>::try_from(x.as_bytes()).unwrap())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    // Build queries
    let queries = positions
        .into_iter()
        .enumerate()
        .map(|(_i, position)| {
            let layers = layer_proofs
                .iter()
                .enumerate()
                .map(|(_n, _proof)| fri::QueryLayerWitness {
                    // TODO: Lookup evaluations and merkle proofs from layer_queries
                    // and layer_proofs respectively, at the position indices
                    evaluations: vec![Fr::from(1); 56], // TODO
                    merkle_proof: vec![],               // TODO
                })
                .collect();
            fri::QueryWitness { position, layers }
        })
        .collect::<Vec<_>>();

    return (layer_commitments, queries, remainder);
}

pub fn fold_positions(
    positions: &[usize],
    source_domain_size: usize,
    folding_factor: usize,
) -> Vec<usize> {
    let target_domain_size = source_domain_size / folding_factor;
    let mut result = Vec::new();
    for position in positions {
        let position = position % target_domain_size;
        // make sure we don't record duplicated values
        if !result.contains(&position) {
            result.push(position);
        }
    }
    result
}

pub fn group_vector_elements<T, const N: usize>(source: Vec<T>) -> Vec<[T; N]> {
    assert_eq!(
        source.len() % N,
        0,
        "source length must be divisible by {}, but was {}",
        N,
        source.len()
    );
    let mut v = mem::ManuallyDrop::new(source);
    let p = v.as_mut_ptr();
    let len = v.len() / N;
    let cap = v.capacity() / N;
    unsafe { Vec::from_raw_parts(p as *mut [T; N], len, cap) }
}

// TODO: Correctly convert [u8; 32] to field element Fr
fn base_element_to_fr(y: BaseElement) -> Fr {
    Fr::from_repr(<[u8; 32]>::try_from(y.as_bytes()).unwrap()).unwrap()
}
