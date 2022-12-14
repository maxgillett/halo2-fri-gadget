use super::*;
use core::mem;
use itertools::Itertools;
use std::collections::HashMap;

use field::bn254::BaseElement;
use halo2_proofs::halo2curves::bn256::Fr;

use winter_crypto::{Digest, ElementHasher};
use winter_fri::{FriOptions as WinterFriOptions, FriProof, FriProver};
use winter_math::{fft, FieldElement, StarkField};
use winter_utils::AsBytes;

pub mod channel;
pub use channel::DefaultProverChannel;

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

    // Parse layer queries and Merkle proofs
    let (layer_queries, layer_merkle_proofs) = proof
        .parse_layers::<H, BaseElement>(domain_size, N)
        .unwrap();

    // Unbatch and reinsert queries/proofs
    let mut indices = positions.clone();
    let mut source_domain_size = domain_size;
    let (layer_queries, layer_merkle_proofs) = {
        let mut layer_queries_ = vec![];
        let mut layer_merkle_proofs_ = vec![];
        for (queries, batch_merkle_proof) in layer_queries.into_iter().zip(layer_merkle_proofs) {
            indices = fold_positions(&indices, source_domain_size, N);
            source_domain_size /= N;
            let indices_deduped = indices.iter().cloned().unique().collect::<Vec<_>>();
            let mut query_map = HashMap::new();
            let mut proof_map = HashMap::new();
            for (index, values, proofs) in itertools::izip!(
                &indices_deduped,
                group_vector_elements::<BaseElement, N>(queries),
                batch_merkle_proof.into_paths(&indices_deduped[..]).unwrap()
            ) {
                query_map.insert(
                    index,
                    values
                        .iter()
                        .map(|x| base_element_to_fr(*x))
                        .collect::<Vec<_>>(),
                );
                proof_map.insert(
                    index,
                    proofs
                        .into_iter()
                        .map(|x: H::Digest| <[u8; 32]>::try_from(x.as_bytes()).unwrap())
                        .collect::<Vec<_>>(),
                );
            }
            let (q, p): (Vec<_>, Vec<_>) = indices
                .iter()
                .map(|i| {
                    (
                        query_map.get(i).unwrap().clone(),
                        proof_map.get(i).unwrap().clone(),
                    )
                })
                .into_iter()
                .unzip();
            layer_queries_.push(q);
            layer_merkle_proofs_.push(p);
        }
        (layer_queries_, layer_merkle_proofs_)
    };

    // Build queries
    let queries = positions
        .into_iter()
        .enumerate()
        .map(|(i, position)| {
            let layers = (0..layer_queries.len())
                .map(|j| fri::QueryLayerWitness {
                    evaluations: layer_queries[j][i].clone(),
                    merkle_proof: layer_merkle_proofs[j][i].clone(),
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
        result.push(position);
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

fn base_element_to_fr(y: BaseElement) -> Fr {
    Fr::from_repr(<[u8; 32]>::try_from(y.as_bytes()).unwrap()).unwrap()
}
