# Halo2 FRI Gadget

## The protocol

The FRI IOP (Fast Reed-Solomon Interactive Oracle Proof of Proximity) introduced in [BSBHR18](https://drops.dagstuhl.de/opus/volltexte/2018/9018/pdf/LIPIcs-ICALP-2018-14.pdf) is a univariate polynomial commitment scheme that asserts with high probability that a committed polynomial is within some specified degree bound.
The protocol is a folding scheme and composed of two phases: a commitment phase, and a query phase. In the commitment phase, the prover first commits to a Merkle tree of polynomial evaluations over some domain. They then proceed in a logarithmic number of rounds to generate new evaluation commitments for each round, where the size of the domain and polynomial degree is successively reduced by a power of two (a procedure referred to as folding).
In the subsequent query phase, the verifier draws a random index, and requests that the prover provide the evaluations at each round corresponding to that index, along with their authentication paths. The verifier then uses this subset of evaluations to confirm that the prover executed the folding procedure correctly.
The verifier has runtime that is logarithmic in the size of the evaluation domain, and the query procedure can be repeated an arbitrary number of times to increase soundness to a desired level.

## Circuit usage

To use the circuit you'll need to implement the `HasherChip<F: FieldExt>` and `RandomCoinChip<F: FieldExt, H: HasherChip<F>>` traits for a specific hasher and random coin.

An example instantiation is shown below:

```rust
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
```

Note that the circuit shape is fixed by the domain size (`log_degree`), folding factor, and the maximum remainder degree (which determines at which layer to stop folding). New proving keys will need to be generated whenever these parameters are changed.
The layer commitments, queries, and remainder are provided as witnesses to the circuit, and the public coin seed determines the initial state of the random coin.

## Testing

To check that a representative circuit is satisfied, you can run the following test.
This will prove the verification of a FRI proof generated over the BN254 scalar field:

`cargo test test_mock_verify_winter --profile=release-with-debug`

### Winterfell FRI support

The library supports parsing of Winterfell FRI proofs, helpful for testing the correctness of the circuit.
To generate a FRI proof, you can call the following:

```rust
let mut channel = winter::DefaultProverChannel::<BaseElement, BaseElement, HashFn>::new(
    domain_size,
    num_queries,
);
let (proof, positions) = winter::build_fri_proof(
    evaluations,
    &mut channel,
    WinterFriOptions::new(blowup_factor, folding_factor, max_remainder_degree),
);
```

To extract the layer commitments, queries, and remainder from a Winterfell FRI proof, you can call the following:
```rust
let (layer_commitments, queries, remainder) = winter::extract_witness::<2, HashFn>(proof, channel, positions, domain_size)
```

## Roadmap
- **Merkle caps**: Instead of authenticating Merkle proofs for queried evaluations up to the root of a layer commitment, authentication can be stopped prematurely, and the derived hash can be compared with one in a *set* of roots that are provided for each layer at a greater depth in the tree -- the Merkle "caps." This optimization is present in the Plonky2 FRI implementation.
- **Larger folding factors**: The current chip is implemented only for a folding factor of 2. Usage of larger folding factors may reduce the total proving cost.
- **Goldilocks field extension**: Performance will benefit greatly from verifying FRI proofs constructed over the Goldilocks field. This will require implementing the Poseidon (or other) hash function that can support this field.
- **Benchmarks**: Proving time should be compared for various fields, folding factors, remainder sizes, and domain sizes.
