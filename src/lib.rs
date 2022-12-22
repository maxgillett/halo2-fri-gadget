use std::marker::PhantomData;

use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        range::{RangeConfig, RangeStrategy},
        GateInstructions, RangeInstructions,
    },
    poseidon::PoseidonChip,
    AssignedValue, Context, ContextParams,
    QuantumCell::{Constant, Existing},
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::*,
};

fn get_root_of_unity<F: FieldExt, const TWO_ADICITY: usize>(n: usize) -> F {
    let r = F::root_of_unity();
    let s = 1u64 << TWO_ADICITY - n;
    r.pow_vartime(&[s])
}

// FRI PROTOCOL PARAMS
// =========================================================================

struct FriProof<F: FieldExt, H: HasherChip<F>> {
    pub layer_commitments: Vec<H::Digest>,
    pub queries: Vec<FriQuery<F, H>>,
    pub options: FriOptions,
}

struct FriQuery<F: FieldExt, H: HasherChip<F>> {
    pub position: AssignedValue<F>,
    pub layers: Vec<FriQueryLayer<F, H>>,
}

struct FriQueryLayer<F: FieldExt, H: HasherChip<F>> {
    pub evaluations: Vec<AssignedValue<F>>,
    pub merkle_proof: Vec<H::Digest>,
}

#[derive(Clone, Copy, Default)]
struct FriOptions {
    pub folding_factor: usize,
    pub max_remainder_degree: usize,
    pub log_degree: usize,
}

// HASHER CHIP
// =========================================================================

trait HasherChip<F: FieldExt> {
    type Digest: HasherChipDigest<F>;

    fn new(ctx: &mut Context<F>, main_gate: &FlexGateConfig<F>) -> Self;
    fn hash(
        &mut self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        values: &[AssignedValue<F>],
    ) -> Result<Self::Digest, Error>;
}

trait HasherChipDigest<F: FieldExt>: Clone {
    fn from_assigned(values: Vec<AssignedValue<F>>) -> Self;
    fn to_vec(&self) -> Vec<AssignedValue<F>>;
}

#[derive(Clone)]
struct Digest<F: FieldExt, const N: usize>([AssignedValue<F>; N]);

impl<F: FieldExt, const N: usize> HasherChipDigest<F> for Digest<F, N> {
    fn from_assigned(values: Vec<AssignedValue<F>>) -> Self {
        Self(values.try_into().unwrap())
    }
    fn to_vec(&self) -> Vec<AssignedValue<F>> {
        self.0.to_vec()
    }
}

struct PoseidonChipBn254_8_120<F: FieldExt>(PoseidonChip<F, FlexGateConfig<F>, 2, 1020>);

// TODO: Implement Goldilocks-friendly Poseidon implementation
impl<F: FieldExt> HasherChip<F> for PoseidonChipBn254_8_120<F> {
    type Digest = Digest<F, 1>;

    fn new(ctx: &mut Context<F>, flex_gate: &FlexGateConfig<F>) -> Self {
        Self(PoseidonChip::<F, FlexGateConfig<F>, 2, 1020>::new(ctx, flex_gate, 8, 120).unwrap())
    }

    fn hash(
        &mut self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        values: &[AssignedValue<F>],
    ) -> Result<Self::Digest, Error> {
        self.0.update(values);
        let value = self.0.squeeze(ctx, main_chip)?;
        Ok(Digest([value; 1]))
    }
}

// RANDOM COIN CHIP
// =========================================================================

trait RandomCoinChip<F: FieldExt, H: HasherChip<F>> {
    fn new(seed: H::Digest, counter: AssignedValue<F>) -> Self;

    fn draw_alpha(
        &mut self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        hasher_chip: &mut H,
        commitment: &H::Digest,
    ) -> Result<H::Digest, Error>;
}

struct RandomCoin<F: FieldExt, H: HasherChip<F>> {
    pub seed: H::Digest,
    pub counter: AssignedValue<F>,
    _marker: PhantomData<H>,
}

impl<F: FieldExt, H: HasherChip<F>> RandomCoinChip<F, H> for RandomCoin<F, H> {
    fn new(seed: H::Digest, counter: AssignedValue<F>) -> Self {
        Self {
            seed,
            counter,
            _marker: PhantomData,
        }
    }

    fn draw_alpha(
        &mut self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        hasher_chip: &mut H,
        commitment: &H::Digest,
    ) -> Result<H::Digest, Error> {
        // Reseed
        let mut contents = self.seed.to_vec();
        contents.append(&mut commitment.to_vec());
        self.seed = hasher_chip.hash(ctx, main_chip, &contents)?;

        // Reproduce alpha
        contents = self.seed.to_vec();
        contents.push(self.counter.clone());
        hasher_chip.hash(ctx, main_chip, &contents)
    }
}

// MERKLE TREE CHIP
// =========================================================================

struct MerkleTreeChip<F: FieldExt, H: HasherChip<F>> {
    _marker: PhantomData<(F, H)>,
}

#[allow(dead_code, unused)]
impl<F: FieldExt, H: HasherChip<F>> MerkleTreeChip<F, H> {
    fn new(ctx: &mut Context<F>, chip: &FlexGateConfig<F>) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    fn verify_merkle_proof(
        &self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        range_chip: &RangeConfig<F>,
        root: &H::Digest,
        index_bits: &[AssignedValue<F>],
        leaves: &[AssignedValue<F>],
        proof: &[H::Digest],
    ) -> Result<(), Error> {
        let mut hasher = H::new(ctx, main_chip);

        // Hash leaves to a single digest
        let mut digest = hasher.hash(ctx, main_chip, leaves)?;
        for (bit, sibling) in index_bits.iter().zip(proof) {
            // TODO: Swap digest and sibling depending on bit
            let mut values = vec![];
            values.append(&mut digest.to_vec());
            values.append(&mut sibling.to_vec());
            digest = hasher.hash(ctx, main_chip, &values)?;
        }

        for (e1, e2) in root.to_vec().iter().zip(digest.to_vec().iter()) {
            range_chip.is_equal(ctx, &Existing(e1), &Existing(e2));
        }

        Ok(())
    }
}

// FRI VERIFIER CHIP
// =========================================================================

#[derive(Clone)]
struct VerifierChipConfig<F: FieldExt> {
    pub instance: Column<Instance>,
    pub main_chip: FlexGateConfig<F>,
    pub range_chip: RangeConfig<F>,
}

struct VerifierChip<F: FieldExt, H: HasherChip<F>, C: RandomCoinChip<F, H>> {
    proof: FriProof<F, H>,
    _marker: PhantomData<C>,
}

impl<F, H, C> VerifierChip<F, H, C>
where
    F: FieldExt,
    H: HasherChip<F>,
    C: RandomCoinChip<F, H>,
{
    fn new(
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        options: FriOptions,
    ) -> Result<Self, Error> {
        Ok(Self {
            // TODO: Create FriProof from params
            proof: FriProof {
                layer_commitments: vec![],
                queries: vec![],
                options,
            },
            _marker: PhantomData,
        })
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        instance: Column<Instance>,
    ) -> VerifierChipConfig<F> {
        VerifierChipConfig {
            instance,
            main_chip: FlexGateConfig::configure(
                meta,
                GateStrategy::PlonkPlus,
                &[NUM_ADVICE],
                1,
                "default".to_string(),
            ),
            range_chip: RangeConfig::configure(
                meta,
                RangeStrategy::PlonkPlus,
                &[NUM_ADVICE],
                &[1],
                1,
                3,
                "default".to_string(),
            ),
        }
    }

    fn num_queries(&self) -> usize {
        self.proof.queries.len()
    }

    fn num_layers(&self) -> usize {
        self.proof.layer_commitments.len()
    }

    fn verify_proof(
        &self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        range_chip: &RangeConfig<F>,
        hasher_chip: &mut H,
        public_coin_seed: H::Digest,
    ) -> Result<(), Error> {
        let log_degree = self.proof.options.log_degree;
        let folding_factor = self.proof.options.folding_factor;
        let layer_commitments = &self.proof.layer_commitments;

        // Use the public coin to generate alphas from the layer commitments
        let alphas = self.draw_alphas(
            ctx,
            main_chip,
            hasher_chip,
            public_coin_seed,
            &self.proof.layer_commitments,
        )?;

        // Initialize the Merkle tree chip
        let mut merkle_chip = MerkleTreeChip::<F, H>::new(ctx, main_chip);

        // Determine domain bit size for each layer
        let folded_domain_bits = (0..self.num_layers())
            .map(|x| log_degree / folding_factor.pow(x as u32))
            .collect::<Vec<_>>();

        // Execute the FRI verification protocol for each query round
        for n in 0..self.num_queries() {
            let mut position_bits = range_chip.num_to_bits(
                ctx,
                &self.proof.queries[n].position,
                F::NUM_BITS as usize,
            )?;

            // Compute the field element at the queried position
            let g = F::multiplicative_generator();
            let omega = get_root_of_unity::<F, 32>(log_degree);
            let omega_i =
                main_chip.pow_bits(ctx, omega, &position_bits.iter().map(Existing).collect())?;
            let mut x = main_chip.mul(ctx, &Constant(g), &Existing(&omega_i))?;

            // Compute the folded roots of unity
            let omega_folded = (1..folding_factor)
                .map(|i| {
                    let new_domain_size = 2usize.pow(log_degree as u32) / folding_factor * i;
                    main_chip
                        .pow(ctx, &Existing(&omega_i), new_domain_size)
                        .unwrap()
                })
                .collect::<Vec<_>>();

            let mut previous_eval = None;

            for i in 0..self.num_layers() {
                let evaluations = self.proof.queries[n].layers[i].evaluations.clone();

                // Fold position
                let folded_position_bits = position_bits[folded_domain_bits[n]..].to_vec();

                // Verify that evaluations reside at the folded position in the Merkle tree
                merkle_chip.verify_merkle_proof(
                    ctx,
                    main_chip,
                    range_chip,
                    &layer_commitments[i],
                    &folded_position_bits,
                    &evaluations,
                    &self.proof.queries[n].layers[i].merkle_proof,
                )?;

                // Compare previous polynomial evaluation and current layer evaluation
                if let Some(eval) = previous_eval {
                    // TODO: Use correct index for evaluations
                    main_chip.assert_equal(ctx, &Existing(&eval), &Existing(&evaluations[0]))?;
                }

                // Compute the remaining x-coordinates for the given layer
                let x_folded = (0..folding_factor)
                    .map(|i| {
                        main_chip
                            .mul(ctx, &Existing(&x), &Existing(&omega_folded[i]))
                            .unwrap()
                    })
                    .collect::<Vec<_>>();

                // Interpolate the evaluations at the x-coordinates, and evaluate at alpha.
                // Use this value to compare with subsequent layer evaluations
                previous_eval = Some(self.evaluate_polynomial(
                    ctx,
                    main_chip,
                    &x,
                    &x_folded,
                    &evaluations,
                    &alphas[i],
                )?);

                // Update variables for the next layer
                position_bits = folded_position_bits;
                x = main_chip.pow(ctx, &Existing(&x), folding_factor)?;
            }

            // TODO
            self.verify_remainder(ctx, vec![], self.proof.options.max_remainder_degree);
        }

        Ok(())
    }

    /// Reconstruct the alphas used at each step of the FRI commit phase using the
    /// Merkle commitments for the layers.
    #[allow(unused)]
    fn draw_alphas(
        &self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        hasher_chip: &mut H,
        initial_seed: H::Digest,
        commitments: &[H::Digest],
    ) -> Result<Vec<H::Digest>, Error> {
        let counter = main_chip.assign_region_smart(
            ctx,
            vec![Constant(F::from(0))],
            vec![],
            vec![],
            vec![],
        )?[0]
            .clone();
        let mut public_coin_chip = C::new(initial_seed, counter);
        let mut alphas = vec![];
        for commitment in commitments {
            let alpha = public_coin_chip.draw_alpha(ctx, main_chip, hasher_chip, commitment)?;
            alphas.push(alpha);
        }
        Ok(alphas)
    }

    /// Use Lagrange interpolation to evaluate the polynomial defined by the evaluations
    /// at the randomly-chosen alpha.
    fn evaluate_polynomial(
        &self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        x: &AssignedValue<F>,
        x_folded: &[AssignedValue<F>],
        evaluations: &[AssignedValue<F>],
        alpha: &H::Digest,
    ) -> Result<AssignedValue<F>, Error> {
        let alpha = alpha.to_vec();
        assert_eq!(
            alpha.len(),
            1,
            "Field extension multiplication is not yet supported"
        );
        match self.proof.options.folding_factor {
            2 => {
                let x_inv = main_chip.invert(ctx, &Existing(x))?;
                let xomega = main_chip.mul(ctx, &Existing(&alpha[0]), &Existing(&x_inv))?;
                let add = main_chip.sub(ctx, &Constant(F::one()), &Existing(&xomega))?;
                let sub = main_chip.add(ctx, &Constant(F::one()), &Existing(&xomega))?;
                let a = main_chip.mul(ctx, &Existing(&add), &Existing(&evaluations[0]))?;
                let b = main_chip.mul(ctx, &Existing(&sub), &Existing(&evaluations[1]))?;
                let prod = main_chip.add(ctx, &Existing(&a), &Existing(&b))?;
                Ok(main_chip.mul(
                    ctx,
                    &Constant(F::from(2).invert().unwrap()),
                    &Existing(&prod),
                )?)
            }
            _ => {
                // TODO: Implement for folding factor > 2
                unimplemented!()
            }
        }
    }

    /// Interpolate the remainder evaluations into a polynomial, and check that its degree
    /// is less than or equal to `max_degree`.
    #[allow(unused)]
    fn verify_remainder(
        &self,
        ctx: &mut Context<'_, F>,
        remainder_evaluations: Vec<F>,
        max_degree: usize,
    ) {
        // TODO
        unimplemented!()
    }
}

// CIRCUIT
// =========================================================================

const NUM_ADVICE: usize = 1;

struct FriVerifierCircuit<F: FieldExt, H: HasherChip<F>, C: RandomCoinChip<F, H>> {
    pub options: FriOptions,
    pub public_coin_seed: F,
    _marker: PhantomData<(C, H)>,
}

impl<F, H, C> Default for FriVerifierCircuit<F, H, C>
where
    F: FieldExt,
    H: HasherChip<F>,
    C: RandomCoinChip<F, H>,
{
    fn default() -> Self {
        Self {
            options: FriOptions::default(),
            public_coin_seed: F::default(),
            _marker: PhantomData,
        }
    }
}

impl<F, H, C> Circuit<F> for FriVerifierCircuit<F, H, C>
where
    F: FieldExt,
    H: HasherChip<F>,
    C: RandomCoinChip<F, H>,
{
    type Config = VerifierChipConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        VerifierChip::<F, H, C>::configure(meta, instance)
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

                let mut hasher_chip = H::new(&mut ctx, &config.main_chip);

                let verifier_chip = VerifierChip::<F, H, C>::new(
                    &mut ctx,
                    &config.main_chip,
                    self.options,
                    // TODO: Pass in FRI proof values
                )?;

                let public_coin_seed = config
                    .main_chip
                    .assign_region(
                        &mut ctx,
                        vec![Constant(self.public_coin_seed)],
                        vec![],
                        None,
                    )
                    .unwrap()[0]
                    .clone();

                verifier_chip.verify_proof(
                    &mut ctx,
                    &config.main_chip,
                    &config.range_chip,
                    &mut hasher_chip,
                    H::Digest::from_assigned(vec![public_coin_seed]),
                )?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

    #[test]
    fn test() {
        let options = FriOptions {
            folding_factor: 2,
            max_remainder_degree: 256,
            log_degree: 21,
        };

        // Random coin
        let public_coin_seed = Fr::from(1);

        let circuit = FriVerifierCircuit::<
            Fr,
            PoseidonChipBn254_8_120<Fr>,
            RandomCoin<Fr, PoseidonChipBn254_8_120<Fr>>,
        > {
            options,
            public_coin_seed,
            _marker: PhantomData,
        };

        //let public_input = vec![];
        let prover = MockProver::run(10, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
