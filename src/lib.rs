#![feature(int_log)]
#![feature(array_chunks)]

use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        range::{RangeConfig, RangeStrategy},
        GateInstructions, RangeInstructions,
    },
    poseidon::PoseidonChip,
    AssignedValue, Context, ContextParams,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::{
    arithmetic::{best_fft, FieldExt},
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::*,
};
use log::debug;
use std::marker::PhantomData;

#[cfg(test)]
mod tests;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

fn get_root_of_unity<F: FieldExt, const TWO_ADICITY: usize>(n: usize) -> F {
    let r = F::root_of_unity();
    let s = 1u64 << TWO_ADICITY - n;
    r.pow_vartime(&[s])
}

// FRI PROTOCOL INPUTS
// =========================================================================

#[derive(Clone)]
pub struct FriQueryWitness<F: FieldExt> {
    pub position: usize,
    pub layers: Vec<FriQueryLayerWitness<F>>,
}

#[derive(Clone)]
pub struct FriQueryLayerWitness<F: FieldExt> {
    pub evaluations: Vec<F>,
    pub merkle_proof: Vec<[u8; 32]>,
}

#[derive(Clone, Copy, Default)]
struct FriOptions {
    pub folding_factor: usize,
    pub max_remainder_degree: usize,
    pub log_degree: usize,
}

// FRI PROTOCOL ASSIGNMENTS
// =========================================================================

struct FriProofAssigned<F: FieldExt, H: HasherChip<F>> {
    pub layer_commitments: Vec<H::Digest>,
    pub queries: Vec<FriQueryAssigned<F, H>>,
    pub remainders: Vec<AssignedValue<F>>,
    pub remainders_poly: Vec<AssignedValue<F>>,
    pub options: FriOptions,
}

struct FriQueryAssigned<F: FieldExt, H: HasherChip<F>> {
    pub position: AssignedValue<F>,
    pub layers: Vec<FriQueryLayerAssigned<F, H>>,
}

struct FriQueryLayerAssigned<F: FieldExt, H: HasherChip<F>> {
    pub evaluations: Vec<AssignedValue<F>>,
    pub merkle_proof: Vec<H::Digest>,
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
    fn to_assigned(&self) -> Vec<AssignedValue<F>>;
}

#[derive(Clone)]
struct Digest<F: FieldExt, const N: usize>([AssignedValue<F>; N]);

impl<F: FieldExt, const N: usize> HasherChipDigest<F> for Digest<F, N> {
    fn from_assigned(values: Vec<AssignedValue<F>>) -> Self {
        Self(values.try_into().unwrap())
    }
    fn to_assigned(&self) -> Vec<AssignedValue<F>> {
        self.0.to_vec()
    }
}

#[derive(Clone)]
struct PoseidonChipBn254_8_58<F: FieldExt>(PoseidonChip<F, FlexGateConfig<F>, 4, 3>);

// TODO: Implement Goldilocks-friendly Poseidon implementation
impl<F: FieldExt> HasherChip<F> for PoseidonChipBn254_8_58<F> {
    type Digest = Digest<F, 1>;

    fn new(ctx: &mut Context<F>, flex_gate: &FlexGateConfig<F>) -> Self {
        Self(PoseidonChip::<F, FlexGateConfig<F>, 4, 3>::new(ctx, flex_gate, 8, 58).unwrap())
    }

    fn hash(
        &mut self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        values: &[AssignedValue<F>],
    ) -> Result<Self::Digest, Error> {
        self.0.update(values);
        let value = self.0.squeeze(ctx, main_chip)?;
        self.0.clear();
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

#[derive(Clone)]
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
        let mut contents = self.seed.to_assigned();
        contents.append(&mut commitment.to_assigned());
        self.seed = hasher_chip.hash(ctx, main_chip, &contents)?;
        self.counter = main_chip.mul(ctx, &Constant(F::zero()), &Existing(&self.counter))?;

        // Reproduce alpha
        contents = self.seed.to_assigned();
        self.counter = main_chip.add(ctx, &Constant(F::one()), &Existing(&self.counter))?;
        contents.push(self.counter.clone());
        hasher_chip.hash(ctx, main_chip, &contents)
    }
}

// MERKLE TREE CHIP
// =========================================================================

struct MerkleTreeChip<F: FieldExt, H: HasherChip<F>> {
    _marker: PhantomData<(F, H)>,
}

impl<F: FieldExt, H: HasherChip<F>> MerkleTreeChip<F, H> {
    fn get_root(
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        hasher_chip: &mut H,
        leaves: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error> {
        let depth = leaves.len().ilog2();
        let mut nodes = leaves.to_vec();
        for _ in 0..depth {
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    hasher_chip
                        .hash(ctx, main_chip, pair)
                        .unwrap()
                        .to_assigned()[0]
                        .clone()
                })
                .collect::<Vec<_>>();
        }
        Ok(nodes[0].clone())
    }

    fn verify_merkle_proof(
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        hasher_chip: &mut H,
        root: &H::Digest,
        index_bits: &[AssignedValue<F>],
        leaves: &[AssignedValue<F>],
        proof: &[H::Digest],
    ) -> Result<(), Error> {
        // Hash leaves to a single digest
        let mut digest = hasher_chip.hash(ctx, main_chip, leaves)?;
        for (bit, sibling) in index_bits.iter().zip(proof.iter().skip(1)) {
            let mut values = vec![];
            let a = main_chip.select(
                ctx,
                &Existing(&sibling.to_assigned()[0]),
                &Existing(&digest.to_assigned()[0]),
                &Existing(&bit),
            )?;
            let b = main_chip.select(
                ctx,
                &Existing(&digest.to_assigned()[0]),
                &Existing(&sibling.to_assigned()[0]),
                &Existing(&bit),
            )?;
            values.push(a);
            values.push(b);
            digest = hasher_chip.hash(ctx, main_chip, &values)?;
        }

        for (e1, e2) in root.to_assigned().iter().zip(digest.to_assigned().iter()) {
            ctx.region.constrain_equal(e1.cell(), e2.cell())?;
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
    config: VerifierChipConfig<F>,
    proof: FriProofAssigned<F, H>,
    _marker: PhantomData<C>,
}

impl<F, H, C> VerifierChip<F, H, C>
where
    F: FieldExt,
    H: HasherChip<F>,
    C: RandomCoinChip<F, H>,
{
    fn new(config: VerifierChipConfig<F>, proof: FriProofAssigned<F, H>) -> Result<Self, Error> {
        Ok(Self {
            config,
            proof,
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
                &[NUM_ADVICE_GATE],
                1,
                "default".to_string(),
            ),
            range_chip: RangeConfig::configure(
                meta,
                RangeStrategy::PlonkPlus,
                &[NUM_ADVICE_RANGE],
                &[1],
                1,
                3,
                "default".to_string(),
            ),
        }
    }

    fn gate(&self) -> &FlexGateConfig<F> {
        &self.config.main_chip
    }

    fn range(&self) -> &RangeConfig<F> {
        &self.config.range_chip
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
        hasher_chip: &mut H,
        public_coin_seed: H::Digest,
    ) -> Result<(), Error> {
        let log_degree = self.proof.options.log_degree;
        let folding_factor = self.proof.options.folding_factor;
        let layer_commitments = &self.proof.layer_commitments;

        // Use the public coin to generate alphas from the layer commitments
        let alphas = self.draw_alphas(
            ctx,
            hasher_chip,
            public_coin_seed,
            &self.proof.layer_commitments,
        )?;

        // Execute the FRI verification protocol for each query round
        // NOTE: this is hardcoded for a folding factor of 2 right now.
        for n in 0..self.num_queries() {
            let position_bits =
                self.range()
                    .num_to_bits(ctx, &self.proof.queries[n].position, 28)?;

            // Compute the field element coordinate at the queried position
            // g: domain offset
            // omega: domain generator
            // x: omega^position * g
            let g = F::multiplicative_generator();
            let omega = get_root_of_unity::<F, 28>(log_degree);
            let mut omega_i = self.pow_bits(ctx, omega, &position_bits)?;

            // Compute the folded roots of unity:
            // omega_folded: {omega^|D_i|} where D_i is the folded domain
            let omega_folded = (1..folding_factor)
                .map(|i| {
                    let new_domain_size = 2usize.pow(log_degree as u32) / folding_factor * i;
                    omega.pow_vartime([new_domain_size as u64])
                })
                .collect::<Vec<_>>();

            let mut previous_eval: Option<AssignedValue<F>> = None;

            for i in 0..self.num_layers() - 1 {
                let x = self.gate().mul(ctx, &Constant(g), &Existing(&omega_i))?;

                // Swap the evaluation points if the folded point is in the second half of the domain
                let evaluations_raw = self.proof.queries[n].layers[i].evaluations.clone();
                let swap_bit = position_bits[log_degree - i - 1].clone();
                let a = self.gate().select(
                    ctx,
                    &Existing(&evaluations_raw[0]),
                    &Existing(&evaluations_raw[1]),
                    &Existing(&swap_bit),
                )?;
                let b = self.gate().select(
                    ctx,
                    &Existing(&evaluations_raw[1]),
                    &Existing(&evaluations_raw[0]),
                    &Existing(&swap_bit),
                )?;
                let evaluations = vec![a, b];

                // Verify that evaluations reside at the folded position in the Merkle tree
                MerkleTreeChip::<F, H>::verify_merkle_proof(
                    ctx,
                    self.gate(),
                    hasher_chip,
                    &layer_commitments[i],
                    &position_bits,
                    &evaluations_raw,
                    &self.proof.queries[n].layers[i].merkle_proof,
                )?;

                // Compare previous polynomial evaluation and current layer evaluation
                if let Some(eval) = previous_eval {
                    ctx.region
                        .constrain_equal(eval.cell(), evaluations[1].cell())?;
                }

                // Compute the remaining x-coordinates for the given layer
                let x_folded = (0..folding_factor - 1)
                    .map(|i| {
                        self.gate()
                            .mul(ctx, &Existing(&x), &Constant(omega_folded[i]))
                            .unwrap()
                    })
                    .collect::<Vec<_>>();

                // Interpolate the evaluations at the x-coordinates, and evaluate at alpha.
                // Use this value to compare with subsequent layer evaluations
                previous_eval =
                    Some(self.evaluate_polynomial(ctx, &x, &x_folded, &evaluations, &alphas[i])?);

                // Update variables for the next layer
                omega_i = self
                    .gate()
                    .mul(ctx, &Existing(&omega_i), &Existing(&omega_i))?;
            }

            // Check that the claimed remainder is equal to the final evaluation.
            // 1. Compute the remainder index
            let mut index = self.gate().load_zero(ctx)?;
            for i in 0..self.proof.options.max_remainder_degree.ilog2() {
                index = self.gate().mul_add(
                    ctx,
                    &Existing(&position_bits[i as usize]),
                    &Constant(F::from(2usize.pow(i) as u64)),
                    &Existing(&index),
                )?;
            }
            let indicator = self.gate().idx_to_indicator(
                ctx,
                &Existing(&index),
                self.proof.options.max_remainder_degree,
            )?;
            // 2. Select the remainder at the computed index
            let remainder = self
                .gate()
                .inner_product(
                    ctx,
                    &indicator.iter().map(|x| Existing(x)).collect::<Vec<_>>(),
                    &self
                        .proof
                        .remainders
                        .iter()
                        .map(|x| Existing(x))
                        .collect::<Vec<_>>(),
                )?
                .2;
            ctx.region
                .constrain_equal(previous_eval.unwrap().cell(), remainder.cell())?;
        }

        // Check that a Merkle tree of the claimed remainders hash to the final layer commitment
        // NOTE: This is hardcoded for a folding factor of 2
        let remainder_commitment =
            self.proof.layer_commitments.last().unwrap().to_assigned()[0].clone();
        let remainder_digests = self.proof.remainders
            [..self.proof.options.max_remainder_degree / 2]
            .iter()
            .cloned()
            .zip(
                self.proof.remainders[self.proof.options.max_remainder_degree / 2..]
                    .iter()
                    .cloned(),
            )
            .map(|values| {
                let digest = hasher_chip
                    .hash(ctx, self.gate(), &[values.0, values.1])
                    .unwrap();
                digest.to_assigned()[0].clone()
            })
            .collect::<Vec<_>>();
        let root =
            MerkleTreeChip::<F, H>::get_root(ctx, self.gate(), hasher_chip, &remainder_digests)?;
        ctx.region
            .constrain_equal(root.cell(), remainder_commitment.cell())?;

        // Ensure that the interpolated remainder polynomial is of degree <= max_remainder_degree
        self.verify_remainder_degree(
            ctx,
            hasher_chip,
            &self.proof.remainders,
            &self.proof.remainders_poly,
            self.proof.options.max_remainder_degree,
        )?;

        Ok(())
    }

    /// Reconstruct the alphas used at each step of the FRI commit phase using the
    /// Merkle commitments for the layers.
    fn draw_alphas(
        &self,
        ctx: &mut Context<'_, F>,
        hasher_chip: &mut H,
        initial_seed: H::Digest,
        commitments: &[H::Digest],
    ) -> Result<Vec<H::Digest>, Error> {
        let counter = self.gate().load_zero(ctx)?;
        let mut public_coin_chip = C::new(initial_seed, counter);
        let mut alphas = vec![];
        for commitment in commitments {
            let alpha = public_coin_chip.draw_alpha(ctx, self.gate(), hasher_chip, commitment)?;
            alphas.push(alpha);
        }
        Ok(alphas)
    }

    /// Use Lagrange interpolation to evaluate the polynomial defined by the evaluations
    /// at the randomly-chosen alpha.
    fn evaluate_polynomial(
        &self,
        ctx: &mut Context<'_, F>,
        x: &AssignedValue<F>,
        _x_folded: &[AssignedValue<F>],
        evaluations: &[AssignedValue<F>],
        alpha: &H::Digest,
    ) -> Result<AssignedValue<F>, Error> {
        let alpha = alpha.to_assigned();
        assert_eq!(
            alpha.len(),
            1,
            "Field extension multiplication is not yet supported"
        );
        match self.proof.options.folding_factor {
            2 => {
                let main_chip = self.gate();
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
    fn verify_remainder_degree(
        &self,
        ctx: &mut Context<'_, F>,
        hasher_chip: &mut H,
        remainder_evaluations: &[AssignedValue<F>],
        remainder_polynomial: &[AssignedValue<F>],
        max_degree: usize,
    ) -> Result<(), Error> {
        // Use the commitment to the remainder polynomial and evaluations to draw a random
        // field element tau
        // TODO: Should we use the multi-phase constraint system to draw the randomness
        // instead here? Is it cheaper?
        let mut contents = remainder_polynomial.to_vec();
        contents.push(self.proof.layer_commitments.last().unwrap().to_assigned()[0].clone());
        let tau = hasher_chip.hash(ctx, self.gate(), &contents)?.to_assigned()[0].clone();

        // Evaluate both polynomial representations at tau and confirm agreement
        let a = self.horner_eval(ctx, remainder_polynomial, &tau)?;
        let b = self.lagrange_eval(ctx, remainder_evaluations, &tau)?;
        ctx.region.constrain_equal(a.cell(), b.cell())?;

        // Check that all polynomial coefficients greater than 'max_degree' are zero
        let zero = self.gate().load_zero(ctx)?;
        for value in remainder_polynomial.iter().skip(max_degree) {
            ctx.region.constrain_equal(value.cell(), zero.cell())?;
        }

        Ok(())
    }

    /// Evaluate a polynomial in coefficient form at a given point using Horner's method.
    fn horner_eval(
        &self,
        ctx: &mut Context<'_, F>,
        coefficients: &[AssignedValue<F>],
        x: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        Ok(coefficients.iter().rev().skip(1).fold(
            coefficients.last().unwrap().clone(),
            |prod, coeff| {
                self.gate()
                    .mul_add(ctx, &Existing(&x), &Existing(&prod), &Existing(&coeff))
                    .unwrap()
            },
        ))
    }

    /// Evaluate a polynomial in evaluation form at a given point using Lagrange interpolation.
    fn lagrange_eval(
        &self,
        ctx: &mut Context<'_, F>,
        evaluations: &[AssignedValue<F>],
        x: &AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let n = evaluations.len();

        // Roots of unity (w_i) for remainder evaluation domain
        let k = n.ilog2();
        let omega_n = get_root_of_unity::<F, 28>(k as usize);
        let omega_i = (0..n)
            .map(|i| {
                let mut x = [0u64; 4];
                x[0] = i as u64;
                omega_n.pow(&x)
            })
            .collect::<Vec<_>>();

        // Numerator: num_j = \prod_{k \neq j} x - w_k
        let x_minus_xk = (0..n)
            .map(|i| {
                self.gate()
                    .sub(ctx, &Existing(x), &Constant(omega_i[i]))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let numer = (0..n)
            .map(|i| {
                (0..n)
                    .filter(|j| i != *j)
                    .fold(None, |acc, j| {
                        if let Some(prod) = acc {
                            self.gate()
                                .mul(ctx, &Existing(&x_minus_xk[j]), &Existing(&prod))
                                .ok()
                        } else {
                            Some(x_minus_xk[j].clone())
                        }
                    })
                    .unwrap()
            })
            .collect::<Vec<_>>();

        // Denominator: den_j = \prod_{k \neq j} w_j - w_k
        let denom = (0..n)
            .map(|j| {
                (0..n)
                    .filter(|k| *k != j)
                    .fold(None, |acc, k| {
                        if let Some(prod) = acc {
                            Some((omega_i[j] - omega_i[k]) * prod)
                        } else {
                            Some(omega_i[j] - omega_i[k])
                        }
                    })
                    .unwrap()
            })
            .collect::<Vec<_>>();

        // Lagrange bases: l_j(x) = num_j / den_j
        let l_j = (0..n)
            .map(|j| {
                self.gate()
                    .mul(
                        ctx,
                        &Existing(&numer[j]),
                        &Constant(denom[j].invert().unwrap()),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();

        // Polynomial evaluation: \sum_j evaluations_j * l_j
        Ok(self
            .gate()
            .inner_product(
                ctx,
                &evaluations.iter().map(Existing).collect::<Vec<_>>(),
                &l_j.iter().map(Existing).collect::<Vec<_>>(),
            )?
            .2)
    }

    /// Compute \prod_{i \neq 0} bits_i * base^i
    fn pow_bits(
        &self,
        ctx: &mut Context<'_, F>,
        base: F,
        bits: &Vec<AssignedValue<F>>,
    ) -> Result<AssignedValue<F>, Error> {
        let mut product =
            self.gate()
                .assign_region(ctx, vec![Constant(F::from(1))], vec![], None)?[0]
                .clone();
        for (i, bit) in bits.iter().enumerate() {
            let a = self.gate().mul(
                ctx,
                &Existing(bit),
                &Constant(F::from(base.pow_vartime(&[1 << i]))),
            )?;
            let is_zero = self.range().is_zero(ctx, &a)?;
            let b =
                self.gate()
                    .select(ctx, &Constant(F::one()), &Existing(&a), &Existing(&is_zero))?;
            product = self.gate().mul(ctx, &Existing(&product), &Existing(&b))?;
        }
        Ok(product)
    }
}

// CIRCUIT
// =========================================================================

const NUM_ADVICE_GATE: usize = 60;
const NUM_ADVICE_RANGE: usize = 40;

#[derive(Clone)]
struct FriVerifierCircuit<F: FieldExt, H: HasherChip<F>, C: RandomCoinChip<F, H>> {
    pub layer_commitments: Vec<[u8; 32]>,
    pub queries: Vec<FriQueryWitness<F>>,
    pub remainder: Vec<F>,
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
            layer_commitments: vec![],
            queries: vec![],
            remainder: vec![],
            options: FriOptions::default(),
            public_coin_seed: F::default(),
            _marker: PhantomData,
        }
    }
}

impl<F, H, C> Circuit<F> for FriVerifierCircuit<F, H, C>
where
    F: FieldExt,
    H: HasherChip<F, Digest = Digest<F, 1>>,
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

    // TODO: Refactor: implement 'assign' traits for FRI input types
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let using_simple_floor_planner = true;
        let mut first_pass = true;

        layouter.assign_region(
            || "gate",
            |region| {
                if first_pass && using_simple_floor_planner {
                    first_pass = false;
                    return Ok(());
                }

                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![(
                            "default".to_string(),
                            NUM_ADVICE_GATE + NUM_ADVICE_RANGE,
                        )],
                    },
                );

                // Remainder polynomial
                let k = self.remainder.len().ilog2();
                let omega_inv = get_root_of_unity::<F, 28>(k as usize).invert().unwrap();
                let mut remainders_poly = self.remainder.clone();
                best_fft(&mut remainders_poly, omega_inv, k);
                let n_inv = F::from(remainders_poly.len() as u64).invert().unwrap();
                for coeff in remainders_poly.iter_mut() {
                    *coeff = *coeff * n_inv;
                }

                // Assign witness cells
                let remainders = config.main_chip.assign_region(
                    &mut ctx,
                    self.remainder
                        .iter()
                        .map(|r| Witness(Value::known(*r)))
                        .collect::<Vec<_>>(),
                    vec![],
                    None,
                )?;
                let remainders_poly = config.main_chip.assign_region(
                    &mut ctx,
                    remainders_poly
                        .iter()
                        .map(|r| Witness(Value::known(*r)))
                        .collect::<Vec<_>>(),
                    vec![],
                    None,
                )?;
                let layer_commitments =
                    assign_digests::<F, H>(&mut ctx, &config.main_chip, &self.layer_commitments)?;
                let positions = config.main_chip.assign_region(
                    &mut ctx,
                    self.queries
                        .iter()
                        .map(|q| Witness(Value::known(F::from(q.position as u64))))
                        .collect::<Vec<_>>(),
                    vec![],
                    None,
                )?;
                let mut queries = vec![];
                for (n, query) in self.queries.iter().enumerate() {
                    let mut layers = vec![];
                    for layer in query.layers.iter() {
                        let evaluations = config.main_chip.assign_region(
                            &mut ctx,
                            layer
                                .evaluations
                                .iter()
                                .map(|x| Witness(Value::known(*x)))
                                .collect(),
                            vec![],
                            None,
                        )?;
                        let merkle_proof = assign_digests::<F, H>(
                            &mut ctx,
                            &config.main_chip,
                            &layer.merkle_proof,
                        )?;
                        layers.push(FriQueryLayerAssigned {
                            evaluations,
                            merkle_proof,
                        });
                    }
                    queries.push(FriQueryAssigned {
                        position: positions[n].clone(),
                        layers,
                    });
                }
                let public_coin_seed = config.main_chip.assign_region(
                    &mut ctx,
                    vec![Constant(self.public_coin_seed)],
                    vec![],
                    None,
                )?[0]
                    .clone();

                // Initialize chips
                let mut hasher_chip = H::new(&mut ctx, &config.main_chip);
                let verifier_chip = VerifierChip::<F, H, C>::new(
                    config.clone(),
                    FriProofAssigned {
                        layer_commitments,
                        queries,
                        remainders,
                        remainders_poly,
                        options: self.options,
                    },
                )?;

                verifier_chip.verify_proof(
                    &mut ctx,
                    &mut hasher_chip,
                    H::Digest::from_assigned(vec![public_coin_seed]),
                )?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

fn assign_digests<F: FieldExt, H: HasherChip<F, Digest = Digest<F, 1>>>(
    ctx: &mut Context<'_, F>,
    main_chip: &FlexGateConfig<F>,
    values: &[[u8; 32]],
) -> Result<Vec<H::Digest>, Error> {
    Ok(main_chip
        .assign_region(
            ctx,
            values
                .iter()
                .map(|digest| Witness(Value::known(from_byte_array(digest))))
                .collect::<Vec<_>>(),
            vec![],
            None,
        )?
        .into_iter()
        .map(|x| Digest::from_assigned(vec![x]))
        .collect::<Vec<_>>())
}

fn from_byte_array<F: FieldExt>(input: &[u8; 32]) -> F {
    let mut bytes = F::Repr::default();
    for (v, b) in bytes.as_mut().iter_mut().zip(input.iter()) {
        *v = *b;
    }
    F::from_repr(bytes).unwrap()
}
