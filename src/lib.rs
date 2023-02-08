#![feature(int_log)]
#![feature(array_chunks)]
#![feature(generic_associated_types)]

use goldilocks::{Extendable, FieldExtension};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions},
    AssignedValue, Context, ContextParams,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::{
    arithmetic::{best_fft, Field, FieldExt},
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::*,
};
use log::debug;
use std::marker::PhantomData;

mod fields;
use fields::{
    AssignedExtensionValue, ExtensionFieldChip, ExtensionFieldConfig,
    QuantumExtensionCell::{Constant as ConstantExt, Existing as ExistingExt},
};

mod hash;
use hash::{Digest, HasherChip, HasherChipDigest};

mod random;
use random::RandomCoinChip;

mod merkle;
use merkle::MerkleTreeChip;

#[cfg(test)]
mod tests;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

// Field extension size (TODO: this should be an associated type within ExtensionFieldChip)
const D: usize = 2;

fn get_root_of_unity<F: FieldExt, const TWO_ADICITY: usize>(n: usize) -> F {
    let r = F::root_of_unity();
    let s = 1u64 << TWO_ADICITY - n;
    r.pow_vartime(&[s])
}

// FRI PROTOCOL INPUTS
// =========================================================================

#[derive(Clone)]
pub struct FriQueryInput<F: FieldExt + Extendable<2>> {
    pub position: usize,
    pub layers: Vec<FriQueryLayerInput<F>>,
}

#[derive(Clone)]
pub struct FriQueryLayerInput<F: FieldExt + Extendable<2>> {
    pub evaluations: Vec<F::Extension>,
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

struct FriProofAssigned<'v, F: FieldExt + Extendable<2>, H: HasherChip<F>> {
    pub layer_commitments: Vec<H::Digest>,
    pub queries: Vec<FriQueryAssigned<'v, F, H>>,
    pub remainders: Vec<AssignedExtensionValue<'v, F>>,
    pub remainders_poly: Vec<AssignedExtensionValue<'v, F>>,
    pub options: FriOptions,
}

struct FriQueryAssigned<'v, F: FieldExt + Extendable<2>, H: HasherChip<F>> {
    pub position: AssignedValue<'v, F>,
    pub layers: Vec<FriQueryLayerAssigned<'v, F, H>>,
}

struct FriQueryLayerAssigned<'v, F: FieldExt + Extendable<2>, H: HasherChip<F>> {
    pub evaluations: Vec<AssignedExtensionValue<'v, F>>,
    pub merkle_proof: Vec<H::Digest>,
}

// ASSIGNMENT INSTRUCTIONS
// =========================================================================

trait AssignInput<'v, const N: usize, F, E, H>
where
    F: FieldExt + Extendable<2>,
    E: ExtensionFieldChip<D, F>,
    H: HasherChip<F, Digest = Digest<'v, F, N>>,
{
    fn assign(
        &self,
        ctx: &mut Context<'_, F>,
        config: &VerifierChipConfig<F, E>,
    ) -> Result<FriQueryAssigned<'v, F, H>, Error>;
}

impl<'v, const N: usize, F, E, H> AssignInput<'v, N, F, E, H> for FriQueryInput<F>
where
    F: FieldExt + Extendable<2>,
    E: ExtensionFieldChip<D, F, BaseField = F, Field = F::Extension>,
    H: HasherChip<F, Digest = Digest<'v, F, N>>,
{
    fn assign(
        &self,
        ctx: &mut Context<'_, F>,
        config: &VerifierChipConfig<F, E>,
    ) -> Result<FriQueryAssigned<'v, F, H>, Error> {
        let position = config
            .extension
            .gate()
            .load_witness(ctx, Value::known(F::from(self.position as u64)));
        let mut layers = vec![];
        for layer in self.layers.iter() {
            let evaluations = layer
                .evaluations
                .iter()
                .map(|x| config.extension.load_witness(ctx, *x))
                .collect();
            let merkle_proof =
                assign_digests::<N, F, H>(ctx, &config.extension.gate(), &layer.merkle_proof)?;
            layers.push(FriQueryLayerAssigned {
                evaluations,
                merkle_proof,
            });
        }
        Ok(FriQueryAssigned { position, layers })
    }
}

// FRI VERIFIER CHIP
// =========================================================================

#[derive(Clone)]
struct VerifierChipConfig<F: FieldExt + Extendable<2>, E: ExtensionFieldChip<D, F>> {
    pub instance: Column<Instance>,
    pub extension: E,
    _marker: PhantomData<F>,
}

struct VerifierChip<
    'a,
    F: FieldExt + Extendable<2>,
    E: ExtensionFieldChip<D, F>,
    H: HasherChip<F>,
    C: RandomCoinChip<F, H>,
> {
    config: VerifierChipConfig<F, E>,
    proof: FriProofAssigned<'a, F, H>,
    _marker: PhantomData<C>,
}

impl<'a, F, E, H, C> VerifierChip<'a, F, E, H, C>
where
    F: FieldExt + Extendable<2>,
    E: ExtensionFieldChip<D, F, BaseField = F, Field = F::Extension> + Clone,
    H: HasherChip<F>,
    C: RandomCoinChip<F, H>,
{
    fn new(
        config: VerifierChipConfig<F, E>,
        proof: FriProofAssigned<'a, F, H>,
    ) -> Result<Self, Error> {
        Ok(Self {
            config,
            proof,
            _marker: PhantomData,
        })
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        instance: Column<Instance>,
    ) -> VerifierChipConfig<F, E> {
        let extension_config = ExtensionFieldConfig::configure(meta, NUM_ADVICE);
        let extension = E::construct(extension_config);
        VerifierChipConfig {
            instance,
            extension,
            _marker: PhantomData,
        }
    }

    fn gate(&self) -> &FlexGateConfig<F> {
        &self.config.extension.gate()
    }

    fn range(&self) -> &RangeConfig<F> {
        &self.config.extension.range()
    }

    fn extension(&self) -> &E {
        &self.config.extension
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
        public_coin_chip: &mut C,
    ) -> Result<(), Error> {
        let log_degree = self.proof.options.log_degree;
        let folding_factor = self.proof.options.folding_factor;
        let layer_commitments = &self.proof.layer_commitments;

        // Use the public coin to generate alphas from the layer commitments
        let alphas = self.draw_alphas(
            ctx,
            hasher_chip,
            public_coin_chip,
            &self.proof.layer_commitments,
        )?;

        // Execute the FRI verification protocol for each query round
        // NOTE: this is hardcoded for a folding factor of 2 right now.
        for n in 0..self.num_queries() {
            let position_bits = self
                .gate()
                .num_to_bits(ctx, &self.proof.queries[n].position, 28);

            // Compute the field element coordinate at the queried position
            // omega : domain generator
            //     g : domain offset
            //     x : omega^position * g
            let omega = get_root_of_unity::<F, 28>(log_degree);
            let g = F::multiplicative_generator();
            let mut omega_i = self.pow_bits(ctx, omega, &position_bits)?;

            // Compute the folded roots of unity:
            // {omega^|D_i|} where D_i is the folded domain
            let omega_folded = (1..folding_factor)
                .map(|i| {
                    let new_domain_size = 2usize.pow(log_degree as u32) / folding_factor * i;
                    omega.pow_vartime([new_domain_size as u64])
                })
                .collect::<Vec<_>>();

            let mut previous_eval: Option<AssignedExtensionValue<'_, F>> = None;

            for i in 0..self.num_layers() - 1 {
                let x = self.gate().mul(ctx, Constant(g), Existing(&omega_i));

                // Swap the evaluation points if the folded point is in the second half of the domain
                let evaluations_raw = self.proof.queries[n].layers[i].evaluations.clone();
                let swap_bit = position_bits[log_degree - i - 1].clone();
                let a = self.extension().select(
                    ctx,
                    ExistingExt(&evaluations_raw[0]),
                    ExistingExt(&evaluations_raw[1]),
                    &swap_bit,
                );
                let b = self.extension().select(
                    ctx,
                    ExistingExt(&evaluations_raw[1]),
                    ExistingExt(&evaluations_raw[0]),
                    &swap_bit,
                );
                let evaluations = vec![a, b];

                // Verify that evaluations reside at the folded position in the Merkle tree
                MerkleTreeChip::<F, H>::verify_merkle_proof(
                    ctx,
                    self.gate(),
                    self.extension(),
                    hasher_chip,
                    &layer_commitments[i],
                    &position_bits,
                    &evaluations_raw,
                    &self.proof.queries[n].layers[i].merkle_proof,
                )?;

                // Compare previous polynomial evaluation and current layer evaluation
                if let Some(eval) = previous_eval {
                    for (a, b) in eval.coeffs().iter().zip(evaluations[1].coeffs()) {
                        ctx.constrain_equal(&a, &b);
                    }
                }

                // Compute the remaining x-coordinates for the given layer
                let x_folded = if folding_factor == 2 {
                    vec![]
                } else {
                    (0..folding_factor - 1)
                        .map(|i| {
                            self.gate()
                                .mul(ctx, Existing(&x), Constant(omega_folded[i]))
                        })
                        .collect::<Vec<_>>()
                };

                // Interpolate the evaluations at the x-coordinates, and evaluate at alpha.
                // Use this value to compare with subsequent layer evaluations
                previous_eval =
                    Some(self.evaluate_polynomial(ctx, &x, &x_folded, &evaluations, &alphas[i])?);

                // Update variables for the next layer
                omega_i = self.gate().mul(ctx, Existing(&omega_i), Existing(&omega_i));
            }

            // Check that the claimed remainder is equal to the final evaluation.
            // 1. Compute the remainder index
            let mut index = self.gate().load_zero(ctx);
            for i in 0..self.proof.options.max_remainder_degree.ilog2() {
                index = self.gate().mul_add(
                    ctx,
                    Existing(&position_bits[i as usize]),
                    Constant(F::from(2usize.pow(i) as u64)),
                    Existing(&index),
                );
            }
            // 2. Construct indicator vector (1 at remainder index, 0 elsewhere)
            let indicator = self.gate().idx_to_indicator(
                ctx,
                Existing(&index),
                self.proof.options.max_remainder_degree,
            );
            // 3. Select the remainder at the indicator
            let remainders = self
                .proof
                .remainders
                .iter()
                .map(ExistingExt)
                .collect::<Vec<_>>();
            let remainder = self
                .extension()
                .select_by_indicator(ctx, remainders, indicator);
            // 4. Compare the remainder to the final evaluation
            self.extension()
                .constrain_equal(ctx, &previous_eval.unwrap(), &remainder);
        }

        // Transpose the remainders and hash them to digests
        // NOTE: This is hardcoded for a folding factor of 2
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
                let mut elements = vec![];
                elements.extend(values.0.coeffs());
                elements.extend(values.1.coeffs());
                let digest = hasher_chip
                    .hash_elements(ctx, self.gate(), &elements)
                    .unwrap();
                digest
            })
            .collect::<Vec<_>>();

        // Check that a Merkle tree of the claimed remainders hash to the final layer commitment
        let root =
            MerkleTreeChip::<F, H>::get_root(ctx, self.gate(), hasher_chip, &remainder_digests)?;
        let remainder_commitment = self.proof.layer_commitments.last().unwrap();
        for (r, c) in root
            .to_assigned()
            .iter()
            .zip(remainder_commitment.to_assigned().iter())
        {
            ctx.constrain_equal(r, c);
        }

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
        public_coin_chip: &mut C,
        commitments: &[H::Digest],
    ) -> Result<Vec<H::Digest>, Error> {
        let mut counter = self.gate().load_zero(ctx);
        let mut alphas = vec![];
        for commitment in commitments {
            let alpha = public_coin_chip.draw_alpha::<E>(
                ctx,
                self.gate(),
                hasher_chip,
                commitment,
                &mut counter,
            )?;
            alphas.push(alpha);
        }
        Ok(alphas)
    }

    /// Use Lagrange interpolation to evaluate the polynomial defined by the evaluations
    /// at the randomly-chosen alpha.
    fn evaluate_polynomial<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        x: &AssignedValue<'v, F>,
        _x_folded: &[AssignedValue<'v, F>],
        evaluations: &[AssignedExtensionValue<'v, F>],
        alpha: &'v H::Digest,
    ) -> Result<AssignedExtensionValue<'v, F>, Error> {
        // Convert alpha to a field element
        let alpha_ext = AssignedExtensionValue::construct(
            alpha
                .to_assigned()
                .to_vec()
                .into_iter()
                .take(F::Extension::NUM_BASE_ELEMENTS)
                .collect::<Vec<_>>(),
        );

        match self.proof.options.folding_factor {
            2 => {
                let main_chip = self.gate();
                let extension = self.extension();
                let x_inv = main_chip.invert(ctx, Existing(x));
                let xomega = extension.mul_base(ctx, ExistingExt(&alpha_ext), Existing(&x_inv));
                let xomega_neg = extension.negate(ctx, ExistingExt(&xomega));
                let add =
                    extension.add(ctx, ExistingExt(&xomega_neg), ConstantExt(E::Field::one()));
                let sub = extension.add(ctx, ExistingExt(&xomega), ConstantExt(E::Field::one()));
                let a = extension.mul(ctx, ExistingExt(&add), ExistingExt(&evaluations[0]));
                let b = extension.mul(ctx, ExistingExt(&sub), ExistingExt(&evaluations[1]));
                let prod = extension.add(ctx, ExistingExt(&a), ExistingExt(&b));
                Ok(extension.mul(
                    ctx,
                    ExistingExt(&prod),
                    ConstantExt(E::Field::from(2).invert().unwrap()),
                ))
            }
            _ => {
                // TODO: Implement for folding factor > 2
                unimplemented!()
            }
        }
    }

    /// Interpolate the remainder evaluations into a polynomial, and check that its degree
    /// is less than or equal to `max_degree`.
    fn verify_remainder_degree<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        hasher_chip: &mut H,
        remainder_evaluations: &[AssignedExtensionValue<'v, F>],
        remainder_polynomial: &[AssignedExtensionValue<'v, F>],
        max_degree: usize,
    ) -> Result<(), Error> {
        // Use the commitment to the remainder polynomial and evaluations to draw a random
        // field element tau
        // TODO: Should we use the multi-phase constraint system to draw the randomness
        // instead here? Is it cheaper?
        let mut contents = remainder_polynomial
            .iter()
            .flat_map(|x| x.coeffs())
            .collect::<Vec<_>>();
        contents.extend(
            self.proof
                .layer_commitments
                .last()
                .unwrap()
                .to_assigned()
                .to_vec(),
        );
        let tau = hasher_chip.hash_elements(ctx, self.gate(), &contents)?;
        // TODO: Refactor this call to be less verbose... Also remove requirement to
        // call 'to_vec' after calling 'to_assigned'
        let tau = AssignedExtensionValue::construct(
            tau.to_assigned()
                .to_vec()
                .into_iter()
                .take(F::Extension::NUM_BASE_ELEMENTS)
                .collect::<Vec<_>>(),
        );

        // Evaluate both polynomial representations at tau and confirm agreement
        let a = self.horner_eval(ctx, remainder_polynomial, &tau)?;
        let b = self.lagrange_eval(ctx, remainder_evaluations, &tau)?;
        self.extension().constrain_equal(ctx, &a, &b);

        // Check that all polynomial coefficients greater than 'max_degree' are zero
        let zero = self.extension().load_constant(ctx, E::Field::zero());
        for value in remainder_polynomial.iter().skip(max_degree) {
            self.extension().constrain_equal(ctx, &value, &zero);
        }

        Ok(())
    }

    /// Evaluate a polynomial in coefficient form at a given point using Horner's method.
    fn horner_eval<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        coefficients: &'v [AssignedExtensionValue<'v, F>],
        x: &'v AssignedExtensionValue<'v, F>,
    ) -> Result<AssignedExtensionValue<'v, F>, Error> {
        Ok(coefficients.iter().rev().skip(1).fold(
            coefficients.last().unwrap().clone(),
            |prod, coeff| {
                self.extension().mul_add(
                    ctx,
                    ExistingExt(&x),
                    ExistingExt(&prod),
                    ExistingExt(&coeff),
                )
            },
        ))
    }

    /// Evaluate a polynomial in evaluation form at a given point using Lagrange interpolation.
    fn lagrange_eval<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        evaluations: &[AssignedExtensionValue<'v, F>],
        x: &AssignedExtensionValue<'v, F>,
    ) -> Result<AssignedExtensionValue<'v, F>, Error> {
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
            .map(|i| self.extension().sub_base(ctx, x, Constant(omega_i[i])))
            .collect::<Vec<_>>();
        let numer = (0..n)
            .map(|i| {
                (0..n)
                    .filter(|j| i != *j)
                    .fold(None, |acc, j| {
                        if let Some(prod) = acc {
                            Some(self.extension().mul(
                                ctx,
                                ExistingExt(&x_minus_xk[j]),
                                ExistingExt(&prod),
                            ))
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
                self.extension().mul_base(
                    ctx,
                    ExistingExt(&numer[j]),
                    Constant(denom[j].invert().unwrap()),
                )
            })
            .collect::<Vec<_>>();

        // Polynomial evaluation: \sum_j evaluations_j * l_j
        Ok(self
            .extension()
            .inner_product(ctx, evaluations.to_vec(), l_j))
    }

    /// Compute \prod_{i \neq 0} bits_i * base^i
    fn pow_bits(
        &self,
        ctx: &mut Context<'_, F>,
        base: F,
        bits: &Vec<AssignedValue<'a, F>>,
    ) -> Result<AssignedValue<'a, F>, Error> {
        let mut product = self.gate().load_constant(ctx, F::one()).clone();
        for (i, bit) in bits.iter().enumerate() {
            let a = self.gate().mul(
                ctx,
                Existing(bit),
                Constant(F::from(base.pow_vartime(&[1 << i]))),
            );
            let is_zero = self.gate().is_zero(ctx, &a);
            let b = self
                .gate()
                .select(ctx, Constant(F::one()), Existing(&a), Existing(&is_zero));
            product = self.gate().mul(ctx, Existing(&product), Existing(&b));
        }
        Ok(product)
    }
}

// CIRCUIT
// =========================================================================

const NUM_ADVICE: usize = 100;

#[derive(Clone)]
struct FriVerifierCircuit<
    'a,
    F: FieldExt + Extendable<2>,
    E: ExtensionFieldChip<D, F>,
    H: HasherChip<F>,
    C: RandomCoinChip<F, H>,
> {
    pub layer_commitments: Vec<[u8; 32]>,
    pub queries: Vec<FriQueryInput<F>>,
    pub remainder: Vec<F::Extension>,
    pub options: FriOptions,
    pub public_coin_seed: F,
    _marker: PhantomData<(&'a (), C, H, E)>,
}

impl<'a, F, E, H, C> Default for FriVerifierCircuit<'a, F, E, H, C>
where
    F: FieldExt + Extendable<2>,
    E: ExtensionFieldChip<D, F>,
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

impl<'a, F, E, H, C, const N: usize> Circuit<F> for FriVerifierCircuit<'a, F, E, H, C>
where
    F: FieldExt + Extendable<2>,
    E: ExtensionFieldChip<D, F, BaseField = F, Field = F::Extension> + Clone,
    H: HasherChip<F, Digest = Digest<'a, F, N>>,
    C: RandomCoinChip<F, H>,
{
    type Config = VerifierChipConfig<F, E>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        VerifierChip::<F, E, H, C>::configure(meta, instance)
    }

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
                        max_rows: 100,
                        fixed_columns: config.extension.gate().constants.clone(),
                        num_context_ids: 1,
                    },
                );

                // Remainder polynomial
                let k = self.remainder.len().ilog2();
                let omega_inv = get_root_of_unity::<F, 28>(k as usize).invert().unwrap();
                let mut remainders_poly = self.remainder.clone();
                best_fft(&mut remainders_poly, F::Extension::from(omega_inv), k);
                let n_inv = F::Extension::from(remainders_poly.len() as u64)
                    .invert()
                    .unwrap();
                for coeff in remainders_poly.iter_mut() {
                    *coeff = *coeff * n_inv;
                }

                // Assign witness cells
                let queries = self
                    .queries
                    .iter()
                    .map(|q| q.assign(&mut ctx, &config).unwrap())
                    .collect::<Vec<_>>();
                let remainders = self
                    .remainder
                    .iter()
                    .map(|r| config.extension.load_witness(&mut ctx, *r))
                    .collect::<Vec<_>>();
                let remainders_poly = remainders_poly
                    .iter()
                    .map(|r| config.extension.load_witness(&mut ctx, *r))
                    .collect::<Vec<_>>();
                let layer_commitments = assign_digests::<N, F, H>(
                    &mut ctx,
                    &config.extension.gate(),
                    &self.layer_commitments,
                )?;
                let fri_proof = FriProofAssigned {
                    layer_commitments,
                    queries,
                    remainders,
                    remainders_poly,
                    options: self.options,
                };

                // Initialize hasher chip
                let mut hasher_chip = H::new(&mut ctx, &config.extension.gate());

                // Initialize public coin chip
                let initial_seed = Digest::new(vec![config
                    .extension
                    .gate()
                    .load_constant(&mut ctx, self.public_coin_seed)]);
                let mut public_coin_chip = C::new(initial_seed);

                // Initialize and run verifier chip
                let verifier_chip = VerifierChip::<F, E, H, C>::new(config.clone(), fri_proof)?;
                verifier_chip.verify_proof(&mut ctx, &mut hasher_chip, &mut public_coin_chip)?;

                config.extension.range().finalize(&mut ctx);

                Ok(())
            },
        )?;

        Ok(())
    }
}

fn assign_digests<'v, const N: usize, F: FieldExt, H: HasherChip<F, Digest = Digest<'v, F, N>>>(
    ctx: &mut Context<'_, F>,
    main_chip: &FlexGateConfig<F>,
    values: &[[u8; 32]],
) -> Result<Vec<H::Digest>, Error> {
    Ok(main_chip
        .assign_region(
            ctx,
            values
                .iter()
                .map(|digest| Witness(Value::known(from_byte_array(digest)))),
            vec![],
        )
        .into_iter()
        .map(|x| Digest::new(vec![x]))
        .collect::<Vec<_>>())
}

fn from_byte_array<F: FieldExt>(input: &[u8; 32]) -> F {
    let mut bytes = F::Repr::default();
    for (v, b) in bytes.as_mut().iter_mut().zip(input.iter()) {
        *v = *b;
    }
    F::from_repr(bytes).unwrap()
}
