use super::{Poseidon64_256, ALL_ROUND_CONSTANTS, HALF_N_FULL_ROUNDS};
use crate::hash::{Digest, HasherChip};
use goldilocks::Field64;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::*;
use std::marker::PhantomData;

// TODO: We should reintroduce a private 'PoseidonChip' struct that is generic over rate,
// capacity, width, etc, as was done for PoseidonChipBn254_8_58

#[derive(Clone)]
pub struct PoseidonChipFp64_8_22<F: Field64> {
    _marker: PhantomData<F>,
}

impl<F: Field64> HasherChip<F> for PoseidonChipFp64_8_22<F> {
    type Digest<'v> = Digest<'v, F, 4>;

    fn new(ctx: &mut Context<F>, flex_gate: &FlexGateConfig<F>) -> Self {
        Self {
            _marker: PhantomData::<F>,
        }
    }

    fn hash_elements<'v>(
        &'v self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        values: &[AssignedValue<'v, F>],
    ) -> Result<Self::Digest<'v>, Error> {
        let mut state: [AssignedValue<F>; 12] = main_chip
            .assign_region(ctx, (0..12).map(|_| Constant(F::zero())), vec![])
            .try_into()
            .unwrap();

        // Absorb all input chunks.
        for input_chunk in values.chunks(8) {
            // Overwrite the first r elements with the inputs. This differs from a standard sponge,
            // where we would xor or add in the inputs. This is a well-known variant, though,
            // sometimes called "overwrite mode".
            state[..input_chunk.len()].clone_from_slice(input_chunk);
            self.permute(ctx, main_chip, &mut state)?;
        }

        // Squeeze until we have the desired number of outputs.
        let mut outputs = vec![];
        for i in 0..8 {
            outputs.push(state[i].clone());
            if i < 3 {
                self.permute(ctx, main_chip, &mut state)?;
            }
        }

        Ok(Digest::new(outputs))
    }
}

impl<F: Field64> PoseidonChipFp64_8_22<F> {
    fn permute<'v, const WIDTH: usize>(
        &self,
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        state: &mut [AssignedValue<'v, F>; WIDTH],
    ) -> Result<(), Error> {
        let mut round_ctr = 0;

        // Full rounds
        for _ in 0..HALF_N_FULL_ROUNDS {
            Self::constant_layer(ctx, chip, state, round_ctr);
            Self::sbox_layer(ctx, chip, state);
            *state = Self::mds_layer(ctx, chip, state);
            round_ctr += 1;
        }

        // TODO: Implement partial round

        // TODO: Implement second full round

        Ok(())
    }

    fn constant_layer<const WIDTH: usize>(
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        state: &mut [AssignedValue<'_, F>; WIDTH],
        round_ctr: usize,
    ) {
        for i in 0..12 {
            if i < WIDTH {
                let round_constant = ALL_ROUND_CONSTANTS[i + WIDTH * round_ctr];
                state[i] = chip.add(ctx, Existing(&state[i]), Constant(F::from(round_constant)));
            }
        }
    }

    fn sbox_layer<'v, const WIDTH: usize>(
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        state: &mut [AssignedValue<'v, F>; WIDTH],
    ) {
        for i in 0..12 {
            if i < WIDTH {
                state[i] = Self::sbox_monomial(ctx, chip, state[i].clone());
            }
        }
    }

    fn sbox_monomial<'v>(
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        x: AssignedValue<'v, F>,
    ) -> AssignedValue<'v, F> {
        let x2 = chip.mul(ctx, Existing(&x), Existing(&x));
        let x4 = chip.mul(ctx, Existing(&x2), Existing(&x2));
        let x6 = chip.mul(ctx, Existing(&x4), Existing(&x2));
        chip.mul(ctx, Existing(&x), Existing(&x6))
    }

    fn mds_layer<'v, const WIDTH: usize>(
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        state: &[AssignedValue<'v, F>; WIDTH],
    ) -> [AssignedValue<'v, F>; WIDTH] {
        let mut result = vec![];
        for r in 0..WIDTH {
            result[r] = Self::mds_row_shf_circuit(ctx, chip, r, state);
        }

        result.try_into().unwrap()
    }

    fn mds_row_shf_circuit<'v, const WIDTH: usize>(
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        r: usize,
        v: &[AssignedValue<'v, F>; WIDTH],
    ) -> AssignedValue<'v, F> {
        let mut res = chip.load_constant(ctx, F::zero());

        for i in 0..WIDTH {
            let c = F::from_canonical_u64(Poseidon64_256::<F>::MDS_MATRIX_CIRC[i]);
            res = chip.mul_add(
                ctx,
                Existing(&res),
                Existing(&v[(i + r) % WIDTH]),
                Constant(c),
            );
        }
        {
            let c = F::from_canonical_u64(Poseidon64_256::<F>::MDS_MATRIX_DIAG[r]);
            res = chip.mul_add(ctx, Existing(&v[r]), Existing(&res), Constant(c));
        }

        res
    }
}
