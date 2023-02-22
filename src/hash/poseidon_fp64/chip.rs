use super::{
    Poseidon64_256, ALL_ROUND_CONSTANTS, FAST_PARTIAL_FIRST_ROUND_CONSTANT,
    FAST_PARTIAL_ROUND_CONSTANTS, FAST_PARTIAL_ROUND_INITIAL_MATRIX, HALF_N_FULL_ROUNDS,
    N_PARTIAL_ROUNDS, WIDTH,
};
use crate::hash::{Digest, HasherChip};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};
use halo2_proofs::arithmetic::Field64;
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

    fn new(_ctx: &mut Context<F>, _flex_gate: &FlexGateConfig<F>) -> Self {
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
        let mut state: [AssignedValue<F>; WIDTH] = main_chip
            .assign_region(ctx, (0..WIDTH).map(|_| Constant(F::zero())), vec![])
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
        self.permute(ctx, main_chip, &mut state)?;
        Ok(Digest::new(state[..4].to_vec()))
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

        // Partial rounds
        Self::partial_first_constant_layer(ctx, chip, state);
        *state = Self::mds_partial_layer_init(ctx, chip, state);
        for i in 0..N_PARTIAL_ROUNDS {
            state[0] = Self::sbox_monomial(ctx, chip, state[0].clone());
            state[0] = chip.add(
                ctx,
                Existing(&state[0]),
                Constant(F::from(FAST_PARTIAL_ROUND_CONSTANTS[i])),
            );
            *state = Self::mds_partial_layer_fast(ctx, chip, state, i);
        }
        round_ctr += N_PARTIAL_ROUNDS;

        // Full rounds
        for _ in 0..HALF_N_FULL_ROUNDS {
            Self::constant_layer(ctx, chip, state, round_ctr);
            Self::sbox_layer(ctx, chip, state);
            *state = Self::mds_layer(ctx, chip, state);
            round_ctr += 1;
        }

        Ok(())
    }

    fn mds_partial_layer_fast<'v, const WIDTH: usize>(
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        state: &[AssignedValue<'v, F>; WIDTH],
        r: usize,
    ) -> [AssignedValue<'v, F>; WIDTH] {
        let s0 = state[0].clone();
        let mds0to0 =
            Poseidon64_256::<F>::MDS_MATRIX_CIRC[0] + Poseidon64_256::<F>::MDS_MATRIX_DIAG[0];
        let mut d = chip.mul(ctx, Constant(F::from_canonical_u64(mds0to0)), Existing(&s0));
        for i in 1..WIDTH {
            let t = Poseidon64_256::<F>::FAST_PARTIAL_ROUND_W_HATS[r][i - 1];
            d = chip.mul_add(
                ctx,
                Constant(F::from_canonical_u64(t)),
                Existing(&state[i]),
                Existing(&d),
            );
        }

        let mut result = vec![];
        result.push(d);
        for i in 1..WIDTH {
            let t = Poseidon64_256::<F>::FAST_PARTIAL_ROUND_VS[r][i - 1];
            let res = chip.mul_add(
                ctx,
                Constant(F::from_canonical_u64(t)),
                Existing(&state[0]),
                Existing(&state[i]),
            );
            result.push(res);
        }
        result.try_into().unwrap()
    }

    fn constant_layer<const WIDTH: usize>(
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        state: &mut [AssignedValue<'_, F>; WIDTH],
        round_ctr: usize,
    ) {
        for i in 0..12 {
            let round_constant = ALL_ROUND_CONSTANTS[i + WIDTH * round_ctr];
            state[i] = chip.add(ctx, Existing(&state[i]), Constant(F::from(round_constant)));
        }
    }

    fn mds_partial_layer_init<'v, const WIDTH: usize>(
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        state: &[AssignedValue<'v, F>; WIDTH],
    ) -> [AssignedValue<'v, F>; WIDTH] {
        let mut result = (0..WIDTH)
            .map(|_| chip.load_constant(ctx, F::zero()))
            .collect::<Vec<_>>();
        result[0] = state[0].clone();

        // TODO: Use inner product gate instead of nested for loop
        for r in 1..WIDTH {
            for c in 1..WIDTH {
                let t = FAST_PARTIAL_ROUND_INITIAL_MATRIX[r - 1][c - 1];
                result[c] = chip.mul_add(
                    ctx,
                    Constant(F::from_canonical_u64(t)),
                    Existing(&state[r]),
                    Existing(&result[c]),
                );
            }
        }
        result.try_into().unwrap()
    }

    fn partial_first_constant_layer<const WIDTH: usize>(
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        state: &mut [AssignedValue<'_, F>; WIDTH],
    ) {
        for i in 0..WIDTH {
            state[i] = chip.add(
                ctx,
                Existing(&state[i]),
                Constant(F::from_canonical_u64(FAST_PARTIAL_FIRST_ROUND_CONSTANT[i])),
            );
        }
    }

    fn sbox_layer<'v, const WIDTH: usize>(
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        state: &mut [AssignedValue<'v, F>; WIDTH],
    ) {
        for i in 0..WIDTH {
            state[i] = Self::sbox_monomial(ctx, chip, state[i].clone());
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
            let res = Self::mds_row_shf_circuit(ctx, chip, r, state);
            result.push(res);
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
                Constant(c),
                Existing(&v[(i + r) % WIDTH]),
                Existing(&res),
            );
        }
        {
            let c = F::from_canonical_u64(Poseidon64_256::<F>::MDS_MATRIX_DIAG[r]);
            res = chip.mul_add(ctx, Constant(c), Existing(&v[r]), Existing(&res));
        }

        res
    }
}
