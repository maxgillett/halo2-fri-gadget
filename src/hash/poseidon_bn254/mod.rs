// Modified from the Axiom halo2-base repo
use halo2_base::{
    gates::GateInstructions,
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};

use halo2_proofs::{halo2curves::FieldExt, plonk::Error};
use std::marker::PhantomData;
// taken from https://github.com/scroll-tech/halo2-snark-aggregator/tree/main/halo2-snark-aggregator-api/src/hash
use poseidon::{SparseMDSMatrix, Spec, State};

pub mod chip;

#[derive(Clone)]
struct PoseidonState<'a, F: FieldExt, A: GateInstructions<F>, const T: usize, const RATE: usize> {
    s: [AssignedValue<'a, F>; T],
    _marker: PhantomData<A>,
}

impl<'a, F: FieldExt, A: GateInstructions<F>, const T: usize, const RATE: usize>
    PoseidonState<'a, F, A, T, RATE>
{
    fn x_power5_with_constant<'v>(
        ctx: &mut Context<'_, F>,
        chip: &A,
        x: &AssignedValue<'v, F>,
        constant: &F,
    ) -> AssignedValue<'v, F> {
        let x2 = chip.mul(ctx, Existing(x), Existing(x));
        let x4 = chip.mul(ctx, Existing(&x2), Existing(&x2));
        chip.mul_add(ctx, Existing(x), Existing(&x4), Constant(*constant))
    }

    fn sbox_full(
        &mut self,
        ctx: &mut Context<'_, F>,
        chip: &A,
        constants: &[F; T],
    ) -> Result<(), Error> {
        for (x, constant) in self.s.iter_mut().zip(constants.iter()) {
            *x = Self::x_power5_with_constant(ctx, chip, x, constant);
        }
        Ok(())
    }

    fn sbox_part(&mut self, ctx: &mut Context<'_, F>, chip: &A, constant: &F) -> Result<(), Error> {
        let x = &mut self.s[0];
        *x = Self::x_power5_with_constant(ctx, chip, x, constant);

        Ok(())
    }

    fn absorb_with_pre_constants(
        &mut self,
        ctx: &mut Context<'_, F>,
        chip: &A,
        inputs: Vec<AssignedValue<'a, F>>,
        pre_constants: &[F; T],
    ) -> Result<(), Error> {
        assert!(inputs.len() < T);
        let offset = inputs.len() + 1;

        if let Some(s_0) = self.s.get_mut(offset) {
            *s_0 = chip.add(ctx, Existing(&s_0), Constant(F::one()));
        }

        for (x, input) in self.s.iter_mut().skip(1).zip(inputs.iter()) {
            *x = chip.add(ctx, Existing(x), Existing(input));
        }

        for (i, (x, constant)) in self.s.iter_mut().zip(pre_constants.iter()).enumerate() {
            *x = chip.add(ctx, Existing(x), Constant(*constant));
        }

        Ok(())
    }

    fn apply_mds(
        &mut self,
        ctx: &mut Context<'_, F>,
        chip: &A,
        mds: &[[F; T]; T],
    ) -> Result<(), Error> {
        let res = mds
            .iter()
            .map(|row| {
                let sum = chip.inner_product(
                    ctx,
                    self.s.iter().map(|a| Existing(a)),
                    row.iter().map(|c| Constant(*c)),
                );
                Ok(sum)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        self.s = res.try_into().unwrap();

        Ok(())
    }

    fn apply_sparse_mds(
        &mut self,
        ctx: &mut Context<'_, F>,
        chip: &A,
        mds: &SparseMDSMatrix<F, T, RATE>,
    ) -> Result<(), Error> {
        let sum = chip.inner_product(
            ctx,
            self.s.iter().map(|a| Existing(a)),
            mds.row().iter().map(|c| Constant(*c)),
        );
        let mut res = vec![sum];

        for (e, x) in mds.col_hat().iter().zip(self.s.iter().skip(1)) {
            res.push(chip.mul_add(ctx, Existing(&self.s[0]), Constant(*e), Existing(x)));
        }

        for (x, new_x) in self.s.iter_mut().zip(res.into_iter()) {
            *x = new_x
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct PoseidonChip<'a, F: FieldExt, A: GateInstructions<F>, const T: usize, const RATE: usize>
{
    init_state: [AssignedValue<'a, F>; T],
    spec: Spec<F, T, RATE>,
    _marker: PhantomData<A>,
}

impl<'a, F: FieldExt, A: GateInstructions<F>, const T: usize, const RATE: usize>
    PoseidonChip<'a, F, A, T, RATE>
{
    pub fn new(ctx: &mut Context<'_, F>, chip: &A, r_f: usize, r_p: usize) -> Result<Self, Error> {
        let init_state = State::<F, T>::default()
            .words()
            .into_iter()
            .map(|x| {
                Ok(chip
                    .assign_region(ctx, vec![Constant(x)], vec![])
                    .pop()
                    .unwrap())
            })
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        Ok(Self {
            spec: Spec::new(r_f, r_p),
            init_state: init_state.clone().try_into().unwrap(),
            _marker: PhantomData,
        })
    }

    pub fn hash(
        &self,
        ctx: &mut Context<'_, F>,
        chip: &A,
        elements: &[AssignedValue<'a, F>],
    ) -> Result<AssignedValue<F>, Error> {
        let mut state = PoseidonState {
            s: self.init_state.clone(),
            _marker: PhantomData,
        };
        let mut absorbing = vec![];

        // Update
        absorbing.extend_from_slice(elements);

        // Squeeze
        let mut input_elements = vec![];
        input_elements.append(&mut absorbing);
        let mut padding_offset = 0;
        for chunk in input_elements.chunks(RATE) {
            padding_offset = RATE - chunk.len();
            self.permutation(ctx, chip, &mut state, chunk.to_vec())?;
        }
        if padding_offset == 0 {
            self.permutation(ctx, chip, &mut state, vec![])?;
        }
        let out = state.s[1].clone();

        Ok(out)
    }

    fn permutation<'v: 'a>(
        &self,
        ctx: &mut Context<'_, F>,
        chip: &A,
        state: &mut PoseidonState<'a, F, A, T, RATE>,
        inputs: Vec<AssignedValue<'v, F>>,
    ) -> Result<(), Error> {
        let r_f = self.spec.r_f() / 2;
        let mds = &self.spec.mds_matrices().mds().rows();

        let constants = &self.spec.constants().start();
        state.absorb_with_pre_constants(ctx, chip, inputs, &constants[0])?;
        for constants in constants.iter().skip(1).take(r_f - 1) {
            state.sbox_full(ctx, chip, constants)?;
            state.apply_mds(ctx, chip, mds)?;
        }

        let pre_sparse_mds = &self.spec.mds_matrices().pre_sparse_mds().rows();
        state.sbox_full(ctx, chip, constants.last().unwrap())?;
        state.apply_mds(ctx, chip, pre_sparse_mds)?;

        let sparse_matrices = &self.spec.mds_matrices().sparse_matrices();
        let constants = &self.spec.constants().partial();
        for (constant, sparse_mds) in constants.iter().zip(sparse_matrices.iter()) {
            state.sbox_part(ctx, chip, constant)?;
            state.apply_sparse_mds(ctx, chip, sparse_mds)?;
        }

        let constants = &self.spec.constants().end();
        for constants in constants.iter() {
            state.sbox_full(ctx, chip, constants)?;
            state.apply_mds(ctx, chip, mds)?;
        }
        state.sbox_full(ctx, chip, &[F::zero(); T])?;
        state.apply_mds(ctx, chip, mds)?;

        Ok(())
    }
}
