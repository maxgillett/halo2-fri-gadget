use halo2_base::{
    gates::flex_gate::FlexGateConfig, poseidon::PoseidonChip, AssignedValue, Context,
};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::*;

pub mod poseidon_bn254;
pub mod poseidon_fp64;

// HASHER CHIP
// =========================================================================

pub trait HasherChip<F: FieldExt> {
    type Digest: HasherChipDigest<F>;

    fn new(ctx: &mut Context<F>, main_gate: &FlexGateConfig<F>) -> Self;

    fn hash_elements(
        &self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        values: &[AssignedValue<F>],
    ) -> Result<Self::Digest, Error>;

    fn hash_digests(
        &mut self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        values: &[Self::Digest],
    ) -> Result<Self::Digest, Error> {
        let elements = values
            .iter()
            .flat_map(|x| x.to_assigned().to_vec())
            .collect::<Vec<_>>();
        self.hash_elements(ctx, main_chip, &elements)
    }
}

// HASHER CHIP DIGEST
// =========================================================================

pub trait HasherChipDigest<F: FieldExt>: Clone {
    fn to_assigned(&self) -> &[AssignedValue<F>];
}

#[derive(Clone)]
pub struct Digest<'v, F: FieldExt, const N: usize>([AssignedValue<'v, F>; N]);

impl<'a, F: FieldExt, const N: usize> Digest<'a, F, N> {
    pub fn new(values: Vec<AssignedValue<'a, F>>) -> Digest<'a, F, N> {
        Self(values.try_into().unwrap())
    }
}

impl<F: FieldExt, const N: usize> HasherChipDigest<F> for Digest<'_, F, N> {
    fn to_assigned(&self) -> &[AssignedValue<F>] {
        self.0[..].as_ref()
    }
}
