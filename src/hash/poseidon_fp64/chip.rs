use crate::hash::{Digest, HasherChip};
use halo2_base::{
    gates::flex_gate::FlexGateConfig, poseidon::PoseidonChip, AssignedValue, Context,
};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::*;

#[derive(Clone)]
pub struct PoseidonChipFp64_8_22<'a, F: FieldExt>(PoseidonChip<'a, F, FlexGateConfig<F>, 4, 3>);

impl<'a, F: FieldExt> HasherChip<F> for PoseidonChipFp64_8_22<'a, F> {
    // TODO: We need to use generic associated types here so that the lifetime
    // is not bound to that of the chip.
    type Digest = Digest<'a, F, 4>;

    fn new(ctx: &mut Context<F>, flex_gate: &FlexGateConfig<F>) -> Self {
        Self(PoseidonChip::<F, FlexGateConfig<F>, 4, 3>::new(ctx, flex_gate, 8, 22).unwrap())
    }

    fn hash_elements(
        &self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        values: &[AssignedValue<F>],
    ) -> Result<Self::Digest, Error> {
        // TODO: implement Goldilocks-Poseidon chip
        todo!()
    }
}
