use crate::hash::{Digest, HasherChip};
use halo2_base::{
    gates::flex_gate::FlexGateConfig, poseidon::PoseidonChip, AssignedValue, Context,
};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::*;

#[derive(Clone)]
pub struct PoseidonChipBn254_8_58<'a, F: FieldExt>(PoseidonChip<'a, F, FlexGateConfig<F>, 4, 3>);

impl<'a, F: FieldExt> HasherChip<F> for PoseidonChipBn254_8_58<'a, F> {
    // TODO: We need to use generic associated types here so that the lifetime
    // is not bound to that of the chip.
    type Digest = Digest<'a, F, 1>;

    fn new(ctx: &mut Context<F>, flex_gate: &FlexGateConfig<F>) -> Self {
        Self(PoseidonChip::<F, FlexGateConfig<F>, 4, 3>::new(ctx, flex_gate, 8, 58).unwrap())
    }

    fn hash_elements(
        &self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        values: &[AssignedValue<F>],
    ) -> Result<Self::Digest, Error> {
        todo!();
        let value = self.0.hash(ctx, main_chip, values)?;
        Ok(Digest([value; 1]))
    }
}
