use crate::fields::{AssignedExtensionValue, ExtensionFieldChip}; //ExtensionValueConstructor};
use crate::hash::{HasherChip, HasherChipDigest};
use crate::D;
use goldilocks::{Extendable, FieldExtension};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};
use halo2_proofs::{arithmetic::FieldExt, plonk::*};
use std::marker::PhantomData;

// RANDOM COIN CHIP
// =========================================================================

pub trait RandomCoinChip<F: FieldExt + Extendable<2>, H: HasherChip<F>> {
    fn new(seed: H::Digest) -> Self;

    fn draw_alpha<'v, E: ExtensionFieldChip<D, F>>(
        &mut self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        hasher_chip: &mut H,
        commitment: &H::Digest,
        counter: &mut AssignedValue<'v, F>,
    ) -> Result<H::Digest, Error>;
}

#[derive(Clone)]
pub struct RandomCoin<F: FieldExt, H: HasherChip<F>> {
    pub seed: H::Digest,
    _marker: PhantomData<H>,
}

impl<F: FieldExt + Extendable<2>, H: HasherChip<F>> RandomCoinChip<F, H> for RandomCoin<F, H> {
    fn new(seed: H::Digest) -> Self {
        Self {
            seed,
            _marker: PhantomData,
        }
    }

    fn draw_alpha<'v, E: ExtensionFieldChip<D, F>>(
        &mut self,
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        hasher_chip: &mut H,
        commitment: &H::Digest,
        counter: &mut AssignedValue<'v, F>,
    ) -> Result<H::Digest, Error> {
        // Reseed
        let mut contents = self.seed.to_assigned().to_vec();
        contents.append(&mut commitment.to_assigned().to_vec());
        self.seed = hasher_chip.hash_elements(ctx, main_chip, &contents)?;
        *counter = main_chip.mul(ctx, Constant(F::zero()), Existing(counter));

        // Reproduce alpha
        let mut contents = self
            .seed
            .to_assigned()
            .into_iter()
            .map(|x| x.clone())
            .collect::<Vec<_>>();
        *counter = main_chip.add(ctx, Constant(F::one()), Existing(counter));
        contents.push(counter.clone());
        let digest = hasher_chip.hash_elements(ctx, main_chip, &contents)?;

        Ok(digest)
    }
}
