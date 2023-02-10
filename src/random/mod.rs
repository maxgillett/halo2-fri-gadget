use crate::fields::{AssignedExtensionValue, ExtensionFieldChip};
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

// TODO: Re-extract the 'draw_alpha' method here from the main verifier chip
pub trait RandomCoinChip<'a, F: FieldExt + Extendable<2>, H: HasherChip<F>> {
    fn new(seed: H::Digest<'a>) -> Self;

    fn seed(&self) -> H::Digest<'a>;
}

#[derive(Clone)]
pub struct RandomCoin<'v, F: FieldExt, H: HasherChip<F>> {
    pub seed: H::Digest<'v>,
    _marker: PhantomData<H>,
}

impl<'a, F: FieldExt + Extendable<2>, H: HasherChip<F>> RandomCoinChip<'a, F, H>
    for RandomCoin<'a, F, H>
{
    fn new(seed: H::Digest<'a>) -> Self {
        Self {
            seed,
            _marker: PhantomData,
        }
    }

    fn seed(&self) -> H::Digest<'a> {
        self.seed.clone()
    }
}
