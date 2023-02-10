use goldilocks::{Extendable, FieldExtension};
use halo2_base::{
    gates::{
        flex_gate::FlexGateConfig,
        range::{RangeConfig, RangeStrategy},
    },
    utils::ScalarField,
    AssignedValue, Context, QuantumCell,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::{circuit::Value, plonk::*};
use std::fmt::Debug;

pub mod fp2;

pub enum QuantumExtensionCell<'a, 'b: 'a, const D: usize, F: FieldExt + Extendable<D>> {
    Existing(&'a AssignedExtensionValue<'b, F>),
    Witness(ExtensionValue<F>),
    Constant(F::Extension),
}

impl<'a, 'b: 'a, const D: usize, F, E> QuantumExtensionCell<'a, 'b, D, F>
where
    F: FieldExt + Extendable<D, Extension = E>,
    E: FieldExtension<D, BaseField = F>,
{
    fn coeffs(&self) -> Vec<QuantumCell<'a, 'b, F>> {
        match self {
            Self::Existing(a) => a.coeffs.iter().map(Existing).collect(),
            Self::Witness(a) => a.coeffs.iter().cloned().map(Witness).collect(),
            Self::Constant(a) => a
                .to_base_elements()
                .into_iter()
                .map(|x| Constant(x))
                .collect(),
            _ => panic!(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AssignedExtensionValue<'v, F: FieldExt> {
    pub coeffs: Vec<AssignedValue<'v, F>>,
}

impl<'a, F: FieldExt> AssignedExtensionValue<'a, F> {
    pub fn construct(coeffs: Vec<AssignedValue<'a, F>>) -> Self {
        Self { coeffs }
    }
    pub fn coeffs(&self) -> Vec<AssignedValue<'a, F>> {
        self.coeffs.clone()
    }
}

#[derive(Clone, Debug)]
pub struct ExtensionValue<F: FieldExt> {
    pub coeffs: Vec<Value<F>>,
}

#[derive(Clone, Debug)]
pub struct ExtensionConstant<F: FieldExt> {
    pub coeffs: Vec<F>,
}

#[derive(Clone, Debug)]
pub struct ExtensionFieldConfig<F: FieldExt> {
    pub range: RangeConfig<F>,
}

impl<F: FieldExt> ExtensionFieldConfig<F> {
    pub fn configure(meta: &mut ConstraintSystem<F>, num_advice: usize, k: usize) -> Self {
        let range = RangeConfig::configure(
            meta,
            RangeStrategy::PlonkPlus,
            &[num_advice],
            &[1],
            1,
            3,
            0,
            k,
        );
        Self { range }
    }
}

pub trait ExtensionFieldChip<const D: usize, F: FieldExt> {
    type BaseField: FieldExt + Extendable<D>;
    type Field: Debug + FieldExtension<D> + FieldExt + From<u64>;

    fn construct(config: ExtensionFieldConfig<F>) -> Self;

    fn gate(&self) -> &FlexGateConfig<F>;

    fn range(&self) -> &RangeConfig<F>;

    fn load_witness<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        witness: <Self::BaseField as Extendable<D>>::Extension,
    ) -> AssignedExtensionValue<'v, F>;

    fn load_constant<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        coeffs: Self::Field,
    ) -> AssignedExtensionValue<'v, F>;

    fn constrain_equal<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedExtensionValue<'v, F>,
        b: &AssignedExtensionValue<'v, F>,
    );

    fn add<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, D, Self::BaseField>,
        b: QuantumExtensionCell<'_, 'v, D, Self::BaseField>,
    ) -> AssignedExtensionValue<'v, F>;

    fn sub<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, D, Self::BaseField>,
        b: QuantumExtensionCell<'_, 'v, D, Self::BaseField>,
    ) -> AssignedExtensionValue<'v, F>;

    fn add_base<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedExtensionValue<'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedExtensionValue<'v, F>;

    fn sub_base<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedExtensionValue<'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedExtensionValue<'v, F>;

    fn negate<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, D, Self::BaseField>,
    ) -> AssignedExtensionValue<'v, F>;

    fn mul_base<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, D, Self::BaseField>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedExtensionValue<'v, F>;

    fn mul<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, D, Self::BaseField>,
        b: QuantumExtensionCell<'_, 'v, D, Self::BaseField>,
    ) -> AssignedExtensionValue<'v, F>;

    fn mul_add<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, D, Self::BaseField>,
        b: QuantumExtensionCell<'_, 'v, D, Self::BaseField>,
        c: QuantumExtensionCell<'_, 'v, D, Self::BaseField>,
    ) -> AssignedExtensionValue<'v, F>;

    fn range_check<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedExtensionValue<'v, F>,
        max_bits: usize,
    );

    fn is_zero<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedExtensionValue<'v, F>,
    ) -> AssignedValue<'v, F>;

    fn assert_equal<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedExtensionValue<'v, F>,
        b: &AssignedExtensionValue<'v, F>,
    );

    fn select<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, D, Self::BaseField>,
        b: QuantumExtensionCell<'_, 'v, D, Self::BaseField>,
        sel: &AssignedValue<'v, F>,
    ) -> AssignedExtensionValue<'v, F>;

    fn select_by_indicator<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: Vec<QuantumExtensionCell<'_, 'v, D, Self::BaseField>>,
        indicator: Vec<AssignedValue<'v, F>>,
    ) -> AssignedExtensionValue<'v, F>;

    fn inner_product<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: Vec<AssignedExtensionValue<'v, F>>,
        b: Vec<AssignedExtensionValue<'v, F>>,
    ) -> AssignedExtensionValue<'v, F>;
}
