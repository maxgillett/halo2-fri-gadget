use super::{
    AssignedExtensionValue, ExtensionFieldChip, ExtensionFieldConfig, QuantumExtensionCell,
};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    utils::ScalarField,
    AssignedValue, Context,
    QuantumCell::{self, Constant, Existing, Witness},
};
use halo2_proofs::arithmetic::{Extendable, FieldExt, FieldExtension};
use halo2_proofs::circuit::Value;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct FpChip<F: FieldExt> {
    pub config: ExtensionFieldConfig<F>,
    _f: PhantomData<F>,
}

impl<F, Fp2> ExtensionFieldChip<1, F> for FpChip<F>
where
    F: FieldExt + Extendable<1, BaseField = F, Extension = Fp2>,
    Fp2: FieldExt + FieldExtension<1, BaseField = F>,
{
    type BaseField = F;
    type Field = Fp2;

    fn construct(config: ExtensionFieldConfig<F>) -> Self {
        Self {
            config,
            _f: PhantomData,
        }
    }

    fn gate(&self) -> &FlexGateConfig<F> {
        &self.config.range.gate
    }

    fn range(&self) -> &RangeConfig<F> {
        &self.config.range
    }

    fn load_witness<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        witness: F::Extension,
    ) -> AssignedExtensionValue<'v, F> {
        let coeffs = witness.to_base_elements();
        assert_eq!(coeffs.len(), 1);
        let mut assigned_coeffs = Vec::with_capacity(1);
        for a in coeffs {
            let assigned_coeff = self.config.range.gate().load_witness(ctx, Value::known(a));
            assigned_coeffs.push(assigned_coeff);
        }
        AssignedExtensionValue::construct(assigned_coeffs)
    }

    fn load_constant<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        c: F::Extension,
    ) -> AssignedExtensionValue<'v, F> {
        let coeffs = c.to_base_elements();
        let mut assigned_coeffs = Vec::with_capacity(1);
        for a in &coeffs {
            let assigned_coeff = self.config.range.gate().load_constant(ctx, *a);
            assigned_coeffs.push(assigned_coeff);
        }
        AssignedExtensionValue::construct(assigned_coeffs)
    }

    fn constrain_equal<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedExtensionValue<'v, F>,
        b: &AssignedExtensionValue<'v, F>,
    ) {
        for (a, b) in a.coeffs.iter().zip(b.coeffs.iter()) {
            ctx.constrain_equal(a, b);
        }
    }

    fn add<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, 1, F>,
        b: QuantumExtensionCell<'_, 'v, 1, F>,
    ) -> AssignedExtensionValue<'v, F> {
        let a0 = a.coeffs()[0].clone();
        let b0 = b.coeffs()[0].clone();
        let c0 = self.config.range.gate().add(ctx, a0, b0);
        AssignedExtensionValue::construct(vec![c0])
    }

    fn sub<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, 1, F>,
        b: QuantumExtensionCell<'_, 'v, 1, F>,
    ) -> AssignedExtensionValue<'v, F> {
        let a0 = a.coeffs()[0].clone();
        let b0 = b.coeffs()[0].clone();
        let c0 = self.config.range.gate().sub(ctx, a0, b0);
        AssignedExtensionValue::construct(vec![c0])
    }

    fn add_base<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedExtensionValue<'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedExtensionValue<'v, F> {
        let a0 = a.coeffs()[0].clone();
        let c0 = self.config.range.gate().add(ctx, Existing(&a0), b);
        AssignedExtensionValue::construct(vec![c0])
    }

    fn sub_base<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedExtensionValue<'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedExtensionValue<'v, F> {
        let a0 = a.coeffs()[0].clone();
        let c0 = self.config.range.gate().sub(ctx, Existing(&a0), b);
        AssignedExtensionValue::construct(vec![c0])
    }

    fn negate<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, 1, F>,
    ) -> AssignedExtensionValue<'v, F> {
        let a_coeffs = a.coeffs();
        let mut out_coeffs = Vec::with_capacity(a_coeffs.len());
        for a_coeff in a_coeffs {
            let out_coeff = self
                .config
                .range
                .gate()
                .mul(ctx, a_coeff, Constant(-F::one())); // negate
            out_coeffs.push(out_coeff);
        }
        AssignedExtensionValue::construct(out_coeffs)
    }

    fn mul_base<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, 1, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedExtensionValue<'v, F> {
        let a_coeffs = a.coeffs();
        assert_eq!(a_coeffs.len(), 1);

        let mut out_coeffs = Vec::with_capacity(1);
        for a in a_coeffs {
            let coeff = self
                .config
                .range
                .gate()
                .mul(ctx, a, Witness(b.value().map(|x| *x)));
            out_coeffs.push(coeff);
        }
        AssignedExtensionValue::construct(out_coeffs)
    }

    fn mul<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, 1, F>,
        b: QuantumExtensionCell<'_, 'v, 1, F>,
    ) -> AssignedExtensionValue<'v, F> {
        let a0 = a.coeffs()[0].clone();
        let b0 = b.coeffs()[0].clone();
        let c0 = self.config.range.gate().mul(ctx, a0, b0);
        AssignedExtensionValue::construct(vec![c0])
    }

    // a*c + c
    fn mul_add<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, 1, F>,
        b: QuantumExtensionCell<'_, 'v, 1, F>,
        c: QuantumExtensionCell<'_, 'v, 1, F>,
    ) -> AssignedExtensionValue<'v, F> {
        let d = self.mul(ctx, a, b);
        let e = self.add(ctx, c, QuantumExtensionCell::Existing(&d));
        e
    }

    fn range_check<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedExtensionValue<'v, F>,
        max_bits: usize,
    ) {
        for a_coeff in &a.coeffs {
            self.config.range.range_check(ctx, a_coeff, max_bits);
        }
    }

    fn is_zero<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedExtensionValue<'v, F>,
    ) -> AssignedValue<'v, F> {
        let mut prev = None;
        for a_coeff in &a.coeffs {
            let coeff = self.config.range.gate().is_zero(ctx, a_coeff);
            if let Some(p) = prev {
                let new = self
                    .config
                    .range
                    .gate()
                    .and(ctx, Existing(&coeff), Existing(&p));
                prev = Some(new);
            } else {
                prev = Some(coeff);
            }
        }
        prev.unwrap()
    }

    fn assert_equal<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedExtensionValue<'v, F>,
        b: &AssignedExtensionValue<'v, F>,
    ) {
        for (a_coeff, b_coeff) in a.coeffs.iter().zip(b.coeffs.iter()) {
            self.config
                .range
                .gate()
                .assert_equal(ctx, Existing(a_coeff), Existing(b_coeff))
        }
    }

    fn select<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, 1, F>,
        b: QuantumExtensionCell<'_, 'v, 1, F>,
        sel: &AssignedValue<'v, F>,
    ) -> AssignedExtensionValue<'v, F> {
        let coeffs: Vec<_> = a
            .coeffs()
            .into_iter()
            .zip(b.coeffs().into_iter())
            .map(|(a, b)| self.config.range.gate().select(ctx, a, b, Existing(sel)))
            .collect();
        AssignedExtensionValue::construct(coeffs)
    }

    fn select_by_indicator<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: Vec<QuantumExtensionCell<'_, 'v, 1, F>>,
        indicator: Vec<AssignedValue<'v, F>>,
    ) -> AssignedExtensionValue<'v, F> {
        let a_coeffs_0: Vec<_> = a
            .into_iter()
            .map(|x| {
                let coeffs = x.coeffs();
                coeffs[0].clone()
            })
            .collect();
        let out = [a_coeffs_0]
            .into_iter()
            .map(|coeff| {
                self.config.range.gate().select_by_indicator(
                    ctx,
                    coeff.clone(),
                    indicator.iter().map(|x| x),
                )
            })
            .collect::<Vec<_>>();
        AssignedExtensionValue::construct(vec![out[0].clone()])
    }

    fn inner_product<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: Vec<AssignedExtensionValue<'v, F>>,
        b: Vec<AssignedExtensionValue<'v, F>>,
    ) -> AssignedExtensionValue<'v, F> {
        let a_coeffs_0: Vec<_> = a.iter().map(|x| Existing(&x.coeffs[0])).collect();
        let b_coeffs_0: Vec<_> = b.iter().map(|x| Existing(&x.coeffs[0])).collect();
        let out0 = self
            .config
            .range
            .gate()
            .inner_product(ctx, a_coeffs_0, b_coeffs_0);
        AssignedExtensionValue::construct(vec![out0])
    }
}
