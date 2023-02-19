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
pub struct Fp2Chip<F: FieldExt> {
    pub config: ExtensionFieldConfig<F>,
    _f: PhantomData<F>,
}

// TODO: Some of these instructions can be further optimized at the gate level
impl<F, Fp2> ExtensionFieldChip<2, F> for Fp2Chip<F>
where
    F: FieldExt + Extendable<2, BaseField = F, Extension = Fp2>,
    Fp2: FieldExt + FieldExtension<2, BaseField = F>,
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
        assert_eq!(coeffs.len(), 2);
        let mut assigned_coeffs = Vec::with_capacity(2);
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
        let mut assigned_coeffs = Vec::with_capacity(2);
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
        a: QuantumExtensionCell<'_, 'v, 2, F>,
        b: QuantumExtensionCell<'_, 'v, 2, F>,
    ) -> AssignedExtensionValue<'v, F> {
        let a_coeffs = a.coeffs();
        let b_coeffs = b.coeffs();
        assert_eq!(a_coeffs.len(), b_coeffs.len());
        let mut out_coeffs = Vec::with_capacity(a_coeffs.len());
        for (a, b) in a_coeffs.iter().cloned().zip(b_coeffs.iter().cloned()) {
            let coeff = self.config.range.gate().add(ctx, a, b);
            out_coeffs.push(coeff);
        }
        AssignedExtensionValue::construct(out_coeffs)
    }

    fn sub<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, 2, F>,
        b: QuantumExtensionCell<'_, 'v, 2, F>,
    ) -> AssignedExtensionValue<'v, F> {
        let a_coeffs = a.coeffs();
        let b_coeffs = b.coeffs();
        assert_eq!(a_coeffs.len(), b_coeffs.len());
        let mut out_coeffs = Vec::with_capacity(a_coeffs.len());
        for (a, b) in a_coeffs.iter().cloned().zip(b_coeffs.iter().cloned()) {
            let coeff = self.config.range.gate().sub(ctx, a, b);
            out_coeffs.push(coeff);
        }
        AssignedExtensionValue::construct(out_coeffs)
    }

    fn add_base<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedExtensionValue<'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedExtensionValue<'v, F> {
        assert_eq!(a.coeffs.len(), 2);
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        out_coeffs.push(a.coeffs[0].clone());
        let coeff = self.config.range.gate().add(ctx, Existing(&a.coeffs[1]), b);
        out_coeffs.push(coeff);
        AssignedExtensionValue::construct(out_coeffs)
    }

    fn sub_base<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: &AssignedExtensionValue<'v, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedExtensionValue<'v, F> {
        assert_eq!(a.coeffs.len(), 2);
        let mut out_coeffs = Vec::with_capacity(a.coeffs.len());
        out_coeffs.push(a.coeffs[0].clone());
        let coeff = self.config.range.gate().sub(ctx, Existing(&a.coeffs[1]), b);
        out_coeffs.push(coeff);
        AssignedExtensionValue::construct(out_coeffs)
    }

    fn negate<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, 2, F>,
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
        a: QuantumExtensionCell<'_, 'v, 2, F>,
        b: QuantumCell<'_, 'v, F>,
    ) -> AssignedExtensionValue<'v, F> {
        let a_coeffs = a.coeffs();
        assert_eq!(a_coeffs.len(), 2);

        let mut out_coeffs = Vec::with_capacity(2);
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

    /// TODO: `Fp2 = Fp[u] / (u^2 - 7)`
    fn mul<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, 2, F>,
        b: QuantumExtensionCell<'_, 'v, 2, F>,
    ) -> AssignedExtensionValue<'v, F> {
        let a_coeffs = a.coeffs();
        let b_coeffs = b.coeffs();

        // c0 = a0 * b0 + W * a1 * b1
        // c1 = a0 * b1 + a1 * b0

        let mut ab_coeffs = Vec::with_capacity(a_coeffs.len() * b_coeffs.len());
        for i in 0..a_coeffs.len() {
            for j in 0..b_coeffs.len() {
                let coeff =
                    self.config
                        .range
                        .gate()
                        .mul(ctx, a_coeffs[i].clone(), b_coeffs[j].clone());
                ab_coeffs.push(coeff);
            }
        }

        let wa1b1 =
            self.config
                .range
                .gate()
                .mul(ctx, Constant(F::from(7)), Existing(&ab_coeffs[3]));

        let c0 = self
            .config
            .range
            .gate()
            .add(ctx, Existing(&ab_coeffs[0]), Existing(&wa1b1));

        let c1 =
            self.config
                .range
                .gate()
                .add(ctx, Existing(&ab_coeffs[1]), Existing(&ab_coeffs[2]));

        AssignedExtensionValue::construct(vec![c0, c1])
    }

    // a*c + c
    fn mul_add<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: QuantumExtensionCell<'_, 'v, 2, F>,
        b: QuantumExtensionCell<'_, 'v, 2, F>,
        c: QuantumExtensionCell<'_, 'v, 2, F>,
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
        a: QuantumExtensionCell<'_, 'v, 2, F>,
        b: QuantumExtensionCell<'_, 'v, 2, F>,
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
        a: Vec<QuantumExtensionCell<'_, 'v, 2, F>>,
        indicator: Vec<AssignedValue<'v, F>>,
    ) -> AssignedExtensionValue<'v, F> {
        let (a_coeffs_0, a_coeffs_1): (Vec<_>, Vec<_>) = a
            .into_iter()
            .map(|x| {
                let coeffs = x.coeffs();
                (coeffs[0].clone(), coeffs[1].clone())
            })
            .unzip();
        let out = [a_coeffs_0, a_coeffs_1]
            .into_iter()
            .map(|coeffs| {
                self.config.range.gate().select_by_indicator(
                    ctx,
                    coeffs.clone(),
                    indicator.iter().map(|x| x),
                )
            })
            .collect::<Vec<_>>();
        AssignedExtensionValue::construct(vec![out[0].clone(), out[1].clone()])
    }

    fn inner_product<'v>(
        &self,
        ctx: &mut Context<'_, F>,
        a: Vec<AssignedExtensionValue<'v, F>>,
        b: Vec<AssignedExtensionValue<'v, F>>,
    ) -> AssignedExtensionValue<'v, F> {
        let (a_coeffs_0, a_coeffs_1): (Vec<_>, Vec<_>) = a
            .iter()
            .map(|x| (Existing(&x.coeffs[0]), Existing(&x.coeffs[1])))
            .unzip();
        let (b_coeffs_0, b_coeffs_1): (Vec<_>, Vec<_>) = b
            .iter()
            .map(|x| (Existing(&x.coeffs[0]), Existing(&x.coeffs[1])))
            .unzip();
        let out0 = self
            .config
            .range
            .gate()
            .inner_product(ctx, a_coeffs_0, b_coeffs_0);
        let out1 = self
            .config
            .range
            .gate()
            .inner_product(ctx, a_coeffs_1, b_coeffs_1);
        AssignedExtensionValue::construct(vec![out0, out1])
    }
}
