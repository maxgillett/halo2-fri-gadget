use crate::fields::AssignedExtensionValue;
use crate::hash::{Digest, HasherChip, HasherChipDigest};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    AssignedValue, Context,
    QuantumCell::Existing,
};
use halo2_proofs::{arithmetic::FieldExt, plonk::*};
use std::marker::PhantomData;

// MERKLE TREE CHIP
// =========================================================================

pub struct MerkleTreeChip<const N: usize, F: FieldExt, H: HasherChip<F>> {
    _marker: PhantomData<(F, H)>,
}

impl<const N: usize, F: FieldExt, H> MerkleTreeChip<N, F, H>
where
    H: for<'v> HasherChip<F, Digest<'v> = Digest<'v, F, N>>,
{
    pub fn get_root<'v>(
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        hasher_chip: &'v H,
        leaves: &[H::Digest<'v>],
    ) -> Result<H::Digest<'v>, Error> {
        let depth = leaves.len().ilog2();
        let mut nodes = leaves.to_vec();
        for _ in 0..depth {
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    // Hash digests
                    let elements = pair
                        .to_vec()
                        .iter()
                        .flat_map(|x| x.0.to_vec())
                        .collect::<Vec<_>>();
                    hasher_chip
                        .hash_elements(ctx, main_chip, &elements)
                        .unwrap()
                })
                .collect::<Vec<_>>();
        }
        Ok(nodes[0].clone())
    }

    pub fn verify_merkle_proof<'v>(
        ctx: &mut Context<'_, F>,
        main_chip: &FlexGateConfig<F>,
        hasher_chip: &H,
        root: &H::Digest<'v>,
        index_bits: &[AssignedValue<F>],
        leaves: &[AssignedExtensionValue<'_, F>],
        proof: &[H::Digest<'v>],
    ) -> Result<(), Error> {
        // Hash leaves to a single digest
        let mut digest = hasher_chip.hash_elements(
            ctx,
            main_chip,
            &leaves.iter().flat_map(|x| x.coeffs()).collect::<Vec<_>>(),
        )?;
        for (bit, sibling) in index_bits.iter().zip(proof.iter().skip(1)) {
            let mut values = vec![];
            let a = sibling
                .to_assigned()
                .iter()
                .zip(digest.0.iter())
                .map(|(s, d)| main_chip.select(ctx, Existing(&s), Existing(&d), Existing(&bit)))
                .collect::<Vec<_>>();
            let b = sibling
                .to_assigned()
                .iter()
                .zip(digest.0.iter())
                .map(|(s, d)| main_chip.select(ctx, Existing(&d), Existing(&s), Existing(&bit)))
                .collect::<Vec<_>>();
            values.extend(a);
            values.extend(b);
            digest = hasher_chip.hash_elements(ctx, main_chip, &values)?;
        }

        for (e1, e2) in root.to_assigned().iter().zip(digest.to_assigned().iter()) {
            ctx.constrain_equal(e1, e2);
        }

        Ok(())
    }
}
