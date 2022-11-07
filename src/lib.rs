use std::marker::PhantomData;

use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        GateInstructions,
    },
    poseidon::PoseidonChip,
    AssignedValue, Context, ContextParams, QuantumCell,
    QuantumCell::{Constant, Witness},
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::*,
};

// FRI PROTOCOL PARAMS
// =========================================================================

#[allow(unused)]
#[derive(Default)]
struct FriProof<F: FieldExt, H: HasherChip<F>> {
    pub layer_commitments: Vec<H::Digest>,
    pub queries: Vec<FriQuery<F, H>>,
    pub options: FriOptions,
}

#[allow(unused)]
#[derive(Default)]
struct FriOptions {
    pub domain_size: usize,
    pub folding_factor: usize,
    pub max_remainder_degree: usize,
}

#[allow(unused)]
struct FriQuery<F: FieldExt, H: HasherChip<F>> {
    pub evaluations: Vec<F>,
    pub merkle_proof: Vec<H::Digest>,
}

// HASHER CHIP
// =========================================================================

struct Digest<F: FieldExt, const N: usize>([F; N]);

trait HasherChip<F: FieldExt> {
    // TODO: Why can't a Deref trait bound be used instead of ToVec?
    type Digest: ToVec<F>;

    fn new(ctx: &mut Context<F>, flex_gate: &FlexGateConfig<F>) -> Self;
    fn hash(
        &mut self,
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        values: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error>;
}

trait ToVec<F> {
    fn to_vec(&self) -> Vec<F>;
}

impl<F: FieldExt, const N: usize> ToVec<F> for Digest<F, N> {
    fn to_vec(&self) -> Vec<F> {
        self.0.to_vec()
    }
}

struct PoseidonChipBn254_8_120<F: FieldExt> {
    inner: PoseidonChip<F, FlexGateConfig<F>, 2, 1020>,
}

// TODO: Fork halo2-base to implement Goldilocks-friendly Poseidon implementation (that can
// return multiple values)
impl<F: FieldExt> HasherChip<F> for PoseidonChipBn254_8_120<F> {
    type Digest = Digest<F, 1>;

    fn new(ctx: &mut Context<F>, flex_gate: &FlexGateConfig<F>) -> Self {
        Self {
            inner: PoseidonChip::<F, FlexGateConfig<F>, 2, 1020>::new(ctx, flex_gate, 8, 120)
                .unwrap(),
        }
    }

    fn hash(
        &mut self,
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        values: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error> {
        self.inner.update(values);
        self.inner.squeeze(ctx, chip)
    }
}

// RANDOM COIN CHIP
// =========================================================================

trait RandomCoinChip<F: FieldExt, H: HasherChip<F>> {
    fn new(seed: AssignedValue<F>, counter: AssignedValue<F>) -> Self;

    fn draw_alpha(
        &mut self,
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        commitment: AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error>;
}

struct RandomCoin<F: FieldExt, H: HasherChip<F>> {
    pub seed: AssignedValue<F>,
    pub counter: AssignedValue<F>,
    _marker: PhantomData<H>,
}

impl<F: FieldExt, H: HasherChip<F>> RandomCoinChip<F, H> for RandomCoin<F, H> {
    fn new(seed: AssignedValue<F>, counter: AssignedValue<F>) -> Self {
        Self {
            seed,
            counter,
            _marker: PhantomData,
        }
    }

    fn draw_alpha(
        &mut self,
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        commitment: AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let mut hasher = H::new(ctx, &chip);
        self.seed = hasher.hash(ctx, chip, &[self.seed.clone(), commitment])?;
        let alpha = hasher.hash(ctx, chip, &[self.seed.clone(), self.counter.clone()]);
        alpha
    }
}

// MERKLE TREE CHIP
// =========================================================================

#[allow(dead_code)]
struct MerkleTreeChip<F: FieldExt, H: HasherChip<F>> {
    _marker: PhantomData<(F, H)>,
}

impl<F: FieldExt, H: HasherChip<F>> MerkleTreeChip<F, H> {
    fn new(ctx: &mut Context<F>, chip: &FlexGateConfig<F>) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    // TODO: Make root, proof, and leaf generic
    #[allow(unused)]
    fn verify_merkle_proof(
        ctx: &mut Context<'_, F>,
        root: AssignedValue<F>,
        proof: Vec<AssignedValue<F>>,
        leaf: AssignedValue<F>,
        index: AssignedValue<F>,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

// FRI VERIFIER CHIP
// =========================================================================

#[allow(dead_code)]
#[derive(Clone)]
struct VerifierChipConfig<F: FieldExt> {
    pub gate_config: FlexGateConfig<F>,
    pub instance: Column<Instance>,
}

#[allow(dead_code)]
struct VerifierChip<F: FieldExt, H: HasherChip<F>, C: RandomCoinChip<F, H>> {
    config: VerifierChipConfig<F>,
    _marker: PhantomData<(H, C)>,
}

impl<F: FieldExt, H: HasherChip<F>, C: RandomCoinChip<F, H>> VerifierChip<F, H, C> {
    fn from_config(config: VerifierChipConfig<F>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        instance: Column<Instance>,
    ) -> VerifierChipConfig<F> {
        VerifierChipConfig {
            gate_config: FlexGateConfig::configure(
                meta,
                GateStrategy::PlonkPlus,
                &[NUM_ADVICE],
                1,
                "default".to_string(),
            ),
            instance,
        }
    }

    fn verify_proof(
        &self,
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        proof: &FriProof<F, H>,
        public_coin_seed: F,
    ) -> Result<(), Error> {
        // Use the public coin to generate alphas from the layer commitments
        let layer_commitments = proof
            .layer_commitments
            .iter()
            .map(|x| {
                Ok(chip
                    .assign_region(
                        ctx,
                        x.to_vec()
                            .into_iter()
                            .map(|x_| Constant(x_))
                            .collect::<Vec<QuantumCell<F>>>(),
                        vec![],
                        None,
                    )?
                    .pop()
                    .unwrap())
            })
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;
        let alphas =
            self.draw_alphas(ctx, chip, Value::known(public_coin_seed), layer_commitments)?;

        // Execute FRI verification protocol for each query round
        for _ in 0..proof.queries.len() {
            let layer_values = self.layer_values(ctx, vec![])?;
            self.evaluate_polynomials(ctx, &alphas, vec![])?;
            self.verify_remainder(ctx, vec![], proof.options.max_remainder_degree);
        }

        Ok(())
    }

    /// Reconstruct the alphas used at each step of the FRI commit phase using the
    /// Merkle commitments for the layers
    #[allow(unused)]
    fn draw_alphas(
        &self,
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        initial_seed: Value<F>,
        commitments: Vec<AssignedValue<F>>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        let (seed, counter) = {
            let cells = self.config.gate_config.assign_region_smart(
                ctx,
                vec![Witness(initial_seed), Constant(F::from(0))],
                vec![],
                vec![],
                vec![],
            )?;
            (cells[0].clone(), cells[1].clone())
        };
        let mut public_coin_chip = C::new(seed, counter);
        let mut alphas = vec![];
        for commitment in commitments {
            let alpha = public_coin_chip.draw_alpha(ctx, chip, commitment)?;
            alphas.push(alpha);
        }
        Ok(alphas)
    }

    /// Check that claimed evaluations match the FRI query values in the Merkle tree
    #[allow(unused)]
    fn layer_values(
        &self,
        ctx: &mut Context<'_, F>,
        evaluations: Vec<F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        // TODO
        Ok(vec![])
    }

    /// Interpolate the evalutions into polynomials, and evaluate at alpha
    #[allow(unused)]
    fn evaluate_polynomials(
        &self,
        ctx: &mut Context<'_, F>,
        alphas: &[AssignedValue<F>],
        evaluations: Vec<F>,
    ) -> Result<Vec<AssignedValue<F>>, Error> {
        // TODO
        Ok(vec![])
    }

    /// Interpolate the remainder evaluations into a polynomial, and check that its degree
    /// is less than or equal to `max_degree`
    #[allow(unused)]
    fn verify_remainder(
        &self,
        ctx: &mut Context<'_, F>,
        remainder_evaluations: Vec<F>,
        max_degree: usize,
    ) {
        // TODO
    }
}

// CIRCUIT
// =========================================================================

const NUM_ADVICE: usize = 1;

struct FriVerifierCircuit<F: FieldExt, H: HasherChip<F>, C: RandomCoinChip<F, H>> {
    pub proof: Option<FriProof<F, H>>,
    pub public_coin_seed: F,
    _marker: PhantomData<(C, H)>,
}

impl<F, H, C> Default for FriVerifierCircuit<F, H, C>
where
    F: FieldExt,
    H: HasherChip<F>,
    C: RandomCoinChip<F, H>,
{
    fn default() -> Self {
        Self {
            proof: None,
            public_coin_seed: F::default(),
            _marker: PhantomData,
        }
    }
}

impl<F, H, C> Circuit<F> for FriVerifierCircuit<F, H, C>
where
    F: FieldExt,
    H: HasherChip<F>,
    C: RandomCoinChip<F, H>,
{
    type Config = VerifierChipConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        VerifierChip::<F, H, C>::configure(meta, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let verifier_chip = VerifierChip::<F, H, C>::from_config(config);

        layouter.assign_region(
            || "gate",
            |region| {
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![("default".to_string(), NUM_ADVICE)],
                    },
                );

                verifier_chip.verify_proof(
                    &mut ctx,
                    &verifier_chip.config.gate_config,
                    &self.proof.as_ref().unwrap(),
                    self.public_coin_seed,
                )?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

    #[test]
    fn test() {
        let options = FriOptions {
            domain_size: 2,
            folding_factor: 2,
            max_remainder_degree: 256,
        };
        let proof = FriProof {
            layer_commitments: vec![],
            queries: vec![],
            options,
        };

        // Random coin
        let public_coin_seed = Fr::from(1);

        let circuit = FriVerifierCircuit::<
            Fr,
            PoseidonChipBn254_8_120<Fr>,
            RandomCoin<Fr, PoseidonChipBn254_8_120<Fr>>,
        > {
            proof: Some(proof),
            public_coin_seed,
            _marker: PhantomData,
        };

        //let public_input = vec![];
        let prover = MockProver::run(10, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}

//// HASH FUNCTIONS
//// =========================================================================
//// TODO: Use implementations in external crates
//
//trait Hasher {
//    type Digest;
//
//    fn hash(bytes: &[u8]) -> Self::Digest;
//    fn merge<F>(values: [Self::Digest; 2]) -> Self::Digest;
//}
//
//struct Poseidon {}
//
//impl Hasher for Poseidon {
//    type Digest = [u8; 32];
//
//    fn hash(bytes: &[u8]) -> Self::Digest {
//        Self::Digest::default()
//    }
//    fn merge<F>(values: [Self::Digest; 2]) -> Self::Digest {
//        Self::Digest::default()
//    }
//}
