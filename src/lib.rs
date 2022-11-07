use std::marker::PhantomData;

use halo2_base::{
    gates::{
        flex_gate::{FlexGateConfig, GateStrategy},
        GateInstructions,
    },
    AssignedValue, Context, ContextParams, QuantumCell,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::*,
    poly::Rotation,
};

use halo2_proofs::halo2curves::bn256::Fr;

// FRI PROTOCOL PARAMS
// =========================================================================

#[allow(unused)]
#[derive(Default)]
struct FriProof<F: FieldExt> {
    pub layer_commitments: Vec<Digest>,
    pub queries: Vec<FriQuery<F>>, //, H>>,
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
struct FriQuery<F: FieldExt> {
    pub evaluations: Vec<F>,
    pub merkle_proof: Vec<Digest>, // siblings
}

// HASH FUNCTIONS
// =========================================================================

trait Hasher: Clone {
    type Digest: Default;

    fn hash(bytes: &[u8]) -> Self::Digest;
    fn merge<F>(values: [Self::Digest; 2]) -> Self::Digest;
}

#[derive(Clone, Default)]
struct Poseidon {
    // TODO
}

impl Hasher for Poseidon {
    type Digest = [u8; 32];

    fn hash(bytes: &[u8]) -> Self::Digest {
        Self::Digest::default()
    }
    fn merge<F>(values: [Self::Digest; 2]) -> Self::Digest {
        Self::Digest::default()
    }
}

// HASHER CHIP
// =========================================================================

type Digest = [u8; 32];

trait HasherChip<F: FieldExt>: Clone {
    //type Digest;

    fn new(ctx: &mut Context<F>, flex_gate: &FlexGateConfig<F>) -> Self;
    fn hash(
        &self,
        ctx: &mut Context<'_, F>,
        values: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error>;
}

#[derive(Clone)]
struct PoseidonChipConfig {
    // TODO
}

#[derive(Clone)]
struct PoseidonChip {
    // TODO
}

#[allow(unused)]
impl<F: FieldExt> HasherChip<F> for PoseidonChip {
    //type Digest = F;

    fn new(ctx: &mut Context<F>, flex_gate: &FlexGateConfig<F>) -> Self {
        Self {}
    }

    fn hash(
        &self,
        ctx: &mut Context<'_, F>,
        values: &[AssignedValue<F>],
    ) -> Result<AssignedValue<F>, Error> {
        unimplemented!()
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
    fn verify_merkle_proof(
        ctx: &mut Context<'_, F>,
        root: AssignedValue<F>,
        proof: Vec<AssignedValue<F>>,
        leaf: AssignedValue<F>,
        index: AssignedValue<F>,
    ) -> Result<(), Error> {
        //for sibling in proof {}
        unimplemented!()
    }
}

// RANDOM COIN CHIP
// =========================================================================

trait RandomCoinChip<F: FieldExt, H: HasherChip<F>>: Clone {
    fn new(
        ctx: &mut Context<'_, F>,
        flex_gate: &FlexGateConfig<F>,
        seed: AssignedValue<F>,
        counter: AssignedValue<F>,
    ) -> Self;

    fn draw_alpha(
        &mut self,
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        commitment: AssignedValue<F>,
    ) -> Result<AssignedValue<F>, Error>;
}

#[derive(Clone)]
struct RandomCoin<F: FieldExt, H: HasherChip<F>> {
    pub seed: AssignedValue<F>,
    pub counter: AssignedValue<F>,
    _marker: PhantomData<H>,
}

impl<F: FieldExt, H: HasherChip<F>> RandomCoinChip<F, H> for RandomCoin<F, H> {
    fn new(
        ctx: &mut Context<F>,
        chip: &FlexGateConfig<F>,
        seed: AssignedValue<F>,
        counter: AssignedValue<F>,
    ) -> Self {
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
        let hasher = H::new(ctx, &chip);
        self.seed = hasher.hash(ctx, &[self.seed.clone(), commitment])?;
        let alpha = hasher.hash(ctx, &[self.seed.clone(), self.counter.clone()]);
        alpha
    }
}

// FRI VERIFIER CHIP
// =========================================================================

#[allow(dead_code)]
#[derive(Clone)]
struct VerifierChipConfig<F: FieldExt, H: HasherChip<F>, C: RandomCoinChip<F, H>> {
    pub gate_config: FlexGateConfig<F>,
    pub instance: Column<Instance>,
    _marker: PhantomData<(C, H)>,
}

#[allow(dead_code)]
struct VerifierChip<F: FieldExt, H: HasherChip<F>, C: RandomCoinChip<F, H>> {
    config: VerifierChipConfig<F, H, C>,
    _marker: PhantomData<C>,
}

impl<F: FieldExt, H: HasherChip<F>, C: RandomCoinChip<F, H>> VerifierChip<F, H, C> {
    fn from_config(config: VerifierChipConfig<F, H, C>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        instance: Column<Instance>,
    ) -> VerifierChipConfig<F, H, C> {
        VerifierChipConfig {
            gate_config: FlexGateConfig::configure(
                meta,
                GateStrategy::PlonkPlus,
                &[NUM_ADVICE],
                1,
                "default".to_string(),
            ),
            instance,
            _marker: PhantomData,
        }
    }

    fn verify_proof(
        &self,
        ctx: &mut Context<'_, F>,
        chip: &FlexGateConfig<F>,
        proof: &FriProof<F>, //, Digest>,
        public_coin_seed: F,
    ) -> Result<(), Error> {
        let layer_commitments = proof
            .layer_commitments
            .iter()
            .map(|x| {
                // TODO: Correctly construct field element from bytes
                Ok(chip
                    .assign_region(ctx, vec![Constant(F::from(0))], vec![], None)?
                    .pop()
                    .unwrap())
            })
            .collect::<Result<Vec<AssignedValue<F>>, Error>>()?;

        let layer_alphas =
            self.layer_alphas(ctx, chip, Value::known(public_coin_seed), layer_commitments)?;

        // Execute FRI verification protocol for each query round
        for _ in 0..proof.queries.len() {
            let layer_values = self.layer_values(ctx, vec![])?;
            self.evaluate_polynomials(ctx, &layer_alphas, vec![])?;
            self.verify_remainder(ctx, vec![], proof.options.max_remainder_degree);
        }

        Ok(())
    }

    /// Reconstruct the alphas used at each step of the FRI commit phase using the
    /// Merkle commitments for the layers
    #[allow(unused)]
    fn layer_alphas(
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
        let mut public_coin_chip = C::new(ctx, &self.config.gate_config, seed, counter);
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
    pub proof: FriProof<F>, //, Digest>,
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
            proof: FriProof::default(),
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
    type Config = VerifierChipConfig<F, H, C>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        VerifierChip::configure(meta, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let verifier_chip = VerifierChip::from_config(config);

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
                    &verifier_chip.config.gate_config, //&config.gate_config,
                    &self.proof,
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

        let circuit = FriVerifierCircuit::<Fr, PoseidonChip, RandomCoin<Fr, PoseidonChip>> {
            proof,
            public_coin_seed,
            _marker: PhantomData,
        };

        //let public_input = vec![];
        let prover = MockProver::run(10, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
