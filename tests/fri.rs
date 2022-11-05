mod tests {
    use winter_crypto::hashers::Blake3_256;
    use winter_fri::{DefaultProverChannel, FriOptions, FriProver};
    use winter_math::{fft, fields::f64::BaseElement, FieldElement};

    type HashFn = Blake3_256<BaseElement>;

    fn test_fri() {
        let trace_length = 1024;
        let blowup_factor = 2;
        let num_queries = 56;

        let options = FriOptions::new(
            blowup_factor,
            4, // folding factor
            4, // max remainder size
        );

        let mut channel = DefaultProverChannel::<BaseElement, BaseElement, HashFn>::new(
            blowup_factor * trace_length,
            num_queries,
        );

        // Evaluations
        let domain_size = trace_length * blowup_factor;
        let mut evaluations = (0..trace_length as u64)
            .map(BaseElement::new)
            .collect::<Vec<_>>();
        evaluations.resize(domain_size, BaseElement::ZERO);
        let twiddles = fft::get_twiddles::<BaseElement>(domain_size);
        fft::evaluate_poly(&mut evaluations, &twiddles);

        let mut prover = FriProver::new(options);
        prover.build_layers(&mut channel, evaluations.clone());
        let positions = channel.draw_query_positions();
        let proof = prover.build_proof(&positions);
    }
}
