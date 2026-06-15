//! Plain and preprocessing DSFS compilers for interactive reductions.

use ia_core::{
    CommittedIndex, Encoding, IndexedInstanceRef, InteractiveReductionProver,
    InteractiveReductionVerifier, NargDeserialize, NargProof, NonInteractiveReductionProver,
    NonInteractiveReductionVerifier, PreprocessingInteractiveReductionProver,
    PreprocessingInteractiveReductionVerifier, PreprocessingNonInteractiveReductionProver,
    PreprocessingNonInteractiveReductionVerifier, ReductionCore, ReductionProverCore,
    VerificationResult,
};

use super::{
    FramedInstance, PreprocessingReductionProver, PreprocessingReductionVerifier, ReductionProver,
    ReductionVerifier,
};
use crate::params::SpongeInfo;
use crate::session::{prove_session, verify_session};

/// Compile a plain interactive reduction prover with no salt.
#[must_use]
pub const fn reduction_prover<P, S, DS>(
    prover: P,
    duplex_sponge: DS,
) -> ReductionProver<P, S, DS, 0> {
    ReductionProver::new(prover, duplex_sponge)
}

/// Compile a salted plain interactive reduction prover.
#[must_use]
pub const fn reduction_prover_with_salt<P, S, DS, const SALT_LEN: usize>(
    prover: P,
    duplex_sponge: DS,
) -> ReductionProver<P, S, DS, SALT_LEN> {
    ReductionProver::new(prover, duplex_sponge)
}

/// Compile a plain interactive reduction verifier with no salt.
#[must_use]
pub const fn reduction_verifier<V, S, DS>(
    verifier: V,
    duplex_sponge: DS,
) -> ReductionVerifier<V, S, DS, 0> {
    ReductionVerifier::new(verifier, duplex_sponge)
}

/// Compile a salted plain interactive reduction verifier.
#[must_use]
pub const fn reduction_verifier_with_salt<V, S, DS, const SALT_LEN: usize>(
    verifier: V,
    duplex_sponge: DS,
) -> ReductionVerifier<V, S, DS, SALT_LEN> {
    ReductionVerifier::new(verifier, duplex_sponge)
}

impl<P, S, DS, const SALT_LEN: usize> ReductionCore for ReductionProver<P, S, DS, SALT_LEN>
where
    P: ReductionCore,
{
    type SourceInstance = P::SourceInstance;
    type TargetInstance = P::TargetInstance;
}

impl<P, S, DS, const SALT_LEN: usize> ReductionProverCore for ReductionProver<P, S, DS, SALT_LEN>
where
    P: ReductionProverCore,
{
    type SourceWitness = P::SourceWitness;
    type TargetWitness = P::TargetWitness;
}

impl<P, S, DS, const SALT_LEN: usize> NonInteractiveReductionProver
    for ReductionProver<P, S, DS, SALT_LEN>
where
    DS: SpongeInfo + Clone,
    P: InteractiveReductionProver,
    S: Encoding<[u8]>,
    P::SourceInstance: Encoding<[DS::U]>,
    [u8; SALT_LEN]: Encoding<[DS::U]>,
{
    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (NargProof, Self::TargetInstance, Self::TargetWitness) {
        let (proof, (target_instance, target_witness)) = prove_session::<_, DS, S, _, SALT_LEN>(
            self.duplex_sponge.clone(),
            self.reduction.protocol_id(),
            session,
            &FramedInstance(instance),
            |ch| self.reduction.prove(ch, instance, witness),
        );
        (proof, target_instance, target_witness)
    }
}

impl<V, S, DS, const SALT_LEN: usize> ReductionCore for ReductionVerifier<V, S, DS, SALT_LEN>
where
    V: ReductionCore,
{
    type SourceInstance = V::SourceInstance;
    type TargetInstance = V::TargetInstance;
}

impl<V, S, DS, const SALT_LEN: usize> NonInteractiveReductionVerifier
    for ReductionVerifier<V, S, DS, SALT_LEN>
where
    DS: SpongeInfo + Clone,
    V: InteractiveReductionVerifier,
    S: Encoding<[u8]>,
    V::SourceInstance: Encoding<[DS::U]>,
    [u8; SALT_LEN]: Encoding<[DS::U]> + NargDeserialize,
{
    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        proof: &NargProof,
    ) -> VerificationResult<Self::TargetInstance> {
        verify_session::<_, DS, S, _, SALT_LEN>(
            self.duplex_sponge.clone(),
            self.reduction.protocol_id(),
            session,
            &FramedInstance(instance),
            proof.as_bytes(),
            |ch| self.reduction.verify(ch, instance),
        )
    }
}

/// Compile a preprocessing reduction prover with no salt.
#[must_use]
pub const fn preprocessing_reduction_prover<P, S, DS>(
    prover: P,
    duplex_sponge: DS,
) -> PreprocessingReductionProver<P, S, DS, 0> {
    PreprocessingReductionProver::new(prover, duplex_sponge)
}

/// Compile a salted preprocessing reduction prover.
#[must_use]
pub const fn preprocessing_reduction_prover_with_salt<P, S, DS, const SALT_LEN: usize>(
    prover: P,
    duplex_sponge: DS,
) -> PreprocessingReductionProver<P, S, DS, SALT_LEN> {
    PreprocessingReductionProver::new(prover, duplex_sponge)
}

/// Compile a preprocessing reduction verifier with no salt.
#[must_use]
pub const fn preprocessing_reduction_verifier<V, S, DS>(
    verifier: V,
    duplex_sponge: DS,
) -> PreprocessingReductionVerifier<V, S, DS, 0> {
    PreprocessingReductionVerifier::new(verifier, duplex_sponge)
}

/// Compile a salted preprocessing reduction verifier.
#[must_use]
pub const fn preprocessing_reduction_verifier_with_salt<V, S, DS, const SALT_LEN: usize>(
    verifier: V,
    duplex_sponge: DS,
) -> PreprocessingReductionVerifier<V, S, DS, SALT_LEN> {
    PreprocessingReductionVerifier::new(verifier, duplex_sponge)
}

impl<P, S, DS, const SALT_LEN: usize> ReductionCore
    for PreprocessingReductionProver<P, S, DS, SALT_LEN>
where
    P: ReductionCore,
{
    type SourceInstance = P::SourceInstance;
    type TargetInstance = P::TargetInstance;
}

impl<P, S, DS, const SALT_LEN: usize> ReductionProverCore
    for PreprocessingReductionProver<P, S, DS, SALT_LEN>
where
    P: ReductionProverCore,
{
    type SourceWitness = P::SourceWitness;
    type TargetWitness = P::TargetWitness;
}

impl<P, S, DS, const SALT_LEN: usize> PreprocessingNonInteractiveReductionProver
    for PreprocessingReductionProver<P, S, DS, SALT_LEN>
where
    DS: SpongeInfo + Clone,
    P: PreprocessingInteractiveReductionProver,
    S: Encoding<[u8]>,
    P::SourceInstance: Encoding<[u8]>,
    [u8; SALT_LEN]: Encoding<[DS::U]>,
{
    type ProverKey = P::ProverKey;

    fn prove(
        &self,
        prover_key: &Self::ProverKey,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (NargProof, Self::TargetInstance, Self::TargetWitness) {
        let committed_index = prover_key.committed_index();
        let public_input = IndexedInstanceRef::new(&committed_index, instance);
        let (proof, (target_instance, target_witness)) = prove_session::<_, DS, S, _, SALT_LEN>(
            self.duplex_sponge.clone(),
            self.reduction.protocol_id(),
            session,
            &public_input,
            |ch| self.reduction.prove(ch, prover_key, instance, witness),
        );
        (proof, target_instance, target_witness)
    }
}

impl<V, S, DS, const SALT_LEN: usize> ReductionCore
    for PreprocessingReductionVerifier<V, S, DS, SALT_LEN>
where
    V: ReductionCore,
{
    type SourceInstance = V::SourceInstance;
    type TargetInstance = V::TargetInstance;
}

impl<V, S, DS, const SALT_LEN: usize> PreprocessingNonInteractiveReductionVerifier
    for PreprocessingReductionVerifier<V, S, DS, SALT_LEN>
where
    DS: SpongeInfo + Clone,
    V: PreprocessingInteractiveReductionVerifier,
    S: Encoding<[u8]>,
    V::SourceInstance: Encoding<[u8]>,
    [u8; SALT_LEN]: Encoding<[DS::U]> + NargDeserialize,
{
    type VerifierKey = V::VerifierKey;

    fn verify(
        &self,
        verifier_key: &Self::VerifierKey,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        proof: &NargProof,
    ) -> VerificationResult<Self::TargetInstance> {
        let committed_index = verifier_key.committed_index();
        let public_input = IndexedInstanceRef::new(&committed_index, instance);
        verify_session::<_, DS, S, _, SALT_LEN>(
            self.duplex_sponge.clone(),
            self.reduction.protocol_id(),
            session,
            &public_input,
            proof.as_bytes(),
            |ch| self.reduction.verify(ch, verifier_key, instance),
        )
    }
}
