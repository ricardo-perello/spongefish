//! Plain and preprocessing DSFS compilers for interactive arguments.

use ia_core::{
    ArgumentCore, ArgumentProverCore, CommittedIndex, Encoding, IndexedInstanceRef,
    InteractiveArgumentProver, InteractiveArgumentVerifier, NargDeserialize, NargProof,
    NonInteractiveArgumentProver, NonInteractiveArgumentVerifier,
    PreprocessingInteractiveArgumentProver, PreprocessingInteractiveArgumentVerifier,
    PreprocessingNonInteractiveArgumentProver, PreprocessingNonInteractiveArgumentVerifier,
    VerificationResult,
};

use super::{
    ArgumentProver, ArgumentVerifier, FramedInstance, PreprocessingArgumentProver,
    PreprocessingArgumentVerifier,
};
use crate::params::SpongeInfo;
use crate::session::{prove_session, verify_session};

/// Compile a plain interactive argument prover with no salt.
#[must_use]
pub const fn argument_prover<P, S, DS>(
    prover: P,
    duplex_sponge: DS,
) -> ArgumentProver<P, S, DS, 0> {
    ArgumentProver::new(prover, duplex_sponge)
}

/// Compile a salted plain interactive argument prover.
#[must_use]
pub const fn argument_prover_with_salt<P, S, DS, const SALT_LEN: usize>(
    prover: P,
    duplex_sponge: DS,
) -> ArgumentProver<P, S, DS, SALT_LEN> {
    ArgumentProver::new(prover, duplex_sponge)
}

/// Compile a plain interactive argument verifier with no salt.
#[must_use]
pub const fn argument_verifier<V, S, DS>(
    verifier: V,
    duplex_sponge: DS,
) -> ArgumentVerifier<V, S, DS, 0> {
    ArgumentVerifier::new(verifier, duplex_sponge)
}

/// Compile a salted plain interactive argument verifier.
#[must_use]
pub const fn argument_verifier_with_salt<V, S, DS, const SALT_LEN: usize>(
    verifier: V,
    duplex_sponge: DS,
) -> ArgumentVerifier<V, S, DS, SALT_LEN> {
    ArgumentVerifier::new(verifier, duplex_sponge)
}

impl<P, S, DS, const SALT_LEN: usize> ArgumentCore for ArgumentProver<P, S, DS, SALT_LEN>
where
    P: ArgumentCore,
{
    type Instance = P::Instance;
}

impl<P, S, DS, const SALT_LEN: usize> ArgumentProverCore for ArgumentProver<P, S, DS, SALT_LEN>
where
    P: ArgumentProverCore,
{
    type Witness = P::Witness;
}

impl<P, S, DS, const SALT_LEN: usize> NonInteractiveArgumentProver
    for ArgumentProver<P, S, DS, SALT_LEN>
where
    DS: SpongeInfo + Clone,
    P: InteractiveArgumentProver,
    S: Encoding<[u8]>,
    P::Instance: Encoding<[DS::U]>,
    [u8; SALT_LEN]: Encoding<[DS::U]>,
{
    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> NargProof {
        prove_session::<_, DS, S, _, SALT_LEN>(
            self.duplex_sponge.clone(),
            self.argument.protocol_id(),
            session,
            &FramedInstance(instance),
            |ch| self.argument.prove(ch, instance, witness),
        )
        .0
    }
}

impl<V, S, DS, const SALT_LEN: usize> ArgumentCore for ArgumentVerifier<V, S, DS, SALT_LEN>
where
    V: ArgumentCore,
{
    type Instance = V::Instance;
}

impl<V, S, DS, const SALT_LEN: usize> NonInteractiveArgumentVerifier
    for ArgumentVerifier<V, S, DS, SALT_LEN>
where
    DS: SpongeInfo + Clone,
    V: InteractiveArgumentVerifier,
    S: Encoding<[u8]>,
    V::Instance: Encoding<[DS::U]>,
    [u8; SALT_LEN]: Encoding<[DS::U]> + NargDeserialize,
{
    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &NargProof,
    ) -> VerificationResult<()> {
        verify_session::<_, DS, S, _, SALT_LEN>(
            self.duplex_sponge.clone(),
            self.argument.protocol_id(),
            session,
            &FramedInstance(instance),
            proof.as_bytes(),
            |ch| self.argument.verify(ch, instance),
        )
    }
}

/// Compile a preprocessing argument prover with no salt.
#[must_use]
pub const fn preprocessing_argument_prover<P, S, DS>(
    prover: P,
    duplex_sponge: DS,
) -> PreprocessingArgumentProver<P, S, DS, 0> {
    PreprocessingArgumentProver::new(prover, duplex_sponge)
}

/// Compile a salted preprocessing argument prover.
#[must_use]
pub const fn preprocessing_argument_prover_with_salt<
    P,
    S,
    DS,
    const SALT_LEN: usize,
>(
    prover: P,
    duplex_sponge: DS,
) -> PreprocessingArgumentProver<P, S, DS, SALT_LEN> {
    PreprocessingArgumentProver::new(prover, duplex_sponge)
}

/// Compile a preprocessing argument verifier with no salt.
#[must_use]
pub const fn preprocessing_argument_verifier<V, S, DS>(
    verifier: V,
    duplex_sponge: DS,
) -> PreprocessingArgumentVerifier<V, S, DS, 0> {
    PreprocessingArgumentVerifier::new(verifier, duplex_sponge)
}

/// Compile a salted preprocessing argument verifier.
#[must_use]
pub const fn preprocessing_argument_verifier_with_salt<
    V,
    S,
    DS,
    const SALT_LEN: usize,
>(
    verifier: V,
    duplex_sponge: DS,
) -> PreprocessingArgumentVerifier<V, S, DS, SALT_LEN> {
    PreprocessingArgumentVerifier::new(verifier, duplex_sponge)
}

impl<P, S, DS, const SALT_LEN: usize> ArgumentCore
    for PreprocessingArgumentProver<P, S, DS, SALT_LEN>
where
    P: ArgumentCore,
{
    type Instance = P::Instance;
}

impl<P, S, DS, const SALT_LEN: usize> ArgumentProverCore
    for PreprocessingArgumentProver<P, S, DS, SALT_LEN>
where
    P: ArgumentProverCore,
{
    type Witness = P::Witness;
}

impl<P, S, DS, const SALT_LEN: usize> PreprocessingNonInteractiveArgumentProver
    for PreprocessingArgumentProver<P, S, DS, SALT_LEN>
where
    DS: SpongeInfo + Clone,
    P: PreprocessingInteractiveArgumentProver,
    S: Encoding<[u8]>,
    P::Instance: Encoding<[u8]>,
    [u8; SALT_LEN]: Encoding<[DS::U]>,
{
    type ProverKey = P::ProverKey;

    fn prove(
        &self,
        prover_key: &Self::ProverKey,
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> NargProof {
        let committed_index = prover_key.committed_index();
        let public_input = IndexedInstanceRef::new(&committed_index, instance);
        prove_session::<_, DS, S, _, SALT_LEN>(
            self.duplex_sponge.clone(),
            self.argument.protocol_id(),
            session,
            &public_input,
            |ch| self.argument.prove(ch, prover_key, instance, witness),
        )
        .0
    }
}

impl<V, S, DS, const SALT_LEN: usize> ArgumentCore
    for PreprocessingArgumentVerifier<V, S, DS, SALT_LEN>
where
    V: ArgumentCore,
{
    type Instance = V::Instance;
}

impl<V, S, DS, const SALT_LEN: usize> PreprocessingNonInteractiveArgumentVerifier
    for PreprocessingArgumentVerifier<V, S, DS, SALT_LEN>
where
    DS: SpongeInfo + Clone,
    V: PreprocessingInteractiveArgumentVerifier,
    S: Encoding<[u8]>,
    V::Instance: Encoding<[u8]>,
    [u8; SALT_LEN]: Encoding<[DS::U]> + NargDeserialize,
{
    type VerifierKey = V::VerifierKey;

    fn verify(
        &self,
        verifier_key: &Self::VerifierKey,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &NargProof,
    ) -> VerificationResult<()> {
        let committed_index = verifier_key.committed_index();
        let public_input = IndexedInstanceRef::new(&committed_index, instance);
        verify_session::<_, DS, S, _, SALT_LEN>(
            self.duplex_sponge.clone(),
            self.argument.protocol_id(),
            session,
            &public_input,
            proof.as_bytes(),
            |ch| self.argument.verify(ch, verifier_key, instance),
        )
    }
}
