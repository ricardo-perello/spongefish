//! Role-specific DSFS compiler wrappers.

extern crate alloc;

use core::marker::PhantomData;

use ia_core::{
    ArgumentCore, ArgumentProverCore, CommittedIndex, Encoding, InteractiveArgumentProver,
    InteractiveArgumentVerifier, InteractiveReductionProver, InteractiveReductionVerifier,
    NargDeserialize, NargProof, NonInteractiveArgumentProver, NonInteractiveArgumentVerifier,
    NonInteractiveReductionProver, NonInteractiveReductionVerifier, NonInteractiveSession,
    PreprocessingInteractiveArgumentProver, PreprocessingInteractiveArgumentVerifier,
    PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
    PreprocessingNonInteractiveArgumentProver, PreprocessingNonInteractiveArgumentVerifier,
    PreprocessingNonInteractiveReductionProver, PreprocessingNonInteractiveReductionVerifier,
    ProtocolCore, ReductionCore, ReductionProverCore, VerificationResult,
};
use rand::RngCore;
use spongefish::{DomainSeparator, DuplexSpongeInterface};

use crate::{
    channel::{SpongeProver, SpongeVerifier},
    params::{Keccak, SpongeInfo},
    runners::{
        prepared_prove_reduction_with_sponge_and_salt, prepared_prove_with_sponge_and_salt,
        prepared_verify_reduction_with_sponge_and_salt, prepared_verify_with_sponge_and_salt,
    },
};

/// Byte-oriented duplex sponge (`U = u8`).
pub trait ByteDuplexSponge: DuplexSpongeInterface<U = u8> {}

impl<T: DuplexSpongeInterface<U = u8>> ByteDuplexSponge for T {}

macro_rules! role_wrapper {
    ($name:ident, $field:ident) => {
        /// A DSFS-compiled executable role.
        ///
        /// Construct this wrapper through the corresponding semantic constructor
        /// rather than depending on its storage layout.
        pub struct $name<P, S, DS = Keccak, const SALT_LEN: usize = 0> {
            $field: P,
            duplex_sponge: DS,
            _session: PhantomData<S>,
        }

        impl<P, S, DS, const SALT_LEN: usize> $name<P, S, DS, SALT_LEN> {
            #[must_use]
            pub const fn new($field: P, duplex_sponge: DS) -> Self {
                Self {
                    $field,
                    duplex_sponge,
                    _session: PhantomData,
                }
            }
        }

        impl<P, S, DS, const SALT_LEN: usize> ProtocolCore for $name<P, S, DS, SALT_LEN>
        where
            P: ProtocolCore,
        {
            fn protocol_id(&self) -> impl AsRef<[u8]> {
                self.$field.protocol_id()
            }
        }

        impl<P, S, DS, const SALT_LEN: usize> NonInteractiveSession for $name<P, S, DS, SALT_LEN> {
            type Session = S;
        }
    };
}

role_wrapper!(DsfsArgumentProver, argument);
role_wrapper!(DsfsArgumentVerifier, argument);
role_wrapper!(DsfsReductionProver, reduction);
role_wrapper!(DsfsReductionVerifier, reduction);
role_wrapper!(PreprocessedDsfsArgumentProver, argument);
role_wrapper!(PreprocessedDsfsArgumentVerifier, argument);
role_wrapper!(PreprocessedDsfsReductionProver, reduction);
role_wrapper!(PreprocessedDsfsReductionVerifier, reduction);

/// Compile a plain interactive argument prover with no salt.
#[must_use]
pub const fn plain_non_interactive_argument_prover<P, S, DS>(
    prover: P,
    duplex_sponge: DS,
) -> DsfsArgumentProver<P, S, DS, 0> {
    DsfsArgumentProver::new(prover, duplex_sponge)
}

/// Compile a salted plain interactive argument prover.
#[must_use]
pub const fn plain_non_interactive_argument_prover_with_salt<P, S, DS, const SALT_LEN: usize>(
    prover: P,
    duplex_sponge: DS,
) -> DsfsArgumentProver<P, S, DS, SALT_LEN> {
    DsfsArgumentProver::new(prover, duplex_sponge)
}

/// Compile a plain interactive argument verifier with no salt.
#[must_use]
pub const fn plain_non_interactive_argument_verifier<V, S, DS>(
    verifier: V,
    duplex_sponge: DS,
) -> DsfsArgumentVerifier<V, S, DS, 0> {
    DsfsArgumentVerifier::new(verifier, duplex_sponge)
}

/// Compile a salted plain interactive argument verifier.
#[must_use]
pub const fn plain_non_interactive_argument_verifier_with_salt<V, S, DS, const SALT_LEN: usize>(
    verifier: V,
    duplex_sponge: DS,
) -> DsfsArgumentVerifier<V, S, DS, SALT_LEN> {
    DsfsArgumentVerifier::new(verifier, duplex_sponge)
}

impl<P, S, DS, const SALT_LEN: usize> ArgumentCore for DsfsArgumentProver<P, S, DS, SALT_LEN>
where
    P: ArgumentCore,
{
    type Instance = P::Instance;
}

impl<P, S, DS, const SALT_LEN: usize> ArgumentProverCore for DsfsArgumentProver<P, S, DS, SALT_LEN>
where
    P: ArgumentProverCore,
{
    type Witness = P::Witness;
}

impl<P, S, DS, const SALT_LEN: usize> NonInteractiveArgumentProver
    for DsfsArgumentProver<P, S, DS, SALT_LEN>
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
        prove_with_sponge_and_salt::<P, DS, S, SALT_LEN>(
            &self.argument,
            self.duplex_sponge.clone(),
            session,
            instance,
            witness,
        )
    }
}

impl<V, S, DS, const SALT_LEN: usize> ArgumentCore for DsfsArgumentVerifier<V, S, DS, SALT_LEN>
where
    V: ArgumentCore,
{
    type Instance = V::Instance;
}

impl<V, S, DS, const SALT_LEN: usize> NonInteractiveArgumentVerifier
    for DsfsArgumentVerifier<V, S, DS, SALT_LEN>
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
        verify_with_sponge_and_salt::<V, DS, S, SALT_LEN>(
            &self.argument,
            self.duplex_sponge.clone(),
            session,
            instance,
            proof.as_bytes(),
        )
    }
}

/// Compile a preprocessing argument prover with no salt.
#[must_use]
pub const fn preprocessing_non_interactive_argument_prover<P, S, DS>(
    prover: P,
    duplex_sponge: DS,
) -> PreprocessedDsfsArgumentProver<P, S, DS, 0> {
    PreprocessedDsfsArgumentProver::new(prover, duplex_sponge)
}

/// Compile a salted preprocessing argument prover.
#[must_use]
pub const fn preprocessing_non_interactive_argument_prover_with_salt<
    P,
    S,
    DS,
    const SALT_LEN: usize,
>(
    prover: P,
    duplex_sponge: DS,
) -> PreprocessedDsfsArgumentProver<P, S, DS, SALT_LEN> {
    PreprocessedDsfsArgumentProver::new(prover, duplex_sponge)
}

/// Compile a preprocessing argument verifier with no salt.
#[must_use]
pub const fn preprocessing_non_interactive_argument_verifier<V, S, DS>(
    verifier: V,
    duplex_sponge: DS,
) -> PreprocessedDsfsArgumentVerifier<V, S, DS, 0> {
    PreprocessedDsfsArgumentVerifier::new(verifier, duplex_sponge)
}

/// Compile a salted preprocessing argument verifier.
#[must_use]
pub const fn preprocessing_non_interactive_argument_verifier_with_salt<
    V,
    S,
    DS,
    const SALT_LEN: usize,
>(
    verifier: V,
    duplex_sponge: DS,
) -> PreprocessedDsfsArgumentVerifier<V, S, DS, SALT_LEN> {
    PreprocessedDsfsArgumentVerifier::new(verifier, duplex_sponge)
}

impl<P, S, DS, const SALT_LEN: usize> ArgumentCore
    for PreprocessedDsfsArgumentProver<P, S, DS, SALT_LEN>
where
    P: ArgumentCore,
{
    type Instance = P::Instance;
}

impl<P, S, DS, const SALT_LEN: usize> ArgumentProverCore
    for PreprocessedDsfsArgumentProver<P, S, DS, SALT_LEN>
where
    P: ArgumentProverCore,
{
    type Witness = P::Witness;
}

impl<P, S, DS, const SALT_LEN: usize> PreprocessingNonInteractiveArgumentProver
    for PreprocessedDsfsArgumentProver<P, S, DS, SALT_LEN>
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
        prepared_prove_with_sponge_and_salt::<P, DS, S, SALT_LEN>(
            &self.argument,
            prover_key,
            &committed_index,
            self.duplex_sponge.clone(),
            session,
            instance,
            witness,
        )
    }
}

impl<V, S, DS, const SALT_LEN: usize> ArgumentCore
    for PreprocessedDsfsArgumentVerifier<V, S, DS, SALT_LEN>
where
    V: ArgumentCore,
{
    type Instance = V::Instance;
}

impl<V, S, DS, const SALT_LEN: usize> PreprocessingNonInteractiveArgumentVerifier
    for PreprocessedDsfsArgumentVerifier<V, S, DS, SALT_LEN>
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
        prepared_verify_with_sponge_and_salt::<V, DS, S, SALT_LEN>(
            &self.argument,
            verifier_key,
            &committed_index,
            self.duplex_sponge.clone(),
            session,
            instance,
            proof.as_bytes(),
        )
    }
}

/// Compile a plain interactive reduction prover with no salt.
#[must_use]
pub const fn plain_non_interactive_reduction_prover<P, S, DS>(
    prover: P,
    duplex_sponge: DS,
) -> DsfsReductionProver<P, S, DS, 0> {
    DsfsReductionProver::new(prover, duplex_sponge)
}

/// Compile a salted plain interactive reduction prover.
#[must_use]
pub const fn plain_non_interactive_reduction_prover_with_salt<P, S, DS, const SALT_LEN: usize>(
    prover: P,
    duplex_sponge: DS,
) -> DsfsReductionProver<P, S, DS, SALT_LEN> {
    DsfsReductionProver::new(prover, duplex_sponge)
}

/// Compile a plain interactive reduction verifier with no salt.
#[must_use]
pub const fn plain_non_interactive_reduction_verifier<V, S, DS>(
    verifier: V,
    duplex_sponge: DS,
) -> DsfsReductionVerifier<V, S, DS, 0> {
    DsfsReductionVerifier::new(verifier, duplex_sponge)
}

/// Compile a salted plain interactive reduction verifier.
#[must_use]
pub const fn plain_non_interactive_reduction_verifier_with_salt<V, S, DS, const SALT_LEN: usize>(
    verifier: V,
    duplex_sponge: DS,
) -> DsfsReductionVerifier<V, S, DS, SALT_LEN> {
    DsfsReductionVerifier::new(verifier, duplex_sponge)
}

impl<P, S, DS, const SALT_LEN: usize> ReductionCore for DsfsReductionProver<P, S, DS, SALT_LEN>
where
    P: ReductionCore,
{
    type SourceInstance = P::SourceInstance;
    type TargetInstance = P::TargetInstance;
}

impl<P, S, DS, const SALT_LEN: usize> ReductionProverCore
    for DsfsReductionProver<P, S, DS, SALT_LEN>
where
    P: ReductionProverCore,
{
    type SourceWitness = P::SourceWitness;
    type TargetWitness = P::TargetWitness;
}

impl<P, S, DS, const SALT_LEN: usize> NonInteractiveReductionProver
    for DsfsReductionProver<P, S, DS, SALT_LEN>
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
        prove_reduction_with_sponge_and_salt_full::<P, DS, S, SALT_LEN>(
            &self.reduction,
            self.duplex_sponge.clone(),
            session,
            instance,
            witness,
        )
    }
}

impl<V, S, DS, const SALT_LEN: usize> ReductionCore for DsfsReductionVerifier<V, S, DS, SALT_LEN>
where
    V: ReductionCore,
{
    type SourceInstance = V::SourceInstance;
    type TargetInstance = V::TargetInstance;
}

impl<V, S, DS, const SALT_LEN: usize> NonInteractiveReductionVerifier
    for DsfsReductionVerifier<V, S, DS, SALT_LEN>
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
        verify_reduction_with_sponge_and_salt::<V, DS, S, SALT_LEN>(
            &self.reduction,
            self.duplex_sponge.clone(),
            session,
            instance,
            proof.as_bytes(),
        )
    }
}

/// Compile a preprocessing reduction prover with no salt.
#[must_use]
pub const fn preprocessing_non_interactive_reduction_prover<P, S, DS>(
    prover: P,
    duplex_sponge: DS,
) -> PreprocessedDsfsReductionProver<P, S, DS, 0> {
    PreprocessedDsfsReductionProver::new(prover, duplex_sponge)
}

/// Compile a salted preprocessing reduction prover.
#[must_use]
pub const fn preprocessing_non_interactive_reduction_prover_with_salt<
    P,
    S,
    DS,
    const SALT_LEN: usize,
>(
    prover: P,
    duplex_sponge: DS,
) -> PreprocessedDsfsReductionProver<P, S, DS, SALT_LEN> {
    PreprocessedDsfsReductionProver::new(prover, duplex_sponge)
}

/// Compile a preprocessing reduction verifier with no salt.
#[must_use]
pub const fn preprocessing_non_interactive_reduction_verifier<V, S, DS>(
    verifier: V,
    duplex_sponge: DS,
) -> PreprocessedDsfsReductionVerifier<V, S, DS, 0> {
    PreprocessedDsfsReductionVerifier::new(verifier, duplex_sponge)
}

/// Compile a salted preprocessing reduction verifier.
#[must_use]
pub const fn preprocessing_non_interactive_reduction_verifier_with_salt<
    V,
    S,
    DS,
    const SALT_LEN: usize,
>(
    verifier: V,
    duplex_sponge: DS,
) -> PreprocessedDsfsReductionVerifier<V, S, DS, SALT_LEN> {
    PreprocessedDsfsReductionVerifier::new(verifier, duplex_sponge)
}

impl<P, S, DS, const SALT_LEN: usize> ReductionCore
    for PreprocessedDsfsReductionProver<P, S, DS, SALT_LEN>
where
    P: ReductionCore,
{
    type SourceInstance = P::SourceInstance;
    type TargetInstance = P::TargetInstance;
}

impl<P, S, DS, const SALT_LEN: usize> ReductionProverCore
    for PreprocessedDsfsReductionProver<P, S, DS, SALT_LEN>
where
    P: ReductionProverCore,
{
    type SourceWitness = P::SourceWitness;
    type TargetWitness = P::TargetWitness;
}

impl<P, S, DS, const SALT_LEN: usize> PreprocessingNonInteractiveReductionProver
    for PreprocessedDsfsReductionProver<P, S, DS, SALT_LEN>
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
        prepared_prove_reduction_with_sponge_and_salt::<P, DS, S, SALT_LEN>(
            &self.reduction,
            prover_key,
            &committed_index,
            self.duplex_sponge.clone(),
            session,
            instance,
            witness,
        )
    }
}

impl<V, S, DS, const SALT_LEN: usize> ReductionCore
    for PreprocessedDsfsReductionVerifier<V, S, DS, SALT_LEN>
where
    V: ReductionCore,
{
    type SourceInstance = V::SourceInstance;
    type TargetInstance = V::TargetInstance;
}

impl<V, S, DS, const SALT_LEN: usize> PreprocessingNonInteractiveReductionVerifier
    for PreprocessedDsfsReductionVerifier<V, S, DS, SALT_LEN>
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
        prepared_verify_reduction_with_sponge_and_salt::<V, DS, S, SALT_LEN>(
            &self.reduction,
            verifier_key,
            &committed_index,
            self.duplex_sponge.clone(),
            session,
            instance,
            proof.as_bytes(),
        )
    }
}

#[inline]
fn prove_with_sponge_and_salt<IA, DS, S, const SALT_LEN: usize>(
    ia: &IA,
    duplex_sponge: DS,
    session: &S,
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> NargProof
where
    DS: SpongeInfo,
    IA: InteractiveArgumentProver,
    S: Encoding<[u8]>,
    IA::Instance: Encoding<[DS::U]>,
    [u8; SALT_LEN]: Encoding<[DS::U]>,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        ia.protocol_id().as_ref(),
        DS::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(instance);

    let mut spongefish_prover_ch = SpongeProver::new(domsep.to_prover(duplex_sponge));
    let mut salt = [0u8; SALT_LEN];
    spongefish_prover_ch.state.rng().fill_bytes(&mut salt);
    spongefish_prover_ch.state.prover_message(&salt);
    ia.prove(&mut spongefish_prover_ch, instance, witness);
    NargProof::from_bytes(spongefish_prover_ch.narg_string().to_vec())
}

fn verify_with_sponge_and_salt<IA, DS, S, const SALT_LEN: usize>(
    ia: &IA,
    duplex_sponge: DS,
    session: &S,
    instance: &IA::Instance,
    proof: &[u8],
) -> VerificationResult<()>
where
    DS: SpongeInfo,
    IA: InteractiveArgumentVerifier,
    S: Encoding<[u8]>,
    IA::Instance: Encoding<[DS::U]>,
    [u8; SALT_LEN]: Encoding<[DS::U]> + NargDeserialize,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        ia.protocol_id().as_ref(),
        DS::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(instance);

    let mut spongefish_verifier_ch = SpongeVerifier::new(domsep.to_verifier(duplex_sponge, proof));
    let _salt: [u8; SALT_LEN] = spongefish_verifier_ch
        .state
        .prover_message()
        .map_err(|_| ia_core::VerificationError)?;
    ia.verify(&mut spongefish_verifier_ch, instance)?;
    spongefish_verifier_ch
        .state
        .check_eof()
        .map_err(|_| ia_core::VerificationError)
}

fn prove_reduction_with_sponge_and_salt_full<IR, DS, S, const SALT_LEN: usize>(
    ir: &IR,
    duplex_sponge: DS,
    session: &S,
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> (NargProof, IR::TargetInstance, IR::TargetWitness)
where
    DS: SpongeInfo,
    IR: InteractiveReductionProver,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding<[DS::U]>,
    [u8; SALT_LEN]: Encoding<[DS::U]>,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        ir.protocol_id().as_ref(),
        DS::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(instance);

    let mut spongefish_prover_ch = SpongeProver::new(domsep.to_prover(duplex_sponge));
    let mut salt = [0u8; SALT_LEN];
    spongefish_prover_ch.state.rng().fill_bytes(&mut salt);
    spongefish_prover_ch.state.prover_message(&salt);
    let (target_instance, target_witness) = ir.prove(&mut spongefish_prover_ch, instance, witness);
    (
        NargProof::from_bytes(spongefish_prover_ch.narg_string().to_vec()),
        target_instance,
        target_witness,
    )
}

fn verify_reduction_with_sponge_and_salt<IR, DS, S, const SALT_LEN: usize>(
    ir: &IR,
    duplex_sponge: DS,
    session: &S,
    instance: &IR::SourceInstance,
    proof: &[u8],
) -> VerificationResult<IR::TargetInstance>
where
    DS: SpongeInfo,
    IR: InteractiveReductionVerifier,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding<[DS::U]>,
    [u8; SALT_LEN]: Encoding<[DS::U]> + NargDeserialize,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        ir.protocol_id().as_ref(),
        DS::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(instance);

    let mut spongefish_verifier_ch = SpongeVerifier::new(domsep.to_verifier(duplex_sponge, proof));
    let _salt: [u8; SALT_LEN] = spongefish_verifier_ch
        .state
        .prover_message()
        .map_err(|_| ia_core::VerificationError)?;
    let target = ir.verify(&mut spongefish_verifier_ch, instance)?;
    spongefish_verifier_ch
        .state
        .check_eof()
        .map_err(|_| ia_core::VerificationError)?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use ia_core::{
        ArgumentCore, ArgumentProverCore, CommittedIndexBytes, InteractiveArgumentProver,
        InteractiveArgumentVerifier, InteractiveReductionProver, InteractiveReductionVerifier,
        NonInteractiveArgumentProver, NonInteractiveArgumentVerifier,
        NonInteractiveReductionProver, NonInteractiveReductionVerifier,
        PreprocessingInteractiveArgumentProver, PreprocessingInteractiveArgumentVerifier,
        PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
        PreprocessingNonInteractiveArgumentProver, PreprocessingNonInteractiveArgumentVerifier,
        PreprocessingNonInteractiveReductionProver, PreprocessingNonInteractiveReductionVerifier,
        ProtocolCore, ProverChannel, ReductionCore, ReductionProverCore, VerificationError,
        VerifierChannel,
    };

    use super::*;

    const SESSION: [u8; 1] = [9];

    struct ArgumentProver;
    struct ArgumentVerifier;

    impl ProtocolCore for ArgumentProver {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            b"dsfs-fixture-argument"
        }
    }
    impl ProtocolCore for ArgumentVerifier {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            b"dsfs-fixture-argument"
        }
    }
    impl ArgumentCore for ArgumentProver {
        type Instance = u32;
    }
    impl ArgumentCore for ArgumentVerifier {
        type Instance = u32;
    }
    impl ArgumentProverCore for ArgumentProver {
        type Witness = u32;
    }
    impl InteractiveArgumentProver for ArgumentProver {
        fn prove<C: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut C,
            _: &Self::Instance,
            witness: &Self::Witness,
        ) {
            ch.send_prover_message(witness);
            let challenge: u32 = ch.read_verifier_message();
            ch.send_prover_message(&(witness ^ challenge));
        }
    }
    impl InteractiveArgumentVerifier for ArgumentVerifier {
        fn verify<C: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut C,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            let witness: u32 = ch.read_prover_message()?;
            let challenge: u32 = ch.send_verifier_message();
            let response: u32 = ch.read_prover_message()?;
            if witness == *instance && response == witness ^ challenge {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }

    struct ReductionProver;
    struct ReductionVerifier;

    impl ProtocolCore for ReductionProver {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            b"dsfs-fixture-reduction"
        }
    }
    impl ProtocolCore for ReductionVerifier {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            b"dsfs-fixture-reduction"
        }
    }
    impl ReductionCore for ReductionProver {
        type SourceInstance = u32;
        type TargetInstance = u32;
    }
    impl ReductionCore for ReductionVerifier {
        type SourceInstance = u32;
        type TargetInstance = u32;
    }
    impl ReductionProverCore for ReductionProver {
        type SourceWitness = u32;
        type TargetWitness = u32;
    }
    impl InteractiveReductionProver for ReductionProver {
        fn prove<C: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut C,
            instance: &Self::SourceInstance,
            witness: &Self::SourceWitness,
        ) -> (Self::TargetInstance, Self::TargetWitness) {
            ch.send_prover_message(witness);
            let challenge: u32 = ch.read_verifier_message();
            (instance ^ challenge, witness ^ challenge)
        }
    }
    impl InteractiveReductionVerifier for ReductionVerifier {
        fn verify<C: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut C,
            instance: &Self::SourceInstance,
        ) -> VerificationResult<Self::TargetInstance> {
            let _: u32 = ch.read_prover_message()?;
            let challenge: u32 = ch.send_verifier_message();
            Ok(instance ^ challenge)
        }
    }

    #[derive(Clone)]
    struct Key(u8);

    impl CommittedIndex for Key {
        fn committed_index(&self) -> CommittedIndexBytes {
            CommittedIndexBytes::new(vec![self.0])
        }
    }

    struct IndexedArgumentProver;
    struct IndexedArgumentVerifier;

    impl ProtocolCore for IndexedArgumentProver {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            b"dsfs-fixture-indexed-argument"
        }
    }
    impl ProtocolCore for IndexedArgumentVerifier {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            b"dsfs-fixture-indexed-argument"
        }
    }
    impl ArgumentCore for IndexedArgumentProver {
        type Instance = u32;
    }
    impl ArgumentCore for IndexedArgumentVerifier {
        type Instance = u32;
    }
    impl ArgumentProverCore for IndexedArgumentProver {
        type Witness = u32;
    }
    impl PreprocessingInteractiveArgumentProver for IndexedArgumentProver {
        type ProverKey = Key;

        fn prove<C: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut C,
            key: &Self::ProverKey,
            _: &Self::Instance,
            witness: &Self::Witness,
        ) {
            ch.send_prover_message(&(witness + u32::from(key.0)));
            let _: u32 = ch.read_verifier_message();
        }
    }
    impl PreprocessingInteractiveArgumentVerifier for IndexedArgumentVerifier {
        type VerifierKey = Key;

        fn verify<C: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut C,
            key: &Self::VerifierKey,
            instance: &Self::Instance,
        ) -> VerificationResult<()> {
            let value: u32 = ch.read_prover_message()?;
            let _: u32 = ch.send_verifier_message();
            if value == instance + u32::from(key.0) {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }

    struct IndexedReductionProver;
    struct IndexedReductionVerifier;

    impl ProtocolCore for IndexedReductionProver {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            b"dsfs-fixture-indexed-reduction"
        }
    }
    impl ProtocolCore for IndexedReductionVerifier {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            b"dsfs-fixture-indexed-reduction"
        }
    }
    impl ReductionCore for IndexedReductionProver {
        type SourceInstance = u32;
        type TargetInstance = u32;
    }
    impl ReductionCore for IndexedReductionVerifier {
        type SourceInstance = u32;
        type TargetInstance = u32;
    }
    impl ReductionProverCore for IndexedReductionProver {
        type SourceWitness = u32;
        type TargetWitness = u32;
    }
    impl PreprocessingInteractiveReductionProver for IndexedReductionProver {
        type ProverKey = Key;

        fn prove<C: ProverChannel<Unit = u8>>(
            &self,
            ch: &mut C,
            key: &Self::ProverKey,
            instance: &Self::SourceInstance,
            witness: &Self::SourceWitness,
        ) -> (Self::TargetInstance, Self::TargetWitness) {
            ch.send_prover_message(witness);
            let challenge: u32 = ch.read_verifier_message();
            let offset = challenge + u32::from(key.0);
            (instance.wrapping_add(offset), witness.wrapping_add(offset))
        }
    }
    impl PreprocessingInteractiveReductionVerifier for IndexedReductionVerifier {
        type VerifierKey = Key;

        fn verify<C: VerifierChannel<Unit = u8>>(
            &self,
            ch: &mut C,
            key: &Self::VerifierKey,
            instance: &Self::SourceInstance,
        ) -> VerificationResult<Self::TargetInstance> {
            let _: u32 = ch.read_prover_message()?;
            let challenge: u32 = ch.send_verifier_message();
            Ok(instance.wrapping_add(challenge + u32::from(key.0)))
        }
    }

    #[test]
    fn plain_argument_fixture_and_eof_rejection() {
        let prover = plain_non_interactive_argument_prover::<_, [u8; 1], _>(
            ArgumentProver,
            Keccak::default(),
        );
        let verifier = plain_non_interactive_argument_verifier::<_, [u8; 1], _>(
            ArgumentVerifier,
            Keccak::default(),
        );
        let proof = prover.prove(&SESSION, &7, &7);
        assert_eq!(proof.as_bytes(), &[7, 0, 0, 0, 177, 110, 148, 211]);
        verifier.verify(&SESSION, &7, &proof).unwrap();
        let mut trailing = proof.into_bytes();
        trailing.push(0);
        assert!(verifier
            .verify(&SESSION, &7, &NargProof::from_bytes(trailing))
            .is_err());
    }

    #[test]
    fn plain_reduction_fixture_and_eof_rejection() {
        let prover = plain_non_interactive_reduction_prover::<_, [u8; 1], _>(
            ReductionProver,
            Keccak::default(),
        );
        let verifier = plain_non_interactive_reduction_verifier::<_, [u8; 1], _>(
            ReductionVerifier,
            Keccak::default(),
        );
        let (proof, target, _) = prover.prove(&SESSION, &11, &13);
        assert_eq!(proof.as_bytes(), &[13, 0, 0, 0]);
        assert_eq!(verifier.verify(&SESSION, &11, &proof).unwrap(), target);
        let mut trailing = proof.into_bytes();
        trailing.push(0);
        assert!(verifier
            .verify(&SESSION, &11, &NargProof::from_bytes(trailing))
            .is_err());
    }

    #[test]
    fn preprocessing_argument_fixture_and_eof_rejection() {
        let prover = preprocessing_non_interactive_argument_prover::<_, [u8; 1], _>(
            IndexedArgumentProver,
            Keccak::default(),
        );
        let verifier = preprocessing_non_interactive_argument_verifier::<_, [u8; 1], _>(
            IndexedArgumentVerifier,
            Keccak::default(),
        );
        let key = Key(3);
        let proof = prover.prove(&key, &SESSION, &17, &17);
        assert_eq!(proof.as_bytes(), &[20, 0, 0, 0]);
        verifier.verify(&key, &SESSION, &17, &proof).unwrap();
        let mut trailing = proof.into_bytes();
        trailing.push(0);
        assert!(verifier
            .verify(&key, &SESSION, &17, &NargProof::from_bytes(trailing))
            .is_err());
    }

    #[test]
    fn preprocessing_reduction_fixture_and_eof_rejection() {
        let prover = preprocessing_non_interactive_reduction_prover::<_, [u8; 1], _>(
            IndexedReductionProver,
            Keccak::default(),
        );
        let verifier = preprocessing_non_interactive_reduction_verifier::<_, [u8; 1], _>(
            IndexedReductionVerifier,
            Keccak::default(),
        );
        let key = Key(5);
        let (proof, target, _) = prover.prove(&key, &SESSION, &19, &23);
        assert_eq!(proof.as_bytes(), &[23, 0, 0, 0]);
        assert_eq!(
            verifier.verify(&key, &SESSION, &19, &proof).unwrap(),
            target
        );
        let mut trailing = proof.into_bytes();
        trailing.push(0);
        assert!(verifier
            .verify(&key, &SESSION, &19, &NargProof::from_bytes(trailing))
            .is_err());
    }

    #[test]
    fn salted_constructor_family_round_trips() {
        let argument_prover = plain_non_interactive_argument_prover_with_salt::<_, [u8; 1], _, 8>(
            ArgumentProver,
            Keccak::default(),
        );
        let argument_verifier = plain_non_interactive_argument_verifier_with_salt::<_, [u8; 1], _, 8>(
            ArgumentVerifier,
            Keccak::default(),
        );
        let argument_proof = argument_prover.prove(&SESSION, &7, &7);
        argument_verifier
            .verify(&SESSION, &7, &argument_proof)
            .unwrap();

        let reduction_prover = plain_non_interactive_reduction_prover_with_salt::<_, [u8; 1], _, 8>(
            ReductionProver,
            Keccak::default(),
        );
        let reduction_verifier =
            plain_non_interactive_reduction_verifier_with_salt::<_, [u8; 1], _, 8>(
                ReductionVerifier,
                Keccak::default(),
            );
        let (reduction_proof, target, _) = reduction_prover.prove(&SESSION, &11, &13);
        assert_eq!(
            reduction_verifier
                .verify(&SESSION, &11, &reduction_proof)
                .unwrap(),
            target,
        );

        let key = Key(3);
        let indexed_argument_prover =
            preprocessing_non_interactive_argument_prover_with_salt::<_, [u8; 1], _, 8>(
                IndexedArgumentProver,
                Keccak::default(),
            );
        let indexed_argument_verifier =
            preprocessing_non_interactive_argument_verifier_with_salt::<_, [u8; 1], _, 8>(
                IndexedArgumentVerifier,
                Keccak::default(),
            );
        let indexed_argument_proof = indexed_argument_prover.prove(&key, &SESSION, &17, &17);
        indexed_argument_verifier
            .verify(&key, &SESSION, &17, &indexed_argument_proof)
            .unwrap();

        let indexed_reduction_prover =
            preprocessing_non_interactive_reduction_prover_with_salt::<_, [u8; 1], _, 8>(
                IndexedReductionProver,
                Keccak::default(),
            );
        let indexed_reduction_verifier =
            preprocessing_non_interactive_reduction_verifier_with_salt::<_, [u8; 1], _, 8>(
                IndexedReductionVerifier,
                Keccak::default(),
            );
        let (indexed_reduction_proof, target, _) =
            indexed_reduction_prover.prove(&key, &SESSION, &19, &23);
        assert_eq!(
            indexed_reduction_verifier
                .verify(&key, &SESSION, &19, &indexed_reduction_proof)
                .unwrap(),
            target,
        );
    }
}
