//! DSFS non-interactive prove/verify entry points.

extern crate alloc;

use core::marker::PhantomData;

use rand::RngCore;

use ia_core::{
    ArgumentCore, CommittedIndex, Encoding, InteractiveArgument, InteractiveReduction,
    NargDeserialize, NargProof, NonInteractiveArgument, NonInteractiveReduction, PreprocessingCore,
    PreprocessingInteractiveArgument, PreprocessingInteractiveReduction,
    PreprocessingNonInteractiveArgument, PreprocessingNonInteractiveReduction, ProtocolCore,
    ReductionCore,
};

use crate::runners::{
    prepared_prove_reduction_with_sponge_and_salt, prepared_prove_with_sponge_and_salt,
    prepared_verify_reduction_with_sponge_and_salt, prepared_verify_with_sponge_and_salt,
};

use spongefish::{DomainSeparator, DuplexSpongeInterface};

use crate::channel::{SpongeProver, SpongeVerifier};
use crate::params::{Keccak, SpongeInfo};

/// Byte-oriented duplex sponge (`U = u8`), matching Keccak and spongefish `StdHash` / SHAKE128.
pub trait ByteDuplexSponge: DuplexSpongeInterface<U = u8> {}

impl<T: DuplexSpongeInterface<U = u8>> ByteDuplexSponge for T {}

/// DSFS compiler wrapper implementing [`NonInteractiveArgument`] for a plain IA.
///
/// Prefer constructing this with [`plain_non_interactive_argument`].
pub struct DsfsArgument<IA, S, DS = Keccak, const SALT_LEN: usize = 0> {
    pub ia: IA,
    pub duplex_sponge: DS,
    _session: PhantomData<S>,
}

/// Construct the DSFS non-interactive-argument view of a plain interactive body.
#[must_use]
pub const fn plain_non_interactive_argument<IA, S, DS>(
    ia: IA,
    duplex_sponge: DS,
) -> DsfsArgument<IA, S, DS, 0> {
    DsfsArgument::new(ia, duplex_sponge)
}

/// Construct a salted DSFS non-interactive-argument view of a plain interactive body.
#[must_use]
pub const fn plain_non_interactive_argument_with_salt<IA, S, DS, const SALT_LEN: usize>(
    ia: IA,
    duplex_sponge: DS,
) -> DsfsArgument<IA, S, DS, SALT_LEN> {
    DsfsArgument::new(ia, duplex_sponge)
}

impl<IA, S, DS, const SALT_LEN: usize> DsfsArgument<IA, S, DS, SALT_LEN> {
    #[must_use]
    pub const fn new(ia: IA, duplex_sponge: DS) -> Self {
        Self {
            ia,
            duplex_sponge,
            _session: PhantomData,
        }
    }
}

impl<IA, S, DS, const SALT_LEN: usize> ProtocolCore for DsfsArgument<IA, S, DS, SALT_LEN>
where
    IA: InteractiveArgument,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.ia.protocol_id()
    }
}

impl<IA, S, DS, const SALT_LEN: usize> ArgumentCore for DsfsArgument<IA, S, DS, SALT_LEN>
where
    IA: InteractiveArgument,
{
    type Instance = IA::Instance;
    type Witness = IA::Witness;
}

impl<IA, S, DS, const SALT_LEN: usize> NonInteractiveArgument for DsfsArgument<IA, S, DS, SALT_LEN>
where
    DS: SpongeInfo + Clone,
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
    IA::Instance: Encoding<[DS::U]>,
    [u8; SALT_LEN]: Encoding<[DS::U]> + NargDeserialize,
{
    type Session = S;

    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> NargProof {
        prove_with_sponge_and_salt::<IA, DS, S, SALT_LEN>(
            &self.ia,
            self.duplex_sponge.clone(),
            session,
            instance,
            witness,
        )
    }

    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &NargProof,
    ) -> ia_core::VerificationResult<()> {
        verify_with_sponge_and_salt::<IA, DS, S, SALT_LEN>(
            &self.ia,
            self.duplex_sponge.clone(),
            session,
            instance,
            proof.as_bytes(),
        )
    }
}

/// DSFS compiler wrapper implementing [`PreprocessingNonInteractiveArgument`] for a
/// preprocessing interactive body.
///
/// Stateless: it holds the protocol body and the sponge, but no keys. Obtain
/// `(pk, vk)` from the body's [`preprocess`](PreprocessingCore::preprocess) and pass the
/// relevant key to `prove` / `verify`; the wrapper derives the committed index
/// from whichever key it is handed.
pub struct PreprocessedDsfsArgument<IA, S, DS = Keccak, const SALT_LEN: usize = 0> {
    pub ia: IA,
    pub duplex_sponge: DS,
    _session: PhantomData<S>,
}

/// Construct the DSFS non-interactive-argument view of a preprocessing body.
#[must_use]
pub const fn preprocessing_non_interactive_argument<IA, S, DS>(
    ia: IA,
    duplex_sponge: DS,
) -> PreprocessedDsfsArgument<IA, S, DS, 0> {
    PreprocessedDsfsArgument::new(ia, duplex_sponge)
}

/// Construct a salted DSFS non-interactive-argument view of a preprocessing body.
#[must_use]
pub const fn preprocessing_non_interactive_argument_with_salt<IA, S, DS, const SALT_LEN: usize>(
    ia: IA,
    duplex_sponge: DS,
) -> PreprocessedDsfsArgument<IA, S, DS, SALT_LEN> {
    PreprocessedDsfsArgument::new(ia, duplex_sponge)
}

impl<IA, S, DS, const SALT_LEN: usize> PreprocessedDsfsArgument<IA, S, DS, SALT_LEN> {
    #[must_use]
    pub const fn new(ia: IA, duplex_sponge: DS) -> Self {
        Self {
            ia,
            duplex_sponge,
            _session: PhantomData,
        }
    }
}

impl<IA, S, DS, const SALT_LEN: usize> ProtocolCore for PreprocessedDsfsArgument<IA, S, DS, SALT_LEN>
where
    IA: PreprocessingInteractiveArgument,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.ia.protocol_id()
    }
}

impl<IA, S, DS, const SALT_LEN: usize> ArgumentCore for PreprocessedDsfsArgument<IA, S, DS, SALT_LEN>
where
    IA: PreprocessingInteractiveArgument,
{
    type Instance = IA::Instance;
    type Witness = IA::Witness;
}

impl<IA, S, DS, const SALT_LEN: usize> PreprocessingCore
    for PreprocessedDsfsArgument<IA, S, DS, SALT_LEN>
where
    IA: PreprocessingInteractiveArgument,
{
    type Index = IA::Index;
    type ProverKey = IA::ProverKey;
    type VerifierKey = IA::VerifierKey;

    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        // Route through `preprocess_checked` so a prover/verifier `committed_index`
        // mismatch is caught at preprocessing time rather than as an opaque verify failure.
        self.ia.preprocess_checked(ix)
    }
}

impl<IA, S, DS, const SALT_LEN: usize> PreprocessingNonInteractiveArgument
    for PreprocessedDsfsArgument<IA, S, DS, SALT_LEN>
where
    DS: SpongeInfo + Clone,
    IA: PreprocessingInteractiveArgument,
    S: Encoding<[u8]>,
    IA::Instance: Encoding<[u8]>,
    [u8; SALT_LEN]: Encoding<[DS::U]> + NargDeserialize,
{
    type Session = S;

    fn prove(
        &self,
        prover_key: &Self::ProverKey,
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> NargProof {
        let committed_index = prover_key.committed_index();
        prepared_prove_with_sponge_and_salt::<IA, DS, S, SALT_LEN>(
            &self.ia,
            prover_key,
            &committed_index,
            self.duplex_sponge.clone(),
            session,
            instance,
            witness,
        )
    }

    fn verify(
        &self,
        verifier_key: &Self::VerifierKey,
        session: &Self::Session,
        instance: &Self::Instance,
        proof: &NargProof,
    ) -> ia_core::VerificationResult<()> {
        let committed_index = verifier_key.committed_index();
        prepared_verify_with_sponge_and_salt::<IA, DS, S, SALT_LEN>(
            &self.ia,
            verifier_key,
            &committed_index,
            self.duplex_sponge.clone(),
            session,
            instance,
            proof.as_bytes(),
        )
    }
}

/// DSFS compiler wrapper implementing [`NonInteractiveReduction`] for an IR.
pub struct DsfsReduction<IR, S, DS = Keccak, const SALT_LEN: usize = 0> {
    pub ir: IR,
    pub duplex_sponge: DS,
    _session: PhantomData<S>,
}

impl<IR, S, DS, const SALT_LEN: usize> DsfsReduction<IR, S, DS, SALT_LEN> {
    #[must_use]
    pub const fn new(ir: IR, duplex_sponge: DS) -> Self {
        Self {
            ir,
            duplex_sponge,
            _session: PhantomData,
        }
    }
}

/// Construct the DSFS non-interactive-reduction view of a plain interactive body.
#[must_use]
pub const fn plain_non_interactive_reduction<IR, S, DS>(
    ir: IR,
    duplex_sponge: DS,
) -> DsfsReduction<IR, S, DS, 0> {
    DsfsReduction::new(ir, duplex_sponge)
}

/// Construct a salted DSFS non-interactive-reduction view of a plain interactive body.
#[must_use]
pub const fn plain_non_interactive_reduction_with_salt<IR, S, DS, const SALT_LEN: usize>(
    ir: IR,
    duplex_sponge: DS,
) -> DsfsReduction<IR, S, DS, SALT_LEN> {
    DsfsReduction::new(ir, duplex_sponge)
}

impl<IR, S, DS, const SALT_LEN: usize> ProtocolCore for DsfsReduction<IR, S, DS, SALT_LEN>
where
    IR: InteractiveReduction,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.ir.protocol_id()
    }
}

impl<IR, S, DS, const SALT_LEN: usize> ReductionCore for DsfsReduction<IR, S, DS, SALT_LEN>
where
    IR: InteractiveReduction,
{
    type SourceInstance = IR::SourceInstance;
    type TargetInstance = IR::TargetInstance;
    type SourceWitness = IR::SourceWitness;
    type TargetWitness = IR::TargetWitness;
}

impl<IR, S, DS, const SALT_LEN: usize> NonInteractiveReduction
    for DsfsReduction<IR, S, DS, SALT_LEN>
where
    DS: SpongeInfo + Clone,
    IR: InteractiveReduction,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding<[DS::U]>,
    [u8; SALT_LEN]: Encoding<[DS::U]> + NargDeserialize,
{
    type Session = S;

    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (NargProof, Self::TargetInstance, Self::TargetWitness) {
        prove_reduction_with_sponge_and_salt_full::<IR, DS, S, SALT_LEN>(
            &self.ir,
            self.duplex_sponge.clone(),
            session,
            instance,
            witness,
        )
    }

    fn verify(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        proof: &NargProof,
    ) -> ia_core::VerificationResult<Self::TargetInstance> {
        verify_reduction_with_sponge_and_salt::<IR, DS, S, SALT_LEN>(
            &self.ir,
            self.duplex_sponge.clone(),
            session,
            instance,
            proof.as_bytes(),
        )
    }
}

/// DSFS compiler wrapper implementing [`PreprocessingNonInteractiveReduction`] for a
/// preprocessing interactive reduction. Stateless; see [`PreprocessedDsfsArgument`].
pub struct PreprocessedDsfsReduction<IR, S, DS = Keccak, const SALT_LEN: usize = 0> {
    pub ir: IR,
    pub duplex_sponge: DS,
    _session: PhantomData<S>,
}

/// Construct the DSFS non-interactive-reduction view of a preprocessing body.
#[must_use]
pub const fn preprocessing_non_interactive_reduction<IR, S, DS>(
    ir: IR,
    duplex_sponge: DS,
) -> PreprocessedDsfsReduction<IR, S, DS, 0> {
    PreprocessedDsfsReduction::new(ir, duplex_sponge)
}

/// Construct a salted DSFS non-interactive-reduction view of a preprocessing body.
#[must_use]
pub const fn preprocessing_non_interactive_reduction_with_salt<IR, S, DS, const SALT_LEN: usize>(
    ir: IR,
    duplex_sponge: DS,
) -> PreprocessedDsfsReduction<IR, S, DS, SALT_LEN> {
    PreprocessedDsfsReduction::new(ir, duplex_sponge)
}

impl<IR, S, DS, const SALT_LEN: usize> PreprocessedDsfsReduction<IR, S, DS, SALT_LEN> {
    #[must_use]
    pub const fn new(ir: IR, duplex_sponge: DS) -> Self {
        Self {
            ir,
            duplex_sponge,
            _session: PhantomData,
        }
    }
}

impl<IR, S, DS, const SALT_LEN: usize> ProtocolCore
    for PreprocessedDsfsReduction<IR, S, DS, SALT_LEN>
where
    IR: PreprocessingInteractiveReduction,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.ir.protocol_id()
    }
}

impl<IR, S, DS, const SALT_LEN: usize> ReductionCore
    for PreprocessedDsfsReduction<IR, S, DS, SALT_LEN>
where
    IR: PreprocessingInteractiveReduction,
{
    type SourceInstance = IR::SourceInstance;
    type TargetInstance = IR::TargetInstance;
    type SourceWitness = IR::SourceWitness;
    type TargetWitness = IR::TargetWitness;
}

impl<IR, S, DS, const SALT_LEN: usize> PreprocessingCore
    for PreprocessedDsfsReduction<IR, S, DS, SALT_LEN>
where
    IR: PreprocessingInteractiveReduction,
{
    type Index = IR::Index;
    type ProverKey = IR::ProverKey;
    type VerifierKey = IR::VerifierKey;

    fn preprocess(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
        // Route through `preprocess_checked` so a prover/verifier `committed_index`
        // mismatch is caught at preprocessing time rather than as an opaque verify failure.
        self.ir.preprocess_checked(ix)
    }
}

impl<IR, S, DS, const SALT_LEN: usize> PreprocessingNonInteractiveReduction
    for PreprocessedDsfsReduction<IR, S, DS, SALT_LEN>
where
    DS: SpongeInfo + Clone,
    IR: PreprocessingInteractiveReduction,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding<[u8]>,
    [u8; SALT_LEN]: Encoding<[DS::U]> + NargDeserialize,
{
    type Session = S;

    fn prove(
        &self,
        prover_key: &Self::ProverKey,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (NargProof, Self::TargetInstance, Self::TargetWitness) {
        let committed_index = prover_key.committed_index();
        prepared_prove_reduction_with_sponge_and_salt::<IR, DS, S, SALT_LEN>(
            &self.ir,
            prover_key,
            &committed_index,
            self.duplex_sponge.clone(),
            session,
            instance,
            witness,
        )
    }

    fn verify(
        &self,
        verifier_key: &Self::VerifierKey,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        proof: &NargProof,
    ) -> ia_core::VerificationResult<Self::TargetInstance> {
        let committed_index = verifier_key.committed_index();
        prepared_verify_reduction_with_sponge_and_salt::<IR, DS, S, SALT_LEN>(
            &self.ir,
            verifier_key,
            &committed_index,
            self.duplex_sponge.clone(),
            session,
            instance,
            proof.as_bytes(),
        )
    }
}

/// Non-interactive prover with explicit salt length and duplex sponge `DS`.
#[inline]
pub(crate) fn prove_with_sponge_and_salt<IA, DS, S, const SALT_LEN: usize>(
    ia: &IA,
    duplex_sponge: DS,
    session: &S,
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> NargProof
where
    DS: SpongeInfo,
    IA: InteractiveArgument,
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

/// Non-interactive verifier with explicit salt length and duplex sponge `DS`.
pub(crate) fn verify_with_sponge_and_salt<IA, DS, S, const SALT_LEN: usize>(
    ia: &IA,
    duplex_sponge: DS,
    session: &S,
    instance: &IA::Instance,
    proof: &[u8],
) -> ia_core::VerificationResult<()>
where
    DS: SpongeInfo,
    IA: InteractiveArgument,
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
    IR: InteractiveReduction,
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

/// Non-interactive verifier for an IOR with explicit salt length and duplex sponge `DS`.
pub(crate) fn verify_reduction_with_sponge_and_salt<IR, DS, S, const SALT_LEN: usize>(
    ir: &IR,
    duplex_sponge: DS,
    session: &S,
    instance: &IR::SourceInstance,
    proof: &[u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    DS: SpongeInfo,
    IR: InteractiveReduction,
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
