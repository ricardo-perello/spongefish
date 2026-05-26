//! DSFS non-interactive prove/verify entry points.

extern crate alloc;

use core::marker::PhantomData;

use rand::RngCore;

use ia_core::{
    ArgumentCore, Encoding, InteractiveArgument, InteractiveReduction, NargDeserialize, NargProof,
    NonInteractiveArgument, NonInteractiveReduction, PreprocessingInteractiveArgument,
    PreprocessingInteractiveReduction, ProtocolCore, ReductionCore,
};

use crate::prepared::{PreparedDsfsArgument, PreparedDsfsReduction};

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

/// DSFS compiler wrapper for a preprocessing argument before keys are prepared.
///
/// This wrapper deliberately does not implement [`NonInteractiveArgument`].
/// Call [`prepare`](Self::prepare) or [`with_keys`](Self::with_keys) to obtain a
/// [`PreparedDsfsArgument`], which then implements
/// [`NonInteractiveArgument`] plus the preprocessing capability.
pub struct UnpreparedDsfsArgument<IA, S, DS = Keccak, const SALT_LEN: usize = 0> {
    ia: IA,
    duplex_sponge: DS,
    _session: PhantomData<S>,
}

/// Construct an unprepared DSFS non-interactive-argument view of a preprocessing body.
#[must_use]
pub const fn preprocessing_non_interactive_argument<IA, S, DS>(
    ia: IA,
    duplex_sponge: DS,
) -> UnpreparedDsfsArgument<IA, S, DS, 0> {
    UnpreparedDsfsArgument::new(ia, duplex_sponge)
}

/// Construct a salted unprepared DSFS non-interactive-argument view of a preprocessing body.
#[must_use]
pub const fn preprocessing_non_interactive_argument_with_salt<IA, S, DS, const SALT_LEN: usize>(
    ia: IA,
    duplex_sponge: DS,
) -> UnpreparedDsfsArgument<IA, S, DS, SALT_LEN> {
    UnpreparedDsfsArgument::new(ia, duplex_sponge)
}

impl<IA, S, DS, const SALT_LEN: usize> UnpreparedDsfsArgument<IA, S, DS, SALT_LEN> {
    #[must_use]
    pub const fn new(ia: IA, duplex_sponge: DS) -> Self {
        Self {
            ia,
            duplex_sponge,
            _session: PhantomData,
        }
    }
}

impl<IA, S, DS, const SALT_LEN: usize> UnpreparedDsfsArgument<IA, S, DS, SALT_LEN>
where
    IA: PreprocessingInteractiveArgument,
{
    pub fn prepare(self, ix: &IA::Index) -> PreparedDsfsArgument<IA, S, DS, SALT_LEN> {
        let (pk, vk) = self.ia.index(ix);
        PreparedDsfsArgument::from_keys(self.ia, pk, vk, self.duplex_sponge)
    }

    pub fn with_keys(
        self,
        pk: IA::ProverKey,
        vk: IA::VerifierKey,
    ) -> PreparedDsfsArgument<IA, S, DS, SALT_LEN> {
        PreparedDsfsArgument::from_keys(self.ia, pk, vk, self.duplex_sponge)
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

/// DSFS compiler wrapper for a preprocessing reduction before keys are prepared.
///
/// This wrapper deliberately does not implement [`NonInteractiveReduction`].
/// Call [`prepare`](Self::prepare) or [`with_keys`](Self::with_keys) to obtain a
/// [`PreparedDsfsReduction`], which then implements
/// [`NonInteractiveReduction`] plus the preprocessing capability.
pub struct UnpreparedDsfsReduction<IR, S, DS = Keccak, const SALT_LEN: usize = 0> {
    ir: IR,
    duplex_sponge: DS,
    _session: PhantomData<S>,
}

/// Construct an unprepared DSFS non-interactive-reduction view of a preprocessing body.
#[must_use]
pub const fn preprocessing_non_interactive_reduction<IR, S, DS>(
    ir: IR,
    duplex_sponge: DS,
) -> UnpreparedDsfsReduction<IR, S, DS, 0> {
    UnpreparedDsfsReduction::new(ir, duplex_sponge)
}

/// Construct a salted unprepared DSFS non-interactive-reduction view of a preprocessing body.
#[must_use]
pub const fn preprocessing_non_interactive_reduction_with_salt<IR, S, DS, const SALT_LEN: usize>(
    ir: IR,
    duplex_sponge: DS,
) -> UnpreparedDsfsReduction<IR, S, DS, SALT_LEN> {
    UnpreparedDsfsReduction::new(ir, duplex_sponge)
}

impl<IR, S, DS, const SALT_LEN: usize> UnpreparedDsfsReduction<IR, S, DS, SALT_LEN> {
    #[must_use]
    pub const fn new(ir: IR, duplex_sponge: DS) -> Self {
        Self {
            ir,
            duplex_sponge,
            _session: PhantomData,
        }
    }
}

impl<IR, S, DS, const SALT_LEN: usize> UnpreparedDsfsReduction<IR, S, DS, SALT_LEN>
where
    IR: PreprocessingInteractiveReduction,
{
    pub fn prepare(self, ix: &IR::Index) -> PreparedDsfsReduction<IR, S, DS, SALT_LEN> {
        let (pk, vk) = self.ir.index(ix);
        PreparedDsfsReduction::from_keys(self.ir, pk, vk, self.duplex_sponge)
    }

    pub fn with_keys(
        self,
        pk: IR::ProverKey,
        vk: IR::VerifierKey,
    ) -> PreparedDsfsReduction<IR, S, DS, SALT_LEN> {
        PreparedDsfsReduction::from_keys(self.ir, pk, vk, self.duplex_sponge)
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
