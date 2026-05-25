//! DSFS non-interactive prove/verify entry points.

extern crate alloc;

use core::marker::PhantomData;

use rand::RngCore;

use ia_core::{
    Encoding, InteractiveArgument, InteractiveReduction, NargDeserialize, NargProof,
    NonInteractiveArgument, NonInteractiveReduction, PreprocessingInteractiveArgument,
    PreprocessingInteractiveReduction,
};

use crate::prepared::{PreparedDsfsArgument, PreparedDsfsReduction};

use spongefish::{DomainSeparator, DuplexSpongeInterface};

use crate::channel::{SpongeProver, SpongeVerifier};
use crate::params::{Keccak, SpongeInfo};

/// Byte-oriented duplex sponge (`U = u8`), matching Keccak and spongefish `StdHash` / SHAKE128.
pub trait ByteDuplexSponge: DuplexSpongeInterface<U = u8> {}

impl<T: DuplexSpongeInterface<U = u8>> ByteDuplexSponge for T {}

/// DSFS compiler wrapper implementing [`NonInteractiveArgument`] for an IA.
///
/// Prefer constructing this with [`non_interactive_argument`].
pub struct DsfsArgument<IA, S, H = Keccak, const SALT_LEN: usize = 0> {
    pub ia: IA,
    pub sponge: H,
    _session: PhantomData<S>,
}

/// Construct the DSFS non-interactive-argument view of an interactive body.
///
/// If `IA: InteractiveArgument`, the returned wrapper implements
/// [`NonInteractiveArgument`] immediately. If `IA: PreprocessingInteractiveArgument`,
/// call `.prepare(&ix)` or `.with_keys(pk, vk)` first; the prepared wrapper then
/// implements [`NonInteractiveArgument`] plus the preprocessing capability.
#[must_use]
pub const fn non_interactive_argument<IA, S, H>(ia: IA, sponge: H) -> DsfsArgument<IA, S, H, 0> {
    DsfsArgument::new(ia, sponge)
}

/// Construct a salted DSFS non-interactive-argument view.
#[must_use]
pub const fn non_interactive_argument_with_salt<IA, S, H, const SALT_LEN: usize>(
    ia: IA,
    sponge: H,
) -> DsfsArgument<IA, S, H, SALT_LEN> {
    DsfsArgument::new(ia, sponge)
}

impl<IA, S, H, const SALT_LEN: usize> DsfsArgument<IA, S, H, SALT_LEN> {
    #[must_use]
    pub const fn new(ia: IA, sponge: H) -> Self {
        Self {
            ia,
            sponge,
            _session: PhantomData,
        }
    }
}

/// Inherent methods that turn a [`DsfsArgument`] over an
/// [`PreprocessingInteractiveArgument`] into a [`PreparedDsfsArgument`] by either running the indexer or accepting
/// externally-stored preprocessing keys. The committed verifier index is always
/// derived from `vk`.
impl<IA, S, H, const SALT_LEN: usize> DsfsArgument<IA, S, H, SALT_LEN>
where
    IA: PreprocessingInteractiveArgument,
{
    pub fn prepare(self, ix: &IA::Index) -> PreparedDsfsArgument<IA, S, H, SALT_LEN> {
        let (pk, vk) = self.ia.index(ix);
        PreparedDsfsArgument::from_keys(self.ia, pk, vk, self.sponge)
    }

    pub fn with_keys(
        self,
        pk: IA::ProverKey,
        vk: IA::VerifierKey,
    ) -> PreparedDsfsArgument<IA, S, H, SALT_LEN> {
        PreparedDsfsArgument::from_keys(self.ia, pk, vk, self.sponge)
    }
}

impl<IA, S, H, const SALT_LEN: usize> NonInteractiveArgument for DsfsArgument<IA, S, H, SALT_LEN>
where
    H: SpongeInfo + Clone,
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
    IA::Instance: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]> + NargDeserialize,
{
    type Session = S;
    type Instance = IA::Instance;
    type Witness = IA::Witness;

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.ia.protocol_id()
    }

    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> NargProof {
        prove_with_sponge_and_salt::<IA, H, S, SALT_LEN>(
            &self.ia,
            self.sponge.clone(),
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
        verify_with_sponge_and_salt::<IA, H, S, SALT_LEN>(
            &self.ia,
            self.sponge.clone(),
            session,
            instance,
            proof.as_bytes(),
        )
    }
}

/// DSFS compiler wrapper implementing [`NonInteractiveReduction`] for an IR.
pub struct DsfsReduction<IR, S, H = Keccak, const SALT_LEN: usize = 0> {
    pub ir: IR,
    pub sponge: H,
    _session: PhantomData<S>,
}

impl<IR, S, H, const SALT_LEN: usize> DsfsReduction<IR, S, H, SALT_LEN> {
    #[must_use]
    pub const fn new(ir: IR, sponge: H) -> Self {
        Self {
            ir,
            sponge,
            _session: PhantomData,
        }
    }
}

/// Construct the DSFS non-interactive-reduction view of an interactive body.
///
/// If `IR: InteractiveReduction`, the returned wrapper implements
/// [`NonInteractiveReduction`] immediately. If `IR: PreprocessingInteractiveReduction`,
/// call `.prepare(&ix)` or `.with_keys(pk, vk)` first; the prepared wrapper then
/// implements [`NonInteractiveReduction`] plus the preprocessing capability.
#[must_use]
pub const fn non_interactive_reduction<IR, S, H>(ir: IR, sponge: H) -> DsfsReduction<IR, S, H, 0> {
    DsfsReduction::new(ir, sponge)
}

/// Construct a salted DSFS non-interactive-reduction view.
#[must_use]
pub const fn non_interactive_reduction_with_salt<IR, S, H, const SALT_LEN: usize>(
    ir: IR,
    sponge: H,
) -> DsfsReduction<IR, S, H, SALT_LEN> {
    DsfsReduction::new(ir, sponge)
}

/// Inherent methods that turn a [`DsfsReduction`] over an
/// [`PreprocessingInteractiveReduction`] into a [`PreparedDsfsReduction`].
impl<IR, S, H, const SALT_LEN: usize> DsfsReduction<IR, S, H, SALT_LEN>
where
    IR: PreprocessingInteractiveReduction,
{
    pub fn prepare(self, ix: &IR::Index) -> PreparedDsfsReduction<IR, S, H, SALT_LEN> {
        let (pk, vk) = self.ir.index(ix);
        PreparedDsfsReduction::from_keys(self.ir, pk, vk, self.sponge)
    }

    pub fn with_keys(
        self,
        pk: IR::ProverKey,
        vk: IR::VerifierKey,
    ) -> PreparedDsfsReduction<IR, S, H, SALT_LEN> {
        PreparedDsfsReduction::from_keys(self.ir, pk, vk, self.sponge)
    }
}

impl<IR, S, H, const SALT_LEN: usize> NonInteractiveReduction for DsfsReduction<IR, S, H, SALT_LEN>
where
    H: SpongeInfo + Clone,
    IR: InteractiveReduction,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]> + NargDeserialize,
{
    type Session = S;
    type SourceInstance = IR::SourceInstance;
    type TargetInstance = IR::TargetInstance;
    type SourceWitness = IR::SourceWitness;
    type TargetWitness = IR::TargetWitness;

    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.ir.protocol_id()
    }

    fn prove(
        &self,
        session: &Self::Session,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (NargProof, Self::TargetInstance, Self::TargetWitness) {
        prove_reduction_with_sponge_and_salt_full::<IR, H, S, SALT_LEN>(
            &self.ir,
            self.sponge.clone(),
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
        verify_reduction_with_sponge_and_salt::<IR, H, S, SALT_LEN>(
            &self.ir,
            self.sponge.clone(),
            session,
            instance,
            proof.as_bytes(),
        )
    }
}

/// Non-interactive prover with explicit salt length and duplex sponge `H`.
#[inline]
pub(crate) fn prove_with_sponge_and_salt<IA, H, S, const SALT_LEN: usize>(
    ia: &IA,
    sponge: H,
    session: &S,
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> NargProof
where
    H: SpongeInfo,
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
    IA::Instance: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]>,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        ia.protocol_id().as_ref(),
        H::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(instance);

    let mut spongefish_prover_ch = SpongeProver::new(domsep.to_prover(sponge));
    let mut salt = [0u8; SALT_LEN];
    spongefish_prover_ch.state.rng().fill_bytes(&mut salt);
    spongefish_prover_ch.state.prover_message(&salt);
    ia.prove(&mut spongefish_prover_ch, instance, witness);
    NargProof::from_bytes(spongefish_prover_ch.narg_string().to_vec())
}

/// Non-interactive verifier with explicit salt length and duplex sponge `H`.
pub(crate) fn verify_with_sponge_and_salt<IA, H, S, const SALT_LEN: usize>(
    ia: &IA,
    sponge: H,
    session: &S,
    instance: &IA::Instance,
    proof: &[u8],
) -> ia_core::VerificationResult<()>
where
    H: SpongeInfo,
    IA: InteractiveArgument,
    S: Encoding<[u8]>,
    IA::Instance: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]> + NargDeserialize,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        ia.protocol_id().as_ref(),
        H::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(instance);

    let mut spongefish_verifier_ch = SpongeVerifier::new(domsep.to_verifier(sponge, proof));
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

fn prove_reduction_with_sponge_and_salt_full<IR, H, S, const SALT_LEN: usize>(
    ir: &IR,
    sponge: H,
    session: &S,
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> (NargProof, IR::TargetInstance, IR::TargetWitness)
where
    H: SpongeInfo,
    IR: InteractiveReduction,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]>,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        ir.protocol_id().as_ref(),
        H::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(instance);

    let mut spongefish_prover_ch = SpongeProver::new(domsep.to_prover(sponge));
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

/// Non-interactive verifier for an IOR with explicit salt length and sponge `H`.
pub(crate) fn verify_reduction_with_sponge_and_salt<IR, H, S, const SALT_LEN: usize>(
    ir: &IR,
    sponge: H,
    session: &S,
    instance: &IR::SourceInstance,
    proof: &[u8],
) -> ia_core::VerificationResult<IR::TargetInstance>
where
    H: SpongeInfo,
    IR: InteractiveReduction,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding<[H::U]>,
    [u8; SALT_LEN]: Encoding<[H::U]> + NargDeserialize,
{
    let session_bytes = session.encode();
    let domsep = DomainSeparator::derive(
        ir.protocol_id().as_ref(),
        H::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(instance);

    let mut spongefish_verifier_ch = SpongeVerifier::new(domsep.to_verifier(sponge, proof));
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
