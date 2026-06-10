//! Indexed DSFS prove/verify runners.
//!
//! These take the prover/verifier key and the committed index as explicit
//! arguments (the compiled object is stateless). They bind
//! `IndexedInstanceRef { committed_index, instance }` before the first challenge
//! via the existing `DomainSeparator::derive(...).instance(...)` path, so proof
//! bytes are identical to the previous key-storing wrappers.

extern crate alloc;

use ia_core::{
    CommittedIndexBytes, Encoding, IndexedInstanceRef, NargDeserialize, NargProof,
    PreprocessingInteractiveArgumentProver, PreprocessingInteractiveArgumentVerifier,
    PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
    VerificationError, VerificationResult,
};
use rand::RngCore;
use spongefish::DomainSeparator;

use crate::{
    channel::{SpongeProver, SpongeVerifier},
    params::SpongeInfo,
};

pub fn prepared_prove_with_sponge_and_salt<IA, DS, S, const SALT_LEN: usize>(
    ia: &IA,
    pk: &IA::ProverKey,
    committed_index: &CommittedIndexBytes,
    duplex_sponge: DS,
    session: &S,
    instance: &IA::Instance,
    witness: &IA::Witness,
) -> NargProof
where
    DS: SpongeInfo,
    IA: PreprocessingInteractiveArgumentProver,
    S: Encoding<[u8]>,
    IA::Instance: Encoding<[u8]>,
    [u8; SALT_LEN]: Encoding<[DS::U]>,
{
    let session_bytes = session.encode();
    let public_input = IndexedInstanceRef::new(committed_index, instance);
    let domsep = DomainSeparator::derive(
        ia.protocol_id().as_ref(),
        DS::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(&public_input);

    let mut prover_ch = SpongeProver::new(domsep.to_prover(duplex_sponge));
    let mut salt = [0u8; SALT_LEN];
    prover_ch.state.rng().fill_bytes(&mut salt);
    prover_ch.state.prover_message(&salt);
    ia.prove(&mut prover_ch, pk, instance, witness);
    NargProof::from_bytes(prover_ch.narg_string().to_vec())
}

pub fn prepared_verify_with_sponge_and_salt<IA, DS, S, const SALT_LEN: usize>(
    ia: &IA,
    vk: &IA::VerifierKey,
    committed_index: &CommittedIndexBytes,
    duplex_sponge: DS,
    session: &S,
    instance: &IA::Instance,
    proof: &[u8],
) -> VerificationResult<()>
where
    DS: SpongeInfo,
    IA: PreprocessingInteractiveArgumentVerifier,
    S: Encoding<[u8]>,
    IA::Instance: Encoding<[u8]>,
    [u8; SALT_LEN]: Encoding<[DS::U]> + NargDeserialize,
{
    let session_bytes = session.encode();
    let public_input = IndexedInstanceRef::new(committed_index, instance);
    let domsep = DomainSeparator::derive(
        ia.protocol_id().as_ref(),
        DS::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(&public_input);

    let mut verifier_ch = SpongeVerifier::new(domsep.to_verifier(duplex_sponge, proof));
    let _salt: [u8; SALT_LEN] = verifier_ch
        .state
        .prover_message()
        .map_err(|_| VerificationError)?;
    ia.verify(&mut verifier_ch, vk, instance)?;
    verifier_ch.state.check_eof().map_err(|_| VerificationError)
}

pub fn prepared_prove_reduction_with_sponge_and_salt<IR, DS, S, const SALT_LEN: usize>(
    ir: &IR,
    pk: &IR::ProverKey,
    committed_index: &CommittedIndexBytes,
    duplex_sponge: DS,
    session: &S,
    instance: &IR::SourceInstance,
    witness: &IR::SourceWitness,
) -> (NargProof, IR::TargetInstance, IR::TargetWitness)
where
    DS: SpongeInfo,
    IR: PreprocessingInteractiveReductionProver,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding<[u8]>,
    [u8; SALT_LEN]: Encoding<[DS::U]>,
{
    let session_bytes = session.encode();
    let public_input = IndexedInstanceRef::new(committed_index, instance);
    let domsep = DomainSeparator::derive(
        ir.protocol_id().as_ref(),
        DS::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(&public_input);

    let mut prover_ch = SpongeProver::new(domsep.to_prover(duplex_sponge));
    let mut salt = [0u8; SALT_LEN];
    prover_ch.state.rng().fill_bytes(&mut salt);
    prover_ch.state.prover_message(&salt);
    let (target_instance, target_witness) = ir.prove(&mut prover_ch, pk, instance, witness);
    (
        NargProof::from_bytes(prover_ch.narg_string().to_vec()),
        target_instance,
        target_witness,
    )
}

pub fn prepared_verify_reduction_with_sponge_and_salt<IR, DS, S, const SALT_LEN: usize>(
    ir: &IR,
    vk: &IR::VerifierKey,
    committed_index: &CommittedIndexBytes,
    duplex_sponge: DS,
    session: &S,
    instance: &IR::SourceInstance,
    proof: &[u8],
) -> VerificationResult<IR::TargetInstance>
where
    DS: SpongeInfo,
    IR: PreprocessingInteractiveReductionVerifier,
    S: Encoding<[u8]>,
    IR::SourceInstance: Encoding<[u8]>,
    [u8; SALT_LEN]: Encoding<[DS::U]> + NargDeserialize,
{
    let session_bytes = session.encode();
    let public_input = IndexedInstanceRef::new(committed_index, instance);
    let domsep = DomainSeparator::derive(
        ir.protocol_id().as_ref(),
        DS::SPONGE_INFO,
        session_bytes.as_ref(),
    )
    .instance(&public_input);

    let mut verifier_ch = SpongeVerifier::new(domsep.to_verifier(duplex_sponge, proof));
    let _salt: [u8; SALT_LEN] = verifier_ch
        .state
        .prover_message()
        .map_err(|_| VerificationError)?;
    let target = ir.verify(&mut verifier_ch, vk, instance)?;
    verifier_ch
        .state
        .check_eof()
        .map_err(|_| VerificationError)?;
    Ok(target)
}
