//! Prepared DSFS wrappers for indexed (preprocessed) protocols.
//!
//! [`super::UnpreparedDsfsArgument`] and [`super::UnpreparedDsfsReduction`]
//! expose `.prepare(&ix)` / `.with_keys(pk, vk)` (in [`super::compile`]) that
//! consume the unprepared wrapper and return a [`PreparedDsfsArgument`] /
//! [`PreparedDsfsReduction`] that
//! implements [`NonInteractiveArgument`] / [`NonInteractiveReduction`] over
//! the *bare* per-claim instance: callers do not construct
//! [`IndexedInstance`](ia_core::IndexedInstance) themselves.
//!
//! Internally the prepared wrappers absorb
//! [`IndexedInstanceRef`](ia_core::IndexedInstanceRef) of `(committed_index,
//! instance)` through the existing `DomainSeparator::derive(...).instance(...)`
//! path. The committed verifier index is therefore bound before the first
//! challenge by the same mechanism that already binds the plain instance.

extern crate alloc;

use core::marker::PhantomData;

use rand::RngCore;

use ia_core::{
    ArgumentCore, CommittedIndexBytes, Encoding, IndexedInstanceRef, NargDeserialize, NargProof,
    NonInteractiveArgument, NonInteractiveReduction, Preprocessed,
    PreprocessingInteractiveArgument, PreprocessingInteractiveReduction, ProtocolCore,
    ReductionCore, VerificationError, VerificationResult, VerifierKeyCommitment,
};

use spongefish::DomainSeparator;

use crate::channel::{SpongeProver, SpongeVerifier};
use crate::params::{Keccak, SpongeInfo};

/// DSFS wrapper for an indexed argument with preprocessing keys derived (or
/// supplied) up front.
///
/// Created via [`super::UnpreparedDsfsArgument::prepare`] or
/// [`super::UnpreparedDsfsArgument::with_keys`].
pub struct PreparedDsfsArgument<
    IA: PreprocessingInteractiveArgument,
    S,
    DS = Keccak,
    const SALT_LEN: usize = 0,
> {
    ia: IA,
    pk: IA::ProverKey,
    vk: IA::VerifierKey,
    committed_index: CommittedIndexBytes,
    duplex_sponge: DS,
    _session: PhantomData<S>,
}

impl<IA: PreprocessingInteractiveArgument, S, DS, const SALT_LEN: usize>
    PreparedDsfsArgument<IA, S, DS, SALT_LEN>
{
    /// Construct from an already-keyed indexed body. The committed index is
    /// derived from `vk` (Invariant 6).
    pub(crate) fn from_keys(
        ia: IA,
        pk: IA::ProverKey,
        vk: IA::VerifierKey,
        duplex_sponge: DS,
    ) -> Self {
        let committed_index = vk.committed_index();
        Self {
            ia,
            pk,
            vk,
            committed_index,
            duplex_sponge,
            _session: PhantomData,
        }
    }

    pub fn committed_index(&self) -> &CommittedIndexBytes {
        &self.committed_index
    }

    pub fn body(&self) -> &IA {
        &self.ia
    }

    pub fn prover_key(&self) -> &IA::ProverKey {
        &self.pk
    }

    pub fn verifier_key(&self) -> &IA::VerifierKey {
        &self.vk
    }
}

impl<IA, S, DS, const SALT_LEN: usize> ProtocolCore for PreparedDsfsArgument<IA, S, DS, SALT_LEN>
where
    IA: PreprocessingInteractiveArgument,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.ia.protocol_id()
    }
}

impl<IA, S, DS, const SALT_LEN: usize> ArgumentCore for PreparedDsfsArgument<IA, S, DS, SALT_LEN>
where
    IA: PreprocessingInteractiveArgument,
{
    type Instance = IA::Instance;
    type Witness = IA::Witness;
}

impl<IA, S, DS, const SALT_LEN: usize> NonInteractiveArgument
    for PreparedDsfsArgument<IA, S, DS, SALT_LEN>
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
        session: &Self::Session,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> NargProof {
        prepared_prove_with_sponge_and_salt::<IA, DS, S, SALT_LEN>(
            &self.ia,
            &self.pk,
            &self.committed_index,
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
    ) -> VerificationResult<()> {
        prepared_verify_with_sponge_and_salt::<IA, DS, S, SALT_LEN>(
            &self.ia,
            &self.vk,
            &self.committed_index,
            self.duplex_sponge.clone(),
            session,
            instance,
            proof.as_bytes(),
        )
    }
}

impl<IA, S, DS, const SALT_LEN: usize> Preprocessed for PreparedDsfsArgument<IA, S, DS, SALT_LEN>
where
    IA: PreprocessingInteractiveArgument,
{
    type ProverKey = IA::ProverKey;
    type VerifierKey = IA::VerifierKey;

    fn prover_key(&self) -> &Self::ProverKey {
        &self.pk
    }

    fn verifier_key(&self) -> &Self::VerifierKey {
        &self.vk
    }

    fn committed_index(&self) -> &CommittedIndexBytes {
        &self.committed_index
    }
}

/// DSFS wrapper for an indexed reduction with preprocessing keys derived (or
/// supplied) up front.
///
/// Created via [`super::UnpreparedDsfsReduction::prepare`] or
/// [`super::UnpreparedDsfsReduction::with_keys`].
pub struct PreparedDsfsReduction<
    IR: PreprocessingInteractiveReduction,
    S,
    DS = Keccak,
    const SALT_LEN: usize = 0,
> {
    ir: IR,
    pk: IR::ProverKey,
    vk: IR::VerifierKey,
    committed_index: CommittedIndexBytes,
    duplex_sponge: DS,
    _session: PhantomData<S>,
}

impl<IR: PreprocessingInteractiveReduction, S, DS, const SALT_LEN: usize>
    PreparedDsfsReduction<IR, S, DS, SALT_LEN>
{
    pub(crate) fn from_keys(
        ir: IR,
        pk: IR::ProverKey,
        vk: IR::VerifierKey,
        duplex_sponge: DS,
    ) -> Self {
        let committed_index = vk.committed_index();
        Self {
            ir,
            pk,
            vk,
            committed_index,
            duplex_sponge,
            _session: PhantomData,
        }
    }

    pub fn committed_index(&self) -> &CommittedIndexBytes {
        &self.committed_index
    }

    pub fn body(&self) -> &IR {
        &self.ir
    }

    pub fn prover_key(&self) -> &IR::ProverKey {
        &self.pk
    }

    pub fn verifier_key(&self) -> &IR::VerifierKey {
        &self.vk
    }
}

impl<IR, S, DS, const SALT_LEN: usize> ProtocolCore for PreparedDsfsReduction<IR, S, DS, SALT_LEN>
where
    IR: PreprocessingInteractiveReduction,
{
    fn protocol_id(&self) -> impl AsRef<[u8]> {
        self.ir.protocol_id()
    }
}

impl<IR, S, DS, const SALT_LEN: usize> ReductionCore for PreparedDsfsReduction<IR, S, DS, SALT_LEN>
where
    IR: PreprocessingInteractiveReduction,
{
    type SourceInstance = IR::SourceInstance;
    type TargetInstance = IR::TargetInstance;
    type SourceWitness = IR::SourceWitness;
    type TargetWitness = IR::TargetWitness;
}

impl<IR, S, DS, const SALT_LEN: usize> NonInteractiveReduction
    for PreparedDsfsReduction<IR, S, DS, SALT_LEN>
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
        session: &Self::Session,
        instance: &Self::SourceInstance,
        witness: &Self::SourceWitness,
    ) -> (NargProof, Self::TargetInstance, Self::TargetWitness) {
        prepared_prove_reduction_with_sponge_and_salt::<IR, DS, S, SALT_LEN>(
            &self.ir,
            &self.pk,
            &self.committed_index,
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
    ) -> VerificationResult<Self::TargetInstance> {
        prepared_verify_reduction_with_sponge_and_salt::<IR, DS, S, SALT_LEN>(
            &self.ir,
            &self.vk,
            &self.committed_index,
            self.duplex_sponge.clone(),
            session,
            instance,
            proof.as_bytes(),
        )
    }
}

impl<IR, S, DS, const SALT_LEN: usize> Preprocessed for PreparedDsfsReduction<IR, S, DS, SALT_LEN>
where
    IR: PreprocessingInteractiveReduction,
{
    type ProverKey = IR::ProverKey;
    type VerifierKey = IR::VerifierKey;

    fn prover_key(&self) -> &Self::ProverKey {
        &self.pk
    }

    fn verifier_key(&self) -> &Self::VerifierKey {
        &self.vk
    }

    fn committed_index(&self) -> &CommittedIndexBytes {
        &self.committed_index
    }
}

// ---------------------------------------------------------------------------
// Indexed DSFS runners
// ---------------------------------------------------------------------------

fn prepared_prove_with_sponge_and_salt<IA, DS, S, const SALT_LEN: usize>(
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
    IA: PreprocessingInteractiveArgument,
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

fn prepared_verify_with_sponge_and_salt<IA, DS, S, const SALT_LEN: usize>(
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
    IA: PreprocessingInteractiveArgument,
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

fn prepared_prove_reduction_with_sponge_and_salt<IR, DS, S, const SALT_LEN: usize>(
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
    IR: PreprocessingInteractiveReduction,
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

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;

    use ia_core::{
        ArgumentCore, CommittedIndexBytes, NonInteractiveArgument, NonInteractiveReduction,
        Preprocessed, PreprocessingCore, PreprocessingInteractiveArgument,
        PreprocessingInteractiveReduction, PreprocessingNonInteractiveArgument,
        PreprocessingNonInteractiveReduction, ProtocolCore, ProverChannel, ReductionCore,
        VerificationError, VerificationResult, VerifierChannel, VerifierKeyCommitment,
    };

    use crate::params::Keccak;
    use crate::{
        preprocessing_non_interactive_argument, preprocessing_non_interactive_reduction,
        PreparedDsfsArgument,
    };

    /// Minimal indexed argument: index is a `Vec<u8>` exposed as the verifier-
    /// key commitment; prover sends a one-byte message; verifier accepts when
    /// it equals 0xAB.
    #[derive(Default)]
    struct DummyIndexedArg;

    #[derive(Clone)]
    struct DummyVk(Vec<u8>);

    impl VerifierKeyCommitment for DummyVk {
        fn committed_index(&self) -> CommittedIndexBytes {
            CommittedIndexBytes::new(self.0.clone())
        }
    }

    impl ProtocolCore for DummyIndexedArg {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"dummy-prepared-arg")
        }
    }

    impl ArgumentCore for DummyIndexedArg {
        type Instance = [u8; 1];
        type Witness = [u8; 1];
    }

    impl PreprocessingCore for DummyIndexedArg {
        type Index = Vec<u8>;
        type ProverKey = ();
        type VerifierKey = DummyVk;

        fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            ((), DummyVk(ix.clone()))
        }
    }

    impl PreprocessingInteractiveArgument for DummyIndexedArg {
        fn prove<P: ProverChannel>(
            &self,
            ch: &mut P,
            _: &Self::ProverKey,
            _: &Self::Instance,
            witness: &Self::Witness,
        ) {
            // Send witness, squeeze a challenge from the duplex sponge, echo it back.
            // The echo lets the verifier detect any transcript-state divergence
            // (e.g., a different committed index) by checking that its squeezed
            // challenge matches the one the prover absorbed.
            ch.send_prover_message(witness);
            let c: [u8; 8] = ch.read_verifier_message();
            ch.send_prover_message(&c);
        }

        fn verify<V: VerifierChannel>(
            &self,
            ch: &mut V,
            _: &Self::VerifierKey,
            _: &Self::Instance,
        ) -> VerificationResult<()> {
            let m: [u8; 1] = ch.read_prover_message()?;
            if m[0] != 0xAB {
                return Err(VerificationError);
            }
            let c: [u8; 8] = ch.send_verifier_message();
            let echoed: [u8; 8] = ch.read_prover_message()?;
            if c == echoed {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }

    /// Indexed reduction whose target instance is the source XOR'd with the
    /// verifier-key byte. Prover sends no messages; commitment binding is the
    /// only thing under test here.
    struct XorWithKey;

    #[derive(Clone)]
    struct XorVk(u8);

    impl VerifierKeyCommitment for XorVk {
        fn committed_index(&self) -> CommittedIndexBytes {
            CommittedIndexBytes::new(vec![self.0])
        }
    }

    impl ProtocolCore for XorWithKey {
        fn protocol_id(&self) -> impl AsRef<[u8]> {
            ia_core::pad_protocol_id(b"xor-with-key")
        }
    }

    impl ReductionCore for XorWithKey {
        type SourceInstance = [u8; 1];
        type TargetInstance = [u8; 1];
        type SourceWitness = ();
        type TargetWitness = ();
    }

    impl PreprocessingCore for XorWithKey {
        type Index = u8;
        type ProverKey = u8;
        type VerifierKey = XorVk;

        fn index(&self, ix: &Self::Index) -> (Self::ProverKey, Self::VerifierKey) {
            (*ix, XorVk(*ix))
        }
    }

    impl PreprocessingInteractiveReduction for XorWithKey {
        fn prove<P: ProverChannel>(
            &self,
            ch: &mut P,
            pk: &Self::ProverKey,
            instance: &Self::SourceInstance,
            _: &Self::SourceWitness,
        ) -> (Self::TargetInstance, Self::TargetWitness) {
            // Echo-challenge for transcript-binding observability (see
            // DummyIndexedArg::prove).
            let c: [u8; 8] = ch.read_verifier_message();
            ch.send_prover_message(&c);
            ([instance[0] ^ *pk], ())
        }

        fn verify<V: VerifierChannel>(
            &self,
            ch: &mut V,
            vk: &Self::VerifierKey,
            instance: &Self::SourceInstance,
        ) -> VerificationResult<Self::TargetInstance> {
            let c: [u8; 8] = ch.send_verifier_message();
            let echoed: [u8; 8] = ch.read_prover_message()?;
            if c != echoed {
                return Err(VerificationError);
            }
            Ok([instance[0] ^ vk.0])
        }
    }

    #[test]
    fn prepared_dsfs_round_trip_succeeds() {
        let prepared = preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            DummyIndexedArg,
            Keccak::default(),
        )
        .prepare(&vec![1, 2, 3]);
        let session = [0u8; 64];
        let instance = [0u8; 1];
        let witness = [0xABu8];
        let proof = prepared.prove(&session, &instance, &witness);
        prepared
            .verify(&session, &instance, &proof)
            .expect("round-trip verification succeeds");
    }

    #[test]
    fn prepared_dsfs_with_keys_round_trip_succeeds() {
        let prepared = preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            DummyIndexedArg,
            Keccak::default(),
        )
        .with_keys((), DummyVk(vec![42]));
        let session = [0u8; 64];
        let instance = [0u8; 1];
        let witness = [0xABu8];
        let proof = prepared.prove(&session, &instance, &witness);
        prepared.verify(&session, &instance, &proof).unwrap();
    }

    #[test]
    fn prepared_dsfs_verify_rejects_proof_from_different_committed_index() {
        // Prover and verifier use *different* indices => different vk bytes
        // => different transcripts => verification must fail.
        let prover_prepared = preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            DummyIndexedArg,
            Keccak::default(),
        )
        .prepare(&vec![1, 2, 3]);
        let verifier_prepared = preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            DummyIndexedArg,
            Keccak::default(),
        )
        .prepare(&vec![9, 9, 9]);
        assert_ne!(
            prover_prepared.committed_index(),
            verifier_prepared.committed_index()
        );

        let session = [0u8; 64];
        let instance = [0u8; 1];
        let witness = [0xABu8];
        let proof = prover_prepared.prove(&session, &instance, &witness);
        assert!(verifier_prepared
            .verify(&session, &instance, &proof)
            .is_err());
    }

    #[test]
    fn prepared_dsfs_verify_rejects_trailing_proof_bytes() {
        let prepared = preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            DummyIndexedArg,
            Keccak::default(),
        )
        .prepare(&vec![1, 2, 3]);
        let session = [0u8; 64];
        let instance = [0u8; 1];
        let witness = [0xABu8];
        let mut proof_bytes = prepared.prove(&session, &instance, &witness).into_bytes();
        proof_bytes.push(0);
        let proof = ia_core::NargProof::from_bytes(proof_bytes);
        assert!(prepared.verify(&session, &instance, &proof).is_err());
    }

    #[test]
    fn prepared_dsfs_reduction_round_trip_returns_target() {
        let prepared = preprocessing_non_interactive_reduction::<_, [u8; 64], _>(
            XorWithKey,
            Keccak::default(),
        )
        .prepare(&0x5Au8);
        let session = [0u8; 64];
        let instance = [0x42u8];
        let (proof, target_p, ()) = prepared.prove(&session, &instance, &());
        let target_v = prepared.verify(&session, &instance, &proof).unwrap();
        assert_eq!(target_p, target_v);
        assert_eq!(target_p, [0x42 ^ 0x5A]);
    }

    #[test]
    fn prepared_dsfs_reduction_verify_rejects_different_committed_index() {
        let prover_prepared = preprocessing_non_interactive_reduction::<_, [u8; 64], _>(
            XorWithKey,
            Keccak::default(),
        )
        .prepare(&0x5Au8);
        let verifier_prepared = preprocessing_non_interactive_reduction::<_, [u8; 64], _>(
            XorWithKey,
            Keccak::default(),
        )
        .prepare(&0x77u8);

        let session = [0u8; 64];
        let instance = [0x42u8];
        let (proof, _, ()) = prover_prepared.prove(&session, &instance, &());
        assert!(verifier_prepared
            .verify(&session, &instance, &proof)
            .is_err());
    }

    /// Sanity check: prepared adapter's protocol_id delegates to the indexed
    /// body. Guards against future refactors of PreparedDsfsArgument::protocol_id.
    #[test]
    fn prepared_dsfs_protocol_id_delegates_to_body() {
        let prepared = preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            DummyIndexedArg,
            Keccak::default(),
        )
        .prepare(&vec![]);
        let expected = ProtocolCore::protocol_id(&DummyIndexedArg);
        assert_eq!(
            <PreparedDsfsArgument<DummyIndexedArg, [u8; 64]> as ProtocolCore>::protocol_id(
                &prepared
            )
            .as_ref(),
            expected.as_ref()
        );
    }

    /// Generic-consumer test: a function bound by PreprocessingNonInteractiveArgument
    /// can pull the committed index off any preprocessed NARG without knowing
    /// its concrete type. This is the polymorphism story the trait was added
    /// for (audit trails, key persistence, etc.).
    #[test]
    fn prepared_dsfs_exposes_committed_index_via_trait_method() {
        fn audit<N: PreprocessingNonInteractiveArgument>(narg: &N) -> CommittedIndexBytes {
            narg.committed_index().clone()
        }
        let prepared = preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            DummyIndexedArg,
            Keccak::default(),
        )
        .prepare(&vec![1, 2, 3]);
        assert_eq!(audit(&prepared).as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn prepared_dsfs_reduction_exposes_committed_index_via_trait_method() {
        fn audit<N: PreprocessingNonInteractiveReduction>(narg: &N) -> CommittedIndexBytes {
            narg.committed_index().clone()
        }
        let prepared = preprocessing_non_interactive_reduction::<_, [u8; 64], _>(
            XorWithKey,
            Keccak::default(),
        )
        .prepare(&0x5Au8);
        assert_eq!(audit(&prepared).as_bytes(), &[0x5A]);
    }

    /// Generic-consumer test: the `Preprocessed` capability is the single
    /// discoverable home for preprocessing keys. A consumer bounded directly
    /// by `Preprocessed` can reach `verifier_key()` (and `prover_key()` /
    /// `committed_index()`) on any prepared wrapper, regardless of which
    /// lattice plane it sits on.
    #[test]
    fn preprocessed_capability_exposes_verifier_key_polymorphically() {
        fn vk_bytes<W: Preprocessed>(w: &W) -> Vec<u8>
        where
            W::VerifierKey: Clone,
        {
            w.verifier_key().committed_index().as_bytes().to_vec()
        }
        let arg_prepared = preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            DummyIndexedArg,
            Keccak::default(),
        )
        .prepare(&vec![1, 2, 3]);
        let red_prepared = preprocessing_non_interactive_reduction::<_, [u8; 64], _>(
            XorWithKey,
            Keccak::default(),
        )
        .prepare(&0x77u8);
        // Same generic function works on both planes.
        assert_eq!(vk_bytes(&arg_prepared), vec![1, 2, 3]);
        assert_eq!(vk_bytes(&red_prepared), vec![0x77]);
    }

    /// Confirms the PreprocessingNonInteractive* marker traits dispatch to the
    /// Preprocessed accessors (blanket impl wiring).
    #[test]
    fn preprocessing_nia_marker_pulls_keys_from_preprocessed_supertrait() {
        fn extract<N: PreprocessingNonInteractiveArgument>(
            narg: &N,
        ) -> (&N::VerifierKey, &CommittedIndexBytes) {
            (narg.verifier_key(), narg.committed_index())
        }
        let prepared = preprocessing_non_interactive_argument::<_, [u8; 64], _>(
            DummyIndexedArg,
            Keccak::default(),
        )
        .prepare(&vec![9, 9]);
        let (vk, ci) = extract(&prepared);
        assert_eq!(vk.0, vec![9, 9]);
        assert_eq!(ci.as_bytes(), &[9, 9]);
    }
}

fn prepared_verify_reduction_with_sponge_and_salt<IR, DS, S, const SALT_LEN: usize>(
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
    IR: PreprocessingInteractiveReduction,
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
