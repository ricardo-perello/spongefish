//! Round-trip and byte-fixture tests for the compiled DSFS roles.

use alloc::vec;

use ia_core::{
    ArgumentCore, ArgumentProverCore, CommittedIndex, CommittedIndexBytes, NargProof,
    InteractiveArgumentProver,
    InteractiveArgumentVerifier, InteractiveReductionProver, InteractiveReductionVerifier,
    NonInteractiveArgumentProver, NonInteractiveArgumentVerifier,
    NonInteractiveReductionProver, NonInteractiveReductionVerifier,
    PreprocessingInteractiveArgumentProver, PreprocessingInteractiveArgumentVerifier,
    PreprocessingInteractiveReductionProver, PreprocessingInteractiveReductionVerifier,
    PreprocessingNonInteractiveArgumentProver, PreprocessingNonInteractiveArgumentVerifier,
    PreprocessingNonInteractiveReductionProver, PreprocessingNonInteractiveReductionVerifier,
    ProtocolCore, ProverChannel, ReductionCore, ReductionProverCore, VerificationError,
    VerificationResult, VerifierChannel,
};

use super::*;

const SESSION: [u8; 1] = [9];

#[test]
fn framed_instance_is_prefix_free_and_tagged() {
    // Under the identity byte encoding, `[1]` is a prefix of `[1, 2]` — the
    // exact ambiguity the plain-path framing removes.
    let a: &[u8] = &[1];
    let b: &[u8] = &[1, 2];
    let fa_inst = FramedInstance(a);
    let fb_inst = FramedInstance(b);
    let fa = fa_inst.encode();
    let fb = fb_inst.encode();
    assert!(fa.as_ref().starts_with(PLAIN_INSTANCE_TAG));
    assert!(fb.as_ref().starts_with(PLAIN_INSTANCE_TAG));
    // The length prefix makes neither framed encoding a prefix of the other.
    assert!(!fb.as_ref().starts_with(fa.as_ref()));
    assert_ne!(fa.as_ref(), fb.as_ref());
}

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
    let prover = argument_prover::<_, [u8; 1], _>(
        ArgumentProver,
        Keccak::default(),
    );
    let verifier = argument_verifier::<_, [u8; 1], _>(
        ArgumentVerifier,
        Keccak::default(),
    );
    let proof = prover.prove(&SESSION, &7, &7);
    // First four bytes are the witness message `7u32` (absorbed before any
    // challenge, so unaffected by instance framing); the last four are the
    // response `7 ^ challenge`, whose challenge now depends on the framed
    // (tagged, length-prefixed) instance — see `FramedInstance`.
    assert_eq!(proof.as_bytes(), &[7, 0, 0, 0, 118, 138, 122, 151]);
    verifier.verify(&SESSION, &7, &proof).unwrap();
    let mut trailing = proof.into_bytes();
    trailing.push(0);
    assert!(verifier
        .verify(&SESSION, &7, &NargProof::from_bytes(trailing))
        .is_err());
}

#[test]
fn plain_reduction_fixture_and_eof_rejection() {
    let prover = reduction_prover::<_, [u8; 1], _>(
        ReductionProver,
        Keccak::default(),
    );
    let verifier = reduction_verifier::<_, [u8; 1], _>(
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
    let prover = preprocessing_argument_prover::<_, [u8; 1], _>(
        IndexedArgumentProver,
        Keccak::default(),
    );
    let verifier = preprocessing_argument_verifier::<_, [u8; 1], _>(
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
    let prover = preprocessing_reduction_prover::<_, [u8; 1], _>(
        IndexedReductionProver,
        Keccak::default(),
    );
    let verifier = preprocessing_reduction_verifier::<_, [u8; 1], _>(
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
    let argument_prover = argument_prover_with_salt::<_, [u8; 1], _, 8>(
        ArgumentProver,
        Keccak::default(),
    );
    let argument_verifier = argument_verifier_with_salt::<_, [u8; 1], _, 8>(
        ArgumentVerifier,
        Keccak::default(),
    );
    let argument_proof = argument_prover.prove(&SESSION, &7, &7);
    argument_verifier
        .verify(&SESSION, &7, &argument_proof)
        .unwrap();

    let reduction_prover = reduction_prover_with_salt::<_, [u8; 1], _, 8>(
        ReductionProver,
        Keccak::default(),
    );
    let reduction_verifier =
        reduction_verifier_with_salt::<_, [u8; 1], _, 8>(
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
        preprocessing_argument_prover_with_salt::<_, [u8; 1], _, 8>(
            IndexedArgumentProver,
            Keccak::default(),
        );
    let indexed_argument_verifier =
        preprocessing_argument_verifier_with_salt::<_, [u8; 1], _, 8>(
            IndexedArgumentVerifier,
            Keccak::default(),
        );
    let indexed_argument_proof = indexed_argument_prover.prove(&key, &SESSION, &17, &17);
    indexed_argument_verifier
        .verify(&key, &SESSION, &17, &indexed_argument_proof)
        .unwrap();

    let indexed_reduction_prover =
        preprocessing_reduction_prover_with_salt::<_, [u8; 1], _, 8>(
            IndexedReductionProver,
            Keccak::default(),
        );
    let indexed_reduction_verifier =
        preprocessing_reduction_verifier_with_salt::<_, [u8; 1], _, 8>(
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
