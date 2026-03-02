use std::path::PathBuf;

use thiserror::Error;

use crate::consensus_bls::PeerId;

pub type DkgResult<T> = Result<T, DkgError>;
pub type ThresholdSetupResult<T> = Result<T, ThresholdSetupError>;

#[derive(Debug, Error)]
pub enum DkgError {
    #[error("threshold must be greater than zero")]
    ThresholdMustBePositive,
    #[error("threshold {threshold} cannot exceed total participants {total_participants}")]
    ThresholdExceedsParticipants {
        threshold: usize,
        total_participants: usize,
    },
    #[error("participant index must be non-zero")]
    ParticipantIndexZero,
    #[error("participant index {index} exceeds total participants {total_participants}")]
    ParticipantIndexOutOfRange {
        index: u64,
        total_participants: usize,
    },
    #[error("missing polynomial coefficient at index {index}")]
    MissingPolynomialCoefficient { index: usize },
    #[error("share dealer index {share_dealer} does not match bundle dealer index {bundle_dealer}")]
    ShareDealerMismatch {
        share_dealer: u64,
        bundle_dealer: u64,
    },
    #[error(
        "invalid commitment bundle for dealer {dealer_index}: commitments={commitments} threshold={threshold}"
    )]
    InvalidCommitmentBundle {
        dealer_index: u64,
        commitments: usize,
        threshold: usize,
    },
    #[error("cannot aggregate empty verified share set for recipient {recipient_index}")]
    EmptyVerifiedShares { recipient_index: u64 },
    #[error("share recipient mismatch: expected {expected}, got {actual}")]
    ShareRecipientMismatch { expected: u64, actual: u64 },
    #[error("cannot derive group public key from empty commitment set")]
    EmptyCommitmentSet,
    #[error("invalid faulty bound: f={max_faulty} must be < n={total_participants}")]
    FaultyBoundOutOfRange {
        max_faulty: usize,
        total_participants: usize,
    },
    #[error("share verification failed: dealer {dealer_index} -> recipient {recipient_index}")]
    ShareVerificationFailed {
        dealer_index: u64,
        recipient_index: u64,
    },
    #[error("BLS operation failed: {0}")]
    BlsOperation(String),
}

#[derive(Debug, Error)]
pub enum ThresholdSetupError {
    #[error("failed to read threshold setup artifact from '{path}'")]
    ArtifactRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse threshold setup artifact JSON from '{path}'")]
    ArtifactParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("threshold setup peer_id mismatch: artifact={artifact} local={local}")]
    PeerIdMismatch { artifact: PeerId, local: PeerId },
    #[error(
        "threshold setup (n,f)=({artifact_n}, {artifact_f}) does not match consensus config ({expected_n}, {expected_f})"
    )]
    ThresholdParamsMismatch {
        artifact_n: usize,
        artifact_f: usize,
        expected_n: usize,
        expected_f: usize,
    },
    #[error("invalid participant_index {participant_index} for n={n}")]
    ParticipantIndexOutOfRange { participant_index: u64, n: usize },
    #[error(
        "threshold setup validator participant list size mismatch: expected {expected}, got {actual}"
    )]
    InvalidCommitmentSetSize { actual: usize, expected: usize },
    #[error("threshold setup contains duplicate peer_id in validator participants: {peer_id}")]
    DuplicatePeerIdInParticipants { peer_id: PeerId },
    #[error(
        "threshold setup contains duplicate participant_index in validator participants: {participant_index}"
    )]
    DuplicateParticipantIndex { participant_index: u64 },
    #[error(
        "threshold setup validator_set_id mismatch: artifact='{artifact}' expected='{expected}'"
    )]
    ValidatorSetMismatch { artifact: String, expected: String },
    #[error("invalid m_nullify threshold {actual} (expected {expected})")]
    InvalidMNullifyThreshold { actual: usize, expected: usize },
    #[error("invalid l_notarization threshold {actual} (expected {expected})")]
    InvalidLNotarizationThreshold { actual: usize, expected: usize },
    #[error("threshold setup domain tags must be non-empty")]
    EmptyDomainTags,
    #[error("threshold setup domain tags must be unique across m_not/nullify/l_not")]
    DuplicateDomainTags,
    #[error("invalid threshold setup group public key '{field}' encoding")]
    InvalidGroupPublicKeyEncoding {
        field: &'static str,
        #[source]
        source: hex::FromHexError,
    },
    #[error(
        "threshold setup group public key '{field}' must be exactly {expected} bytes, got {actual}"
    )]
    InvalidGroupPublicKeyLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid threshold setup group public key '{field}' bytes")]
    InvalidGroupPublicKeyBytes {
        field: &'static str,
        error_code: blst::BLST_ERROR,
    },
    #[error("invalid threshold setup secret share '{field}' hex")]
    InvalidSecretShareEncoding {
        field: &'static str,
        #[source]
        source: hex::FromHexError,
    },
    #[error("threshold setup secret share '{field}' must be exactly 32 bytes, got {actual}")]
    InvalidSecretShareLength { field: &'static str, actual: usize },
}
