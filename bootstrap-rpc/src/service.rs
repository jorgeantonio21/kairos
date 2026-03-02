use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

use crypto::dkg::{
    DkgCommitmentBundle, DkgShare, ParticipantShare, aggregate_verified_shares,
    derive_group_public_key, derive_participant_public_key, verify_share,
};
use crypto::threshold_setup::{
    ThresholdDomains, ThresholdKeyset, ThresholdKeysets, ThresholdSetupArtifact,
    ValidatorParticipant,
};
use crypto::{consensus_bls::BlsPublicKey, scalar::Scalar};
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

use crate::proto::{
    Commitment, FetchArtifactRequest, FetchArtifactResponse, FinalizeCeremonyRequest,
    FinalizeCeremonyResponse, RegisterParticipantRequest, RegisterParticipantResponse, Share,
    SubmitCommitmentsRequest, SubmitCommitmentsResponse, SubmitSharesRequest, SubmitSharesResponse,
    bootstrap_service_server::BootstrapService,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum KeysetKind {
    MNullify,
    LNotarization,
}

impl KeysetKind {
    fn parse(value: &str) -> Result<Self, Status> {
        match value {
            "m_nullify" => Ok(Self::MNullify),
            "l_notarization" => Ok(Self::LNotarization),
            _ => Err(Status::invalid_argument(format!(
                "invalid keyset '{value}', expected 'm_nullify' or 'l_notarization'"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::MNullify => "m_nullify",
            Self::LNotarization => "l_notarization",
        }
    }

    fn threshold(self, n: usize, f: usize) -> usize {
        match self {
            Self::MNullify => 2 * f + 1,
            Self::LNotarization => n - f,
        }
    }
}

#[derive(Default)]
struct CeremonyState {
    participants: BTreeMap<u64, u64>, // peer_id -> participant_index
    commitments: HashMap<(KeysetKind, u64), Commitment>,
    shares: HashMap<(KeysetKind, u64, u64), Share>,
    expected_m_nullify_group_public_key: Option<String>,
    expected_l_notarization_group_public_key: Option<String>,
    artifacts_by_peer: HashMap<u64, String>,
    finalized: bool,
}

/// In-memory bootstrap service skeleton for DKG ceremony coordination.
///
/// This service coordinates submissions from validator nodes and finalizes artifacts from those
/// submitted materials. It does not execute complaint rounds or persistent recovery logic.
#[derive(Default)]
pub struct BootstrapServiceImpl {
    states: RwLock<HashMap<String, CeremonyState>>,
}

#[tonic::async_trait]
impl BootstrapService for BootstrapServiceImpl {
    async fn register_participant(
        &self,
        request: Request<RegisterParticipantRequest>,
    ) -> Result<Response<RegisterParticipantResponse>, Status> {
        let req = request.into_inner();
        if req.validator_set_id.is_empty() {
            return Err(Status::invalid_argument(
                "validator_set_id must be non-empty",
            ));
        }
        if req.peer_id == 0 {
            return Err(Status::invalid_argument("peer_id must be non-zero"));
        }
        if req.participant_index == 0 {
            return Err(Status::invalid_argument(
                "participant_index must be non-zero",
            ));
        }

        let mut states = self.states.write().await;
        let state = states.entry(req.validator_set_id).or_default();
        if state.finalized {
            return Ok(Response::new(RegisterParticipantResponse {
                accepted: false,
                message: "ceremony already finalized".to_string(),
            }));
        }
        if let Some(existing_index) = state.participants.get(&req.peer_id) {
            if *existing_index != req.participant_index {
                return Ok(Response::new(RegisterParticipantResponse {
                    accepted: false,
                    message: "peer_id already registered with different participant_index"
                        .to_string(),
                }));
            }
            return Ok(Response::new(RegisterParticipantResponse {
                accepted: true,
                message: "participant already registered".to_string(),
            }));
        }
        if state
            .participants
            .values()
            .any(|idx| *idx == req.participant_index)
        {
            return Ok(Response::new(RegisterParticipantResponse {
                accepted: false,
                message: "participant_index already in use".to_string(),
            }));
        }
        state
            .participants
            .insert(req.peer_id, req.participant_index);

        Ok(Response::new(RegisterParticipantResponse {
            accepted: true,
            message: "participant registered".to_string(),
        }))
    }

    async fn submit_commitments(
        &self,
        request: Request<SubmitCommitmentsRequest>,
    ) -> Result<Response<SubmitCommitmentsResponse>, Status> {
        let req = request.into_inner();
        if req.validator_set_id.is_empty() {
            return Err(Status::invalid_argument(
                "validator_set_id must be non-empty",
            ));
        }
        if req.commitments.is_empty() {
            return Err(Status::invalid_argument(
                "commitments request must include at least one commitment",
            ));
        }

        let mut states = self.states.write().await;
        let state = states.entry(req.validator_set_id).or_default();
        if state.finalized {
            return Ok(Response::new(SubmitCommitmentsResponse {
                accepted: false,
                message: "ceremony already finalized".to_string(),
            }));
        }

        for commitment in req.commitments {
            let keyset = KeysetKind::parse(&commitment.keyset)?;
            if commitment.dealer_index == 0 {
                return Err(Status::invalid_argument(
                    "commitment dealer_index must be non-zero",
                ));
            }
            if !state
                .participants
                .values()
                .any(|index| *index == commitment.dealer_index)
            {
                return Err(Status::failed_precondition(format!(
                    "dealer_index {} is not a registered participant",
                    commitment.dealer_index
                )));
            }
            if commitment.commitment_public_keys.is_empty() {
                return Err(Status::invalid_argument(format!(
                    "commitment bundle for dealer {} keyset {} is empty",
                    commitment.dealer_index,
                    keyset.as_str()
                )));
            }
            for value in &commitment.commitment_public_keys {
                BlsPublicKey::from_str(value).map_err(|error| {
                    Status::invalid_argument(format!(
                        "invalid commitment public key for dealer {} keyset {}: {}",
                        commitment.dealer_index,
                        keyset.as_str(),
                        error
                    ))
                })?;
            }

            let entry_key = (keyset, commitment.dealer_index);
            if state.commitments.contains_key(&entry_key) {
                return Ok(Response::new(SubmitCommitmentsResponse {
                    accepted: false,
                    message: format!(
                        "commitments for dealer {} keyset {} already submitted",
                        commitment.dealer_index,
                        keyset.as_str()
                    ),
                }));
            }
            state.commitments.insert(entry_key, commitment);
        }

        Ok(Response::new(SubmitCommitmentsResponse {
            accepted: true,
            message: "commitments accepted".to_string(),
        }))
    }

    async fn submit_shares(
        &self,
        request: Request<SubmitSharesRequest>,
    ) -> Result<Response<SubmitSharesResponse>, Status> {
        let req = request.into_inner();
        if req.validator_set_id.is_empty() {
            return Err(Status::invalid_argument(
                "validator_set_id must be non-empty",
            ));
        }
        if req.shares.is_empty() {
            return Err(Status::invalid_argument(
                "shares request must include at least one share",
            ));
        }

        let mut states = self.states.write().await;
        let state = states.entry(req.validator_set_id).or_default();
        if state.finalized {
            return Ok(Response::new(SubmitSharesResponse {
                accepted: false,
                message: "ceremony already finalized".to_string(),
            }));
        }

        for share in req.shares {
            let keyset = KeysetKind::parse(&share.keyset)?;
            if share.dealer_index == 0 || share.recipient_index == 0 {
                return Err(Status::invalid_argument(
                    "share dealer_index and recipient_index must be non-zero",
                ));
            }
            if !state
                .participants
                .values()
                .any(|index| *index == share.dealer_index)
            {
                return Err(Status::failed_precondition(format!(
                    "share dealer_index {} is not a registered participant",
                    share.dealer_index
                )));
            }
            if !state
                .participants
                .values()
                .any(|index| *index == share.recipient_index)
            {
                return Err(Status::failed_precondition(format!(
                    "share recipient_index {} is not a registered participant",
                    share.recipient_index
                )));
            }
            decode_share_scalar(&share.share_hex).map_err(|error| {
                Status::invalid_argument(format!(
                    "invalid share for dealer {} recipient {} keyset {}: {}",
                    share.dealer_index,
                    share.recipient_index,
                    keyset.as_str(),
                    error
                ))
            })?;

            let entry_key = (keyset, share.dealer_index, share.recipient_index);
            if state.shares.contains_key(&entry_key) {
                return Ok(Response::new(SubmitSharesResponse {
                    accepted: false,
                    message: format!(
                        "share already submitted for dealer {} recipient {} keyset {}",
                        share.dealer_index,
                        share.recipient_index,
                        keyset.as_str()
                    ),
                }));
            }
            state.shares.insert(entry_key, share);
        }

        Ok(Response::new(SubmitSharesResponse {
            accepted: true,
            message: "shares accepted".to_string(),
        }))
    }

    async fn finalize_ceremony(
        &self,
        request: Request<FinalizeCeremonyRequest>,
    ) -> Result<Response<FinalizeCeremonyResponse>, Status> {
        let req = request.into_inner();
        if req.validator_set_id.is_empty() {
            return Err(Status::invalid_argument(
                "validator_set_id must be non-empty",
            ));
        }
        let mut states = self.states.write().await;
        let state = states
            .get_mut(&req.validator_set_id)
            .ok_or_else(|| Status::not_found("validator_set_id not found"))?;

        if state.participants.is_empty() {
            return Err(Status::failed_precondition(
                "cannot finalize ceremony without registered participants",
            ));
        }
        if state.finalized {
            return Ok(Response::new(FinalizeCeremonyResponse {
                finalized: true,
                message: "ceremony already finalized".to_string(),
                expected_m_nullify_group_public_key: state
                    .expected_m_nullify_group_public_key
                    .clone()
                    .unwrap_or_default(),
                expected_l_notarization_group_public_key: state
                    .expected_l_notarization_group_public_key
                    .clone()
                    .unwrap_or_default(),
            }));
        }

        let n = state.participants.len();
        let max_index = state
            .participants
            .values()
            .copied()
            .max()
            .ok_or_else(|| Status::failed_precondition("participant set is empty"))?
            as usize;
        if max_index != n {
            return Err(Status::failed_precondition(
                "participant indices must be contiguous in range 1..=n",
            ));
        }
        let mut expected_indices = (1..=n as u64).collect::<Vec<_>>();
        expected_indices.sort_unstable();
        let mut actual_indices = state.participants.values().copied().collect::<Vec<_>>();
        actual_indices.sort_unstable();
        if expected_indices != actual_indices {
            return Err(Status::failed_precondition(
                "participant indices must be exactly 1..=n",
            ));
        }

        let f = (n - 1) / 5;
        let m_output = finalize_keyset(state, KeysetKind::MNullify, n, f)?;
        let l_output = finalize_keyset(state, KeysetKind::LNotarization, n, f)?;
        let expected_m = hex::encode(m_output.group_public_key.0);
        let expected_l = hex::encode(l_output.group_public_key.0);
        state.expected_m_nullify_group_public_key = Some(expected_m.clone());
        state.expected_l_notarization_group_public_key = Some(expected_l.clone());

        let participant_by_index = state
            .participants
            .iter()
            .map(|(peer_id, index)| (*index, *peer_id))
            .collect::<HashMap<_, _>>();
        let mut validators = participant_by_index
            .iter()
            .map(|(participant_index, peer_id)| {
                let m_share_public_key = m_output
                    .participant_public_keys
                    .get(participant_index)
                    .ok_or_else(|| {
                        Status::internal(format!(
                            "missing m-nullify public share key for participant index {}",
                            participant_index
                        ))
                    })?;
                let l_share_public_key = l_output
                    .participant_public_keys
                    .get(participant_index)
                    .ok_or_else(|| {
                        Status::internal(format!(
                            "missing l-notarization public share key for participant index {}",
                            participant_index
                        ))
                    })?;
                Ok(ValidatorParticipant {
                    peer_id: *peer_id,
                    participant_index: *participant_index,
                    m_share_public_key: hex::encode(m_share_public_key.0),
                    l_share_public_key: hex::encode(l_share_public_key.0),
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;
        validators.sort_by_key(|validator| validator.participant_index);

        for share in &m_output.participant_shares {
            let peer_id = participant_by_index
                .get(&share.participant_index)
                .ok_or_else(|| {
                    Status::internal(format!(
                        "missing peer mapping for participant index {}",
                        share.participant_index
                    ))
                })?;

            let l_share = l_output
                .participant_shares
                .iter()
                .find(|value| value.participant_index == share.participant_index)
                .ok_or_else(|| {
                    Status::internal(format!(
                        "missing l-notarization share for participant index {}",
                        share.participant_index
                    ))
                })?;

            let artifact = ThresholdSetupArtifact {
                validator_set_id: req.validator_set_id.clone(),
                peer_id: *peer_id,
                participant_index: share.participant_index,
                n,
                f,
                validators: validators.clone(),
                domains: ThresholdDomains {
                    m_not: "minimmit/m_not/v1".to_string(),
                    nullify: "minimmit/nullify/v1".to_string(),
                    l_not: "minimmit/l_not/v1".to_string(),
                },
                keysets: ThresholdKeysets {
                    m_nullify: ThresholdKeyset {
                        threshold: KeysetKind::MNullify.threshold(n, f),
                        group_public_key: expected_m.clone(),
                        secret_share: hex::encode(share.secret_share.to_bytes_le()),
                    },
                    l_notarization: ThresholdKeyset {
                        threshold: KeysetKind::LNotarization.threshold(n, f),
                        group_public_key: expected_l.clone(),
                        secret_share: hex::encode(l_share.secret_share.to_bytes_le()),
                    },
                },
            };
            let artifact_json = serde_json::to_string_pretty(&artifact).map_err(|error| {
                Status::internal(format!(
                    "failed to serialize threshold setup artifact for peer {}: {}",
                    peer_id, error
                ))
            })?;
            state.artifacts_by_peer.insert(*peer_id, artifact_json);
        }
        state.finalized = true;

        Ok(Response::new(FinalizeCeremonyResponse {
            finalized: true,
            message: "ceremony finalized and artifacts generated".to_string(),
            expected_m_nullify_group_public_key: expected_m,
            expected_l_notarization_group_public_key: expected_l,
        }))
    }

    async fn fetch_artifact(
        &self,
        request: Request<FetchArtifactRequest>,
    ) -> Result<Response<FetchArtifactResponse>, Status> {
        let req = request.into_inner();
        if req.validator_set_id.is_empty() {
            return Err(Status::invalid_argument(
                "validator_set_id must be non-empty",
            ));
        }
        let states = self.states.read().await;
        let state = states
            .get(&req.validator_set_id)
            .ok_or_else(|| Status::not_found("validator_set_id not found"))?;
        let artifact_json = state
            .artifacts_by_peer
            .get(&req.peer_id)
            .cloned()
            .unwrap_or_default();

        Ok(Response::new(FetchArtifactResponse {
            found: !artifact_json.is_empty(),
            artifact_json,
            expected_m_nullify_group_public_key: state
                .expected_m_nullify_group_public_key
                .clone()
                .unwrap_or_default(),
            expected_l_notarization_group_public_key: state
                .expected_l_notarization_group_public_key
                .clone()
                .unwrap_or_default(),
        }))
    }
}

struct FinalizedKeyset {
    group_public_key: BlsPublicKey,
    participant_shares: Vec<ParticipantShare>,
    participant_public_keys: HashMap<u64, BlsPublicKey>,
}

fn finalize_keyset(
    state: &CeremonyState,
    keyset: KeysetKind,
    n: usize,
    f: usize,
) -> Result<FinalizedKeyset, Status> {
    let threshold = keyset.threshold(n, f);
    let bundles = (1..=n as u64)
        .map(|dealer_index| {
            let commitment = state
                .commitments
                .get(&(keyset, dealer_index))
                .ok_or_else(|| {
                    Status::failed_precondition(format!(
                        "missing commitment bundle for dealer {} keyset {}",
                        dealer_index,
                        keyset.as_str()
                    ))
                })?;

            if commitment.commitment_public_keys.len() != threshold {
                return Err(Status::failed_precondition(format!(
                    "invalid commitment count for dealer {} keyset {}: expected {}, got {}",
                    dealer_index,
                    keyset.as_str(),
                    threshold,
                    commitment.commitment_public_keys.len()
                )));
            }

            let commitments = commitment
                .commitment_public_keys
                .iter()
                .map(|encoded| {
                    BlsPublicKey::from_str(encoded).map_err(|error| {
                        Status::invalid_argument(format!(
                            "invalid commitment public key for dealer {} keyset {}: {}",
                            dealer_index,
                            keyset.as_str(),
                            error
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(DkgCommitmentBundle {
                dealer_index,
                threshold,
                commitments,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut shares_by_recipient = vec![Vec::<DkgShare>::with_capacity(n); n];
    for recipient_index in 1..=n as u64 {
        for dealer_index in 1..=n as u64 {
            let share = state
                .shares
                .get(&(keyset, dealer_index, recipient_index))
                .ok_or_else(|| {
                    Status::failed_precondition(format!(
                        "missing share for dealer {} recipient {} keyset {}",
                        dealer_index,
                        recipient_index,
                        keyset.as_str()
                    ))
                })?;
            let scalar = decode_share_scalar(&share.share_hex).map_err(|error| {
                Status::invalid_argument(format!(
                    "invalid share scalar for dealer {} recipient {} keyset {}: {}",
                    dealer_index,
                    recipient_index,
                    keyset.as_str(),
                    error
                ))
            })?;
            let dkg_share = DkgShare {
                dealer_index,
                recipient_index,
                value: scalar,
            };
            let bundle = &bundles[(dealer_index - 1) as usize];
            let verified = verify_share(&dkg_share, bundle).map_err(|error| {
                Status::failed_precondition(format!(
                    "share verification failed for dealer {} recipient {} keyset {}: {}",
                    dealer_index,
                    recipient_index,
                    keyset.as_str(),
                    error
                ))
            })?;
            if !verified {
                return Err(Status::failed_precondition(format!(
                    "share mismatch for dealer {} recipient {} keyset {}",
                    dealer_index,
                    recipient_index,
                    keyset.as_str()
                )));
            }
            shares_by_recipient[(recipient_index - 1) as usize].push(dkg_share);
        }
    }

    let participant_shares = (1..=n as u64)
        .map(|participant_index| {
            let secret_share = aggregate_verified_shares(
                participant_index,
                &shares_by_recipient[(participant_index - 1) as usize],
            )
            .map_err(|error| {
                Status::failed_precondition(format!(
                    "failed to aggregate shares for participant {} keyset {}: {}",
                    participant_index,
                    keyset.as_str(),
                    error
                ))
            })?;
            Ok(ParticipantShare {
                participant_index,
                secret_share,
            })
        })
        .collect::<Result<Vec<_>, Status>>()?;

    let group_public_key = derive_group_public_key(&bundles).map_err(|error| {
        Status::failed_precondition(format!(
            "failed to derive group public key for keyset {}: {}",
            keyset.as_str(),
            error
        ))
    })?;
    let participant_public_keys = (1..=n as u64)
        .map(|participant_index| {
            let key =
                derive_participant_public_key(&bundles, participant_index).map_err(|error| {
                    Status::failed_precondition(format!(
                        "failed to derive participant public key for participant {} keyset {}: {}",
                        participant_index,
                        keyset.as_str(),
                        error
                    ))
                })?;
            Ok((participant_index, key))
        })
        .collect::<Result<HashMap<_, _>, Status>>()?;

    Ok(FinalizedKeyset {
        group_public_key,
        participant_shares,
        participant_public_keys,
    })
}

fn decode_share_scalar(encoded: &str) -> Result<Scalar, String> {
    let decoded = hex::decode(encoded).map_err(|error| error.to_string())?;
    let len = decoded.len();
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| format!("share must be exactly 32 bytes, got {len}"))?;
    Ok(Scalar::from_bytes_le(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        FetchArtifactRequest, FinalizeCeremonyRequest, RegisterParticipantRequest,
        SubmitCommitmentsRequest, SubmitSharesRequest, bootstrap_service_server::BootstrapService,
    };
    use crypto::dkg::create_dealer_contribution;
    use rand::{SeedableRng, rngs::StdRng};

    async fn register_participants(service: &BootstrapServiceImpl, validator_set_id: &str, n: u64) {
        for index in 1..=n {
            let request = RegisterParticipantRequest {
                validator_set_id: validator_set_id.to_string(),
                peer_id: 10_000 + index,
                participant_index: index,
            };
            let response = service
                .register_participant(Request::new(request))
                .await
                .expect("register")
                .into_inner();
            assert!(response.accepted);
        }
    }

    async fn submit_valid_material(
        service: &BootstrapServiceImpl,
        validator_set_id: &str,
        n: usize,
    ) {
        let f = (n - 1) / 5;
        let mut rng = StdRng::seed_from_u64(77);
        for (keyset, threshold) in [
            ("m_nullify".to_string(), 2 * f + 1),
            ("l_notarization".to_string(), n - f),
        ] {
            let mut commitments = Vec::with_capacity(n);
            let mut shares = Vec::with_capacity(n * n);
            for dealer in 1..=n as u64 {
                let (bundle, dealer_shares) =
                    create_dealer_contribution(threshold, n, dealer, &mut rng)
                        .expect("dealer contribution");

                commitments.push(Commitment {
                    dealer_index: dealer,
                    keyset: keyset.clone(),
                    commitment_public_keys: bundle
                        .commitments
                        .iter()
                        .map(|public_key| hex::encode(public_key.0))
                        .collect(),
                });
                shares.extend(dealer_shares.into_iter().map(|share| Share {
                    dealer_index: share.dealer_index,
                    recipient_index: share.recipient_index,
                    keyset: keyset.clone(),
                    share_hex: hex::encode(share.value.to_bytes_le()),
                }));
            }

            let commitment_response = service
                .submit_commitments(Request::new(SubmitCommitmentsRequest {
                    validator_set_id: validator_set_id.to_string(),
                    commitments,
                }))
                .await
                .expect("submit commitments")
                .into_inner();
            assert!(
                commitment_response.accepted,
                "{}",
                commitment_response.message
            );

            let shares_response = service
                .submit_shares(Request::new(SubmitSharesRequest {
                    validator_set_id: validator_set_id.to_string(),
                    shares,
                }))
                .await
                .expect("submit shares")
                .into_inner();
            assert!(shares_response.accepted, "{}", shares_response.message);
        }
    }

    #[tokio::test]
    async fn finalize_generates_artifacts_for_all_participants() {
        let service = BootstrapServiceImpl::default();
        let validator_set_id = "vs-phase-b".to_string();
        register_participants(&service, &validator_set_id, 6).await;
        submit_valid_material(&service, &validator_set_id, 6).await;

        let finalized = service
            .finalize_ceremony(Request::new(FinalizeCeremonyRequest {
                validator_set_id: validator_set_id.clone(),
            }))
            .await
            .expect("finalize")
            .into_inner();

        assert!(finalized.finalized);
        assert!(!finalized.expected_m_nullify_group_public_key.is_empty());
        assert!(
            !finalized
                .expected_l_notarization_group_public_key
                .is_empty()
        );

        let fetched = service
            .fetch_artifact(Request::new(FetchArtifactRequest {
                validator_set_id,
                peer_id: 10_003,
            }))
            .await
            .expect("fetch")
            .into_inner();
        assert!(fetched.found);
        assert!(!fetched.artifact_json.is_empty());
    }

    #[tokio::test]
    async fn finalize_fails_when_material_is_missing() {
        let service = BootstrapServiceImpl::default();
        let validator_set_id = "vs-missing".to_string();
        register_participants(&service, &validator_set_id, 6).await;

        let response = service
            .finalize_ceremony(Request::new(FinalizeCeremonyRequest { validator_set_id }))
            .await;
        assert!(response.is_err());
        let status = response.expect_err("status");
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    }
}
