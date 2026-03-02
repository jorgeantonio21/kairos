use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bootstrap_rpc::proto::{
    Commitment, FetchArtifactRequest, RegisterParticipantRequest, Share, SubmitCommitmentsRequest,
    SubmitSharesRequest, bootstrap_service_client::BootstrapServiceClient,
};
use crypto::dkg::create_dealer_contribution;
use p2p::ValidatorIdentity;
use tonic::transport::Channel;

const KEYSET_M_NULLIFY: &str = "m_nullify";
const KEYSET_L_NOTARIZATION: &str = "l_notarization";
const BOOTSTRAP_RPC_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct BootstrapProvisionedArtifact {
    pub artifact_json: String,
    pub expected_m_nullify_group_public_key: String,
    pub expected_l_notarization_group_public_key: String,
}

#[derive(Debug)]
pub struct BootstrapOrchestrationConfig {
    pub endpoint: String,
    pub validator_set_id: String,
    pub participant_index: u64,
    pub total_participants: usize,
    pub max_faulty: usize,
    pub finalize_if_last: bool,
    pub max_attempts: u32,
    pub backoff: Duration,
}

pub struct BootstrapClient {
    client: BootstrapServiceClient<Channel>,
}

impl BootstrapClient {
    pub async fn connect(endpoint: &str) -> Result<Self> {
        let endpoint_str = endpoint.to_string();
        let endpoint = tonic::transport::Endpoint::from_shared(endpoint_str.clone())
            .with_context(|| format!("invalid bootstrap endpoint '{endpoint}'"))?
            .connect_timeout(BOOTSTRAP_RPC_TIMEOUT)
            .timeout(BOOTSTRAP_RPC_TIMEOUT);
        let client = BootstrapServiceClient::connect(endpoint)
            .await
            .with_context(|| {
                format!("failed to connect to bootstrap endpoint '{}'", endpoint_str)
            })?;
        Ok(Self { client })
    }

    pub async fn provision_artifact(
        mut self,
        identity: &ValidatorIdentity,
        config: &BootstrapOrchestrationConfig,
    ) -> Result<BootstrapProvisionedArtifact> {
        self.register(identity, config).await?;
        self.submit_dkg_material(config).await?;
        self.finalize_and_fetch(identity.peer_id(), config).await
    }

    async fn register(
        &mut self,
        identity: &ValidatorIdentity,
        config: &BootstrapOrchestrationConfig,
    ) -> Result<()> {
        let response = Self::rpc_call_static(
            self.client
                .register_participant(RegisterParticipantRequest {
                    validator_set_id: config.validator_set_id.clone(),
                    peer_id: identity.peer_id(),
                    participant_index: config.participant_index,
                }),
            "register_participant",
        )
        .await?
        .into_inner();

        if !response.accepted {
            if response.message.contains("already finalized") {
                return Ok(());
            }
            return Err(anyhow!(
                "bootstrap register_participant was rejected: {}",
                response.message
            ));
        }
        Ok(())
    }

    async fn submit_dkg_material(&mut self, config: &BootstrapOrchestrationConfig) -> Result<()> {
        let mut rng = rand::thread_rng();
        let m_threshold = 2 * config.max_faulty + 1;
        let l_threshold = config.total_participants - config.max_faulty;

        let (m_bundle, m_shares) = create_dealer_contribution(
            m_threshold,
            config.total_participants,
            config.participant_index,
            &mut rng,
        )
        .context("failed to generate m-nullify dealer contribution")?;
        let (l_bundle, l_shares) = create_dealer_contribution(
            l_threshold,
            config.total_participants,
            config.participant_index,
            &mut rng,
        )
        .context("failed to generate l-notarization dealer contribution")?;

        let commitments = vec![
            Commitment {
                dealer_index: config.participant_index,
                keyset: KEYSET_M_NULLIFY.to_string(),
                commitment_public_keys: m_bundle
                    .commitments
                    .iter()
                    .map(|public_key| hex::encode(public_key.0))
                    .collect(),
            },
            Commitment {
                dealer_index: config.participant_index,
                keyset: KEYSET_L_NOTARIZATION.to_string(),
                commitment_public_keys: l_bundle
                    .commitments
                    .iter()
                    .map(|public_key| hex::encode(public_key.0))
                    .collect(),
            },
        ];
        self.submit_commitments(config, commitments).await?;

        let shares = m_shares
            .into_iter()
            .map(|share| Share {
                dealer_index: share.dealer_index,
                recipient_index: share.recipient_index,
                keyset: KEYSET_M_NULLIFY.to_string(),
                share_hex: hex::encode(share.value.to_bytes_le()),
            })
            .chain(l_shares.into_iter().map(|share| Share {
                dealer_index: share.dealer_index,
                recipient_index: share.recipient_index,
                keyset: KEYSET_L_NOTARIZATION.to_string(),
                share_hex: hex::encode(share.value.to_bytes_le()),
            }))
            .collect::<Vec<_>>();
        self.submit_shares(config, shares).await?;

        Ok(())
    }

    async fn submit_commitments(
        &mut self,
        config: &BootstrapOrchestrationConfig,
        commitments: Vec<Commitment>,
    ) -> Result<()> {
        let response = Self::rpc_call_static(
            self.client.submit_commitments(SubmitCommitmentsRequest {
                validator_set_id: config.validator_set_id.clone(),
                commitments,
            }),
            "submit_commitments",
        )
        .await?
        .into_inner();
        if !response.accepted
            && !response.message.contains("already submitted")
            && !response.message.contains("already finalized")
        {
            return Err(anyhow!(
                "bootstrap submit_commitments was rejected: {}",
                response.message
            ));
        }
        Ok(())
    }

    async fn submit_shares(
        &mut self,
        config: &BootstrapOrchestrationConfig,
        shares: Vec<Share>,
    ) -> Result<()> {
        let response = Self::rpc_call_static(
            self.client.submit_shares(SubmitSharesRequest {
                validator_set_id: config.validator_set_id.clone(),
                shares,
            }),
            "submit_shares",
        )
        .await?
        .into_inner();
        if !response.accepted
            && !response.message.contains("already submitted")
            && !response.message.contains("already finalized")
        {
            return Err(anyhow!(
                "bootstrap submit_shares was rejected: {}",
                response.message
            ));
        }
        Ok(())
    }

    async fn finalize_and_fetch(
        &mut self,
        peer_id: u64,
        config: &BootstrapOrchestrationConfig,
    ) -> Result<BootstrapProvisionedArtifact> {
        for _ in 0..config.max_attempts {
            if config.finalize_if_last {
                let _ = Self::rpc_call_static(
                    self.client
                        .finalize_ceremony(bootstrap_rpc::proto::FinalizeCeremonyRequest {
                            validator_set_id: config.validator_set_id.clone(),
                        }),
                    "finalize_ceremony",
                )
                .await;
            }

            let response = Self::rpc_call_static(
                self.client.fetch_artifact(FetchArtifactRequest {
                    validator_set_id: config.validator_set_id.clone(),
                    peer_id,
                }),
                "fetch_artifact",
            )
            .await;
            if let Ok(response) = response {
                let payload = response.into_inner();
                if payload.found && !payload.artifact_json.is_empty() {
                    return Ok(BootstrapProvisionedArtifact {
                        artifact_json: payload.artifact_json,
                        expected_m_nullify_group_public_key: payload
                            .expected_m_nullify_group_public_key,
                        expected_l_notarization_group_public_key: payload
                            .expected_l_notarization_group_public_key,
                    });
                }
            }

            tokio::time::sleep(config.backoff).await;
        }

        Err(anyhow!(
            "bootstrap artifact not available after {} attempts for validator_set_id '{}'",
            config.max_attempts,
            config.validator_set_id
        ))
    }

    async fn rpc_call_static<T>(
        fut: impl std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
        rpc_name: &str,
    ) -> Result<tonic::Response<T>> {
        tokio::time::timeout(BOOTSTRAP_RPC_TIMEOUT, fut)
            .await
            .with_context(|| format!("bootstrap {} RPC timed out", rpc_name))?
            .with_context(|| format!("bootstrap {} RPC failed", rpc_name))
    }
}
