use std::collections::HashSet;

use anyhow::Result;

use crate::{
    crypto::consensus_bls::{ThresholdPartialSignature, ThresholdProof},
    state::{notarizations::Vote, nullify::Nullify, peer::PeerSet},
};

/// Data structure containing the aggregated signature and peer IDs for a notarization.
///
/// This struct is used to bundle the results of signature aggregation and peer ID
/// collection for both M-notarizations and L-notarizations.
pub(crate) struct NotarizationData<const N: usize> {
    /// The aggregated BLS signature from the participating peers.
    pub(crate) aggregated_signature: ThresholdProof,
}

/// Creates notarization data by combining threshold partial signatures and collecting signer IDs.
///
/// This function takes the first N votes from the provided HashSet and:
/// 1. Sorts votes by `peer_id` to ensure deterministic signer ordering
/// 2. Combines their partial signatures using `BlsSignature::combine_partials`
/// 2. Collects their peer IDs into a fixed-size array
///
/// # Important Notes
///
/// - Deterministic ordering is kept intentionally for reproducible proof bytes across nodes.
///
/// # Parameters
///
/// * `votes` - HashSet of votes to aggregate
///
/// # Returns
///
/// Returns `NotarizationData<N>` containing the aggregated signature and peer IDs.
///
/// # Errors
///
/// Returns an error if there are not enough votes to create notarization data.
///
/// # Examples
///
/// ```ignore
/// let votes = HashSet::from([vote1, vote2, vote3]);
/// let data: NotarizationData<3> = create_notarization_data(&votes, &peer_set)?;
/// ```
pub(crate) fn create_notarization_data<const N: usize>(
    votes: &HashSet<Vote>,
    peer_set: &PeerSet,
) -> Result<NotarizationData<N>> {
    if votes.len() < N {
        return Err(anyhow::anyhow!(
            "Not enough votes to create notarization data: {} < {}",
            votes.len(),
            N
        ));
    }

    let mut selected_votes: Vec<&Vote> = votes.iter().collect();
    // Deterministic ordering across replicas before selecting N participants.
    selected_votes.sort_by_key(|vote| vote.peer_id);
    let selected_votes = &selected_votes[..N];

    let partials: Vec<(u64, ThresholdPartialSignature)> = selected_votes
        .iter()
        .map(|vote| -> Result<(u64, ThresholdPartialSignature)> {
            let participant_index = peer_set.get_index(&vote.peer_id)?;
            Ok((participant_index, vote.signature))
        })
        .collect::<Result<Vec<_>>>()?;
    let aggregated_signature = ThresholdProof::combine_partials(&partials)?;
    Ok(NotarizationData {
        aggregated_signature,
    })
}

/// Data structure containing the aggregated signature and peer IDs for a nullification.
///
/// This struct is used to bundle the results of signature aggregation and peer ID
/// collection for nullifications.
pub(crate) struct NullificationData<const N: usize> {
    /// The aggregated BLS signature from the participating peers.
    pub(crate) aggregated_signature: ThresholdProof,
}

/// Creates nullification data by combining threshold partial signatures and collecting signer IDs.
///
/// This function selects N nullifications from the provided HashSet and:
/// 1. Sorts nullifications by `peer_id` to ensure deterministic signer ordering
/// 2. Combines partial signatures using `BlsSignature::combine_partials`
/// 2. Collects their peer IDs into a fixed-size array
///
/// # Important Notes
///
/// - The HashSet ensures uniqueness based on (view, peer_id), so peer IDs are guaranteed distinct
/// - Sorting removes HashSet iteration nondeterminism for reproducible proof construction
/// - All nullifications should be for the same view (enforced by the HashSet's equality)
///
/// # Parameters
///
/// * `nullifications` - HashSet of nullifications to aggregate
///
/// # Returns
///
/// Returns `NullificationData<N>` containing the aggregated signature and peer IDs.
///
/// # Errors
///
/// Returns an error if there are fewer than N nullifications available.
///
/// # Examples
///
/// ```ignore
/// let nullifications = HashSet::from([nullify1, nullify2, nullify3]);
/// let data: NullificationData<3> = create_nullification_data(&nullifications, &peer_set)?;
/// ```
pub(crate) fn create_nullification_data<const N: usize>(
    nullifications: &HashSet<Nullify>,
    peer_set: &PeerSet,
) -> Result<NullificationData<N>> {
    if nullifications.len() < N {
        return Err(anyhow::anyhow!(
            "Not enough nullifications to create nullification data: {} < {}",
            nullifications.len(),
            N
        ));
    }

    let mut selected_nullifications: Vec<&Nullify> = nullifications.iter().collect();
    // Deterministic ordering across replicas before selecting N participants.
    selected_nullifications.sort_by_key(|nullify| nullify.peer_id);
    let selected_nullifications = &selected_nullifications[..N];

    let partials: Vec<(u64, ThresholdPartialSignature)> = selected_nullifications
        .iter()
        .map(|nullify| -> Result<(u64, ThresholdPartialSignature)> {
            let participant_index = peer_set.get_index(&nullify.peer_id)?;
            Ok((participant_index, nullify.signature))
        })
        .collect::<Result<Vec<_>>>()?;
    let aggregated_signature = ThresholdProof::combine_partials(&partials)?;
    Ok(NullificationData {
        aggregated_signature,
    })
}
