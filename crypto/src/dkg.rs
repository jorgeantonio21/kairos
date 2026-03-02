use rand::{CryptoRng, Rng};

use crate::bls::constants::BLS_PUBLIC_KEY_BYTES;
use crate::bls::ops::{combine_public_keys_with_lagrange, public_key_from_scalar};
use crate::consensus_bls::BlsPublicKey;
use crate::error::{DkgError, DkgResult};
use crate::polynomial::Polynomial;
use crate::scalar::Scalar;

/// DKG participant index in the finite field domain.
///
/// This index is the x-coordinate for Shamir polynomial evaluation and must be non-zero.
pub type ParticipantIndex = u64;

/// Commitment bundle broadcast by a dealer in one DKG keyset ceremony.
///
/// `commitments[k]` is a commitment to polynomial coefficient `a_k` as `g2^{a_k}`.
#[derive(Clone, Debug)]
pub struct DkgCommitmentBundle {
    pub dealer_index: ParticipantIndex,
    pub threshold: usize,
    pub commitments: Vec<BlsPublicKey>,
}

/// Secret share sent from one dealer to one recipient.
#[derive(Clone, Debug)]
pub struct DkgShare {
    pub dealer_index: ParticipantIndex,
    pub recipient_index: ParticipantIndex,
    pub value: Scalar,
}

/// Final local key share for one participant after aggregating verified dealer shares.
#[derive(Clone, Debug)]
pub struct ParticipantShare {
    pub participant_index: ParticipantIndex,
    pub secret_share: Scalar,
}

/// Output for one in-memory DKG ceremony.
#[derive(Clone, Debug)]
pub struct InMemoryDkgOutput {
    pub group_public_key: BlsPublicKey,
    pub participant_shares: Vec<ParticipantShare>,
}

/// Output for the dual-keyset DKG needed by Minimmit:
/// - `m_nullify`: threshold `2f + 1`
/// - `l_notarization`: threshold `n - f`
#[derive(Clone, Debug)]
pub struct DualDkgOutput {
    pub m_nullify: InMemoryDkgOutput,
    pub l_notarization: InMemoryDkgOutput,
}

/// Creates one dealer contribution for Joint-Feldman DKG.
///
/// Joint-Feldman DKG (JFDKG) is a distributed key generation protocol that enables
/// a set of `n` participants to collaboratively generate a shared BLS12-381 public key.
/// Each participant receives a secret share of the corresponding threshold private key.
///
/// ## Mathematical Background
///
/// ### Shamir Secret Sharing
/// A dealer creates a random polynomial of degree `t - 1`:
/// ```math
/// f(x) = a_0 + a_1 x + a_2 x^2 + \cdots + a_{t-1} x^{t-1}
/// ```
///
/// - The **secret** to be shared is `a_0` (the constant term)
/// - Each participant `i` receives the share `f(i)` where `i ∈ [1, n]`
/// - Any `t` or more shares can reconstruct the polynomial via Lagrange interpolation
///
/// ### Commitment Scheme
/// Each coefficient `a_k` is committed using the BLS generator `g_2`:
/// ```math
/// C_k = g_2^{a_k}
/// ```
///
/// The commitment bundle contains `t` commitments `C_0, C_1, ..., C_{t-1}`.
///
/// ### Share Verification
/// A recipient verifies their share using the commitments:
/// ```math
/// g_2^{f(i)} = \prod_{k=0}^{t-1} C_k^{i^k}
/// ```
///
/// This holds because:
/// ```math
/// \prod_{k=0}^{t-1} C_k^{i^k} = \prod_{k=0}^{t-1} (g_2^{a_k})^{i^k}
///                              = g_2^{\sum_{k=0}^{t-1} a_k i^k}
///                              = g_2^{f(i)}
/// ```
///
/// ## Arguments
/// * `threshold` - Threshold `t` for this keyset (polynomial degree is `t - 1`). Requires `t`
///   shares to reconstruct the secret or sign.
/// * `total_participants` - Number of participants `n`
/// * `dealer_index` - Dealer participant index in `[1, n]`
/// * `rng` - Cryptographically secure random number generator
///
/// ## Returns
/// A commitment bundle plus one share per recipient index in `[1, n]`.
///
/// ## Security Considerations
/// - The dealer's secret `a_0` is never exposed; only the commitment `C_0 = g_2^{a_0}` is broadcast
/// - Share verification ensures integrity of the distributed key generation
/// - Each dealer contribution is independent; multiple dealers provide robustness against Byzantine
///   (malicious) dealers
pub fn create_dealer_contribution<R: Rng + CryptoRng>(
    threshold: usize,
    total_participants: usize,
    dealer_index: ParticipantIndex,
    rng: &mut R,
) -> DkgResult<(DkgCommitmentBundle, Vec<DkgShare>)> {
    validate_threshold_params(threshold, total_participants)?;
    validate_participant_index(dealer_index, total_participants)?;

    let secret = Scalar::random(rng);
    let polynomial = Polynomial::random(threshold - 1, secret, rng);

    let commitments = coefficient_commitments(&polynomial, threshold)?;
    let shares = (1..=total_participants)
        .map(|recipient| {
            let x = Scalar::from_u64(recipient as u64);
            DkgShare {
                dealer_index,
                recipient_index: recipient as u64,
                value: polynomial.evaluate(&x),
            }
        })
        .collect::<Vec<_>>();

    Ok((
        DkgCommitmentBundle {
            dealer_index,
            threshold,
            commitments,
        },
        shares,
    ))
}

/// Verifies a dealer share against the dealer's public commitments.
///
/// ## Mathematical Background
///
/// Given a share `s = f(i)` for participant `i` and commitment bundle
/// `C_0, C_1, ..., C_{t-1}` to polynomial coefficients, verification checks:
///
/// ```math
/// g_2^s \stackrel{?}{=} \prod_{k=0}^{t-1} C_k^{i^k}
/// ```
///
/// This equation derives from the polynomial commitment scheme:
/// - Left side: `g_2^{f(i)}` — the public key corresponding to the secret share
/// - Right side: Evaluates the commitments at point `i` using the polynomial representation,
///   equivalent to `g_2^{a_0 + a_1 i + a_2 i^2 + ... + a_{t-1} i^{t-1}}`
///
/// ## Arguments
/// * `share` - The dealer's share sent to a recipient
/// * `bundle` - The commitment bundle broadcast by the dealer
///
/// ## Returns
/// `Ok(true)` if the share is valid, `Ok(false)` if invalid, or an error if
/// the bundle structure is malformed.
///
/// ## Attack Prevention
/// This verification prevents a malicious dealer from:
/// 1. Sending invalid shares that don't correspond to a valid polynomial
/// 2. Sending different shares to different recipients (consistency check)
/// 3. Manipulating the commitment bundle after distribution
pub fn verify_share(share: &DkgShare, bundle: &DkgCommitmentBundle) -> DkgResult<bool> {
    if share.dealer_index != bundle.dealer_index {
        return Err(DkgError::ShareDealerMismatch {
            share_dealer: share.dealer_index,
            bundle_dealer: bundle.dealer_index,
        });
    }

    if bundle.commitments.len() != bundle.threshold {
        return Err(DkgError::InvalidCommitmentBundle {
            dealer_index: bundle.dealer_index,
            commitments: bundle.commitments.len(),
            threshold: bundle.threshold,
        });
    }

    let expected = evaluate_commitments(bundle, share.recipient_index)?;
    let actual = BlsPublicKey(
        public_key_from_scalar(&share.value)
            .map_err(|error| DkgError::BlsOperation(error.to_string()))?,
    );
    Ok(expected == actual)
}

/// Aggregates verified shares for one recipient into its final local secret share.
///
/// ## Mathematical Background
///
/// In Joint-Feldman DKG, each participant receives one share from every dealer.
/// The final secret share is the **sum** of all verified shares:
///
/// ```math
/// s_i = \sum_{d=1}^{n} f_d(i)
/// ```
///
/// where `f_d(i)` is the share from dealer `d` to participant `i`.
///
/// ### Why Summation Works
///
/// Each dealer's polynomial `f_d(x)` has constant term `a_{d,0}`. The group secret is:
/// ```math
/// S = \sum_{d=1}^{n} a_{d,0}
/// ```
///
/// Participant `i`'s share of `S` is:
/// ```math
/// s_i = \sum_{d=1}^{n} f_d(i) = \sum_{d=1}^{n} \sum_{k=0}^{t-1} a_{d,k} i^k
///                              = \sum_{k=0}^{t-1} \left(\sum_{d=1}^{n} a_{d,k}\right) i^k
/// ```
///
/// This defines a new polynomial `F(x) = \sum_{d=1}^{n} f_d(x)` with constant term `S`.
/// Thus `s_i = F(i)` is a valid Shamir share of the group secret `S`.
///
/// ## Arguments
/// * `recipient_index` - The participant index receiving the aggregated share
/// * `verified_shares` - Vector of verified shares from all dealers for this recipient
///
/// ## Returns
/// The aggregated secret share `s_i = Σ f_d(i)` for the recipient.
///
/// ## Preconditions
/// All shares in `verified_shares` must be verified via `verify_share` before calling
/// this function. Aggregation of unverified shares is insecure.
pub fn aggregate_verified_shares(
    recipient_index: ParticipantIndex,
    verified_shares: &[DkgShare],
) -> DkgResult<Scalar> {
    if verified_shares.is_empty() {
        return Err(DkgError::EmptyVerifiedShares { recipient_index });
    }

    let mut aggregate = Scalar::zero();
    for share in verified_shares {
        if share.recipient_index != recipient_index {
            return Err(DkgError::ShareRecipientMismatch {
                expected: recipient_index,
                actual: share.recipient_index,
            });
        }
        aggregate = aggregate.add(&share.value);
    }

    Ok(aggregate)
}

/// Derives the group public key from all dealer commitment bundles.
///
/// ## Mathematical Background
///
/// The group public key corresponds to the group secret `S = Σ a_{d,0}` (sum of all
/// dealers' constant terms). It is computed from the constant-term commitments:
///
/// ```math
/// PK = \prod_{d=1}^{n} C_{d,0} = \prod_{d=1}^{n} g_2^{a_{d,0}} = g_2^{\sum_{d=1}^{n} a_{d,0}} = g_2^S
/// ```
///
/// ### Derivation via Lagrange Interpolation
///
/// At threshold `t`, the group public key can equivalently be derived using Lagrange
/// coefficients for any set of `t` dealers. For set `D` of dealers with indices in
/// domain `{1, ..., n}`:
///
/// ```math
/// PK = \sum_{d \in D} \lambda_d \cdot C_{d,0}, \quad \lambda_d = \prod_{j \in D, j \neq d} \frac{j}{j - d}
/// ```
///
/// This implementation uses Lagrange coefficients of all ones (equivalent to summation
/// when using all `n` dealers), which simplifies to the product of constant terms.
///
/// ## Arguments
/// * `bundles` - Vector of commitment bundles from all dealers
///
/// ## Returns
/// The group public key `PK = g_2^S` where `S` is the group secret.
///
/// ## Security Considerations
/// - All bundles must be verified (shares validated) before deriving the group key
/// - The group public key is publicly computable from commitments alone—no secret information
///   needed
/// - This matches the public key that would result from aggregating all secret shares
pub fn derive_group_public_key(bundles: &[DkgCommitmentBundle]) -> DkgResult<BlsPublicKey> {
    if bundles.is_empty() {
        return Err(DkgError::EmptyCommitmentSet);
    }

    let c0_bytes = bundles
        .iter()
        .map(|bundle| {
            if bundle.commitments.len() != bundle.threshold {
                return Err(DkgError::InvalidCommitmentBundle {
                    dealer_index: bundle.dealer_index,
                    commitments: bundle.commitments.len(),
                    threshold: bundle.threshold,
                });
            }
            Ok(bundle.commitments[0].0)
        })
        .collect::<DkgResult<Vec<[u8; BLS_PUBLIC_KEY_BYTES]>>>()?;

    let ones = vec![Scalar::one(); c0_bytes.len()];
    let group_pk = combine_public_keys_with_lagrange(&c0_bytes, &ones)
        .map_err(|error| DkgError::BlsOperation(error.to_string()))?;
    Ok(BlsPublicKey(group_pk))
}

/// Derives the threshold verification public key for one participant index.
///
/// The returned key equals `g2^{F(i)}` where `F(x)` is the aggregate polynomial across all
/// dealers and `i` is the participant index.
pub fn derive_participant_public_key(
    bundles: &[DkgCommitmentBundle],
    participant_index: ParticipantIndex,
) -> DkgResult<BlsPublicKey> {
    if bundles.is_empty() {
        return Err(DkgError::EmptyCommitmentSet);
    }
    if participant_index == 0 {
        return Err(DkgError::ParticipantIndexZero);
    }

    let evaluated_commitments = bundles
        .iter()
        .map(|bundle| evaluate_commitments(bundle, participant_index).map(|pk| pk.0))
        .collect::<DkgResult<Vec<[u8; BLS_PUBLIC_KEY_BYTES]>>>()?;
    let ones = vec![Scalar::one(); evaluated_commitments.len()];
    let pk = combine_public_keys_with_lagrange(&evaluated_commitments, &ones)
        .map_err(|error| DkgError::BlsOperation(error.to_string()))?;
    Ok(BlsPublicKey(pk))
}

/// Runs one in-memory Joint-Feldman ceremony for a single threshold.
///
/// ## Protocol Overview
///
/// Joint-Feldman DKG proceeds in phases:
///
/// ### Phase 1: Dealer Contribution
/// Each of the `n` participants acts as a dealer and:
/// 1. Generates a random polynomial `f(x)` of degree `t - 1`
/// 2. Computes commitment bundle `C_k = g_2^{a_k}` for each coefficient
/// 3. Computes shares `s_i = f(i)` for each recipient `i`
/// 4. Broadcasts the commitment bundle to all participants
/// 5. Sends each share to its designated recipient (via secure private channel)
///
/// ### Phase 2: Share Verification
/// Each participant verifies all `n` received shares against their bundles.
/// Any invalid share indicates a malicious dealer and aborts the protocol.
///
/// ### Phase 3: Share Aggregation
/// Each participant aggregates their verified shares:
/// ```math
/// s_i = \sum_{d=1}^{n} f_d(i)
/// ```
///
/// ### Phase 4: Group Key Derivation
/// All participants compute the group public key from constant-term commitments.
///
/// ## Threshold Signature Capability
///
/// With a `(t, n)` threshold scheme:
/// - Any `t` or more participants can sign messages
/// - Fewer than `t` participants cannot produce a valid signature
/// - The signature can be verified with the group public key
///
/// The secret key is never reconstructed; instead, partial signatures are combined:
///
/// ```math
/// \sigma = \sum_{i \in S} \lambda_i \cdot \sigma_i, \quad S \text{ is a set of } t \text{ signers}
/// ```
///
/// where `λ_i` are Lagrange coefficients based on signer indices.
///
/// ## Arguments
/// * `total_participants` - Number of participants `n`
/// * `threshold` - Minimum number of shares `t` required for signing
/// * `rng` - Cryptographically secure random number generator
///
/// ## Returns
/// * `group_public_key` - The shared public key for the group
/// * `participant_shares` - Vector of `n` secret shares, one per participant
///
/// ## Limitations (In-Memory Version)
/// This implementation is for testing/prototyping. In production:
/// - Shares should be transmitted over secure authenticated channels
/// - Commitment bundles should be broadcast via reliable broadcast
/// - The protocol should handle malicious participants (verifiable secret sharing)
pub fn run_in_memory_joint_feldman<R: Rng + CryptoRng>(
    total_participants: usize,
    threshold: usize,
    rng: &mut R,
) -> DkgResult<InMemoryDkgOutput> {
    validate_threshold_params(threshold, total_participants)?;

    let mut bundles = Vec::with_capacity(total_participants);
    let mut shares_by_recipient = vec![Vec::<DkgShare>::new(); total_participants];

    for dealer in 1..=total_participants {
        let (bundle, shares) =
            create_dealer_contribution(threshold, total_participants, dealer as u64, rng)?;

        for share in shares {
            if !verify_share(&share, &bundle)? {
                return Err(DkgError::ShareVerificationFailed {
                    dealer_index: share.dealer_index,
                    recipient_index: share.recipient_index,
                });
            }
            let idx = share.recipient_index as usize - 1;
            shares_by_recipient[idx].push(share);
        }
        bundles.push(bundle);
    }

    let participant_shares = (1..=total_participants)
        .map(|recipient| {
            let secret =
                aggregate_verified_shares(recipient as u64, &shares_by_recipient[recipient - 1])?;
            Ok(ParticipantShare {
                participant_index: recipient as u64,
                secret_share: secret,
            })
        })
        .collect::<DkgResult<Vec<_>>>()?;

    let group_public_key = derive_group_public_key(&bundles)?;

    Ok(InMemoryDkgOutput {
        group_public_key,
        participant_shares,
    })
}

/// Runs the dual-keyset in-memory DKG for Minimmit.
///
/// ## Minimmit Protocol Requirements
///
/// Minimmit BFT uses two distinct threshold signature schemes with different thresholds:
///
/// ### M-Notarization Threshold: `2f + 1`
/// - Required for view progression (M-notarization)
/// - Uses threshold `t_m = 2f + 1` where `f` is the maximum Byzantine fault bound
/// - Example: With `n = 7` and `f = 1`, threshold is `3`
///
/// ### L-Notarization Threshold: `n - f`
/// - Required for block finalization (L-notarization)
/// - Uses threshold `t_l = n - f`
/// - Example: With `n = 7` and `f = 1`, threshold is `6`
///
/// ## Mathematical Justification
///
/// With `n >= 5f + 1` (the Minimmit Byzantine assumption):
///
/// | Threshold | Formula | Property |
/// |-----------|---------|----------|
/// | M-Notarization | `2f + 1` | Guarantees at least one honest participant in any majority |
/// | L-Notarization | `n - f` | Guarantees finality; cannot be achieved if >f Byzantine |
///
/// ### Key Properties:
///
/// 1. **M-notarization + Nullification coexistence**: With `n >= 5f + 1`, a view can receive both
///    M-notarization AND nullification without contradiction (Lemma 5.3 in Minimmit paper)
///
/// 2. **L-notarization exclusion**: If a view receives L-notarization, it cannot receive
///    nullification. This is crucial for finality guarantees.
///
/// 3. **Cascade nullification**: When view `V` is nullified and the node has already progressed to
///    `V+k`, all views `V+1` through `V+k` must also be nullified to maintain pending state
///    consistency.
///
/// ## Arguments
/// * `total_participants` - Number of validators `n`
/// * `max_faulty` - Maximum Byzantine fault bound `f`
/// * `rng` - Cryptographically secure random number generator
///
/// ## Returns
/// A `DualDkgOutput` containing two independent DKG outputs:
///
/// * `m_nullify` - Threshold `2f + 1` keyset for M-notarization
/// * `l_notarization` - Threshold `n - f` keyset for L-notarization
///
/// ## Example
/// ```ignore
/// // For n=7, f=1 (Byzantine tolerance)
/// let output = run_in_memory_dual_dkg(7, 1, &mut rng)?;
///
/// // M-notarization: needs 3 of 7 shares to sign
/// assert_eq!(output.m_nullify.participant_shares.len(), 7);
/// // M-notarization threshold: 2*1 + 1 = 3
///
/// // L-notarization: needs 6 of 7 shares to sign
/// assert_eq!(output.l_notarization.participant_shares.len(), 7);
/// // L-notarization threshold: 7 - 1 = 6
/// ```
pub fn run_in_memory_dual_dkg<R: Rng + CryptoRng>(
    total_participants: usize,
    max_faulty: usize,
    rng: &mut R,
) -> DkgResult<DualDkgOutput> {
    if max_faulty >= total_participants {
        return Err(DkgError::FaultyBoundOutOfRange {
            max_faulty,
            total_participants,
        });
    }

    let m_threshold = 2 * max_faulty + 1;
    let l_threshold = total_participants - max_faulty;
    validate_threshold_params(m_threshold, total_participants)?;
    validate_threshold_params(l_threshold, total_participants)?;

    let m_nullify = run_in_memory_joint_feldman(total_participants, m_threshold, rng)?;
    let l_notarization = run_in_memory_joint_feldman(total_participants, l_threshold, rng)?;

    Ok(DualDkgOutput {
        m_nullify,
        l_notarization,
    })
}

/// Validates that threshold parameters satisfy DKG requirements.
///
/// ## Requirements
/// - `threshold > 0`: Must have at least 1 share required
/// - `threshold <= total_participants`: Cannot require more shares than participants
///
/// A `(t, n)` threshold scheme requires `t <= n` by definition.
fn validate_threshold_params(threshold: usize, total_participants: usize) -> DkgResult<()> {
    if threshold == 0 {
        return Err(DkgError::ThresholdMustBePositive);
    }
    if threshold > total_participants {
        return Err(DkgError::ThresholdExceedsParticipants {
            threshold,
            total_participants,
        });
    }
    Ok(())
}

/// Validates that a participant index is in the valid domain.
///
/// ## Requirements
/// - `index > 0`: Participant indices are 1-indexed (x-coordinate in Shamir scheme)
/// - `index <= total_participants`: Index must not exceed the participant count
///
/// The index `0` is excluded because evaluating a polynomial at `x = 0`
/// would reveal the secret constant term.
fn validate_participant_index(index: ParticipantIndex, total_participants: usize) -> DkgResult<()> {
    if index == 0 {
        return Err(DkgError::ParticipantIndexZero);
    }
    if index as usize > total_participants {
        return Err(DkgError::ParticipantIndexOutOfRange {
            index,
            total_participants,
        });
    }
    Ok(())
}

/// Computes commitment bundle from polynomial coefficients.
///
/// ## Mathematical Background
///
/// For a polynomial of degree `t - 1`:
/// ```math
/// f(x) = a_0 + a_1 x + a_2 x^2 + \cdots + a_{t-1} x^{t-1}
/// ```
///
/// Each coefficient `a_k` is committed using the BLS generator `g_2`:
/// ```math
/// C_k = g_2^{a_k} \quad \text{for } k = 0, 1, \ldots, t-1
/// ```
///
/// The commitment bundle `C = (C_0, C_1, ..., C_{t-1})` allows verification
/// without revealing the coefficients.
///
/// ## Arguments
/// * `polynomial` - The Shamir polynomial with `threshold` coefficients
/// * `threshold` - Number of coefficients (degree + 1)
///
/// ## Returns
/// Vector of `threshold` BLS public keys, one per coefficient.
fn coefficient_commitments(
    polynomial: &Polynomial,
    threshold: usize,
) -> DkgResult<Vec<BlsPublicKey>> {
    let mut commitments = Vec::with_capacity(threshold);
    for idx in 0..threshold {
        let coeff = polynomial
            .coefficient(idx)
            .ok_or(DkgError::MissingPolynomialCoefficient { index: idx })?;
        let coeff_pk = BlsPublicKey(
            public_key_from_scalar(coeff)
                .map_err(|error| DkgError::BlsOperation(error.to_string()))?,
        );
        commitments.push(coeff_pk);
    }

    Ok(commitments)
}

/// Evaluates the commitment polynomial at a given recipient index.
///
/// ## Mathematical Background
///
/// Given commitment bundle `C = (C_0, C_1, ..., C_{t-1})` to polynomial coefficients,
/// evaluating at point `x = i` computes:
///
/// ```math
/// \prod_{k=0}^{t-1} C_k^{i^k} = \prod_{k=0}^{t-1} (g_2^{a_k})^{i^k}
///                            = g_2^{\sum_{k=0}^{t-1} a_k i^k}
///                            = g_2^{f(i)}
/// ```
///
/// This is the public key that corresponds to the secret share `f(i)`.
/// The verification in `verify_share` checks that this equals `g_2^{share}`.
///
/// ## Arguments
/// * `bundle` - Commitment bundle from a dealer
/// * `recipient_index` - The x-coordinate to evaluate at (participant ID)
///
/// ## Returns
/// The evaluated public key `g_2^{f(i)}` at the given index.
///
/// ## Implementation Note
/// This uses Lagrange interpolation formula with coefficients `1, x, x^2, ..., x^{t-1}`.
/// The `combine_public_keys_with_lagrange` function performs the weighted combination.
fn evaluate_commitments(
    bundle: &DkgCommitmentBundle,
    recipient_index: ParticipantIndex,
) -> DkgResult<BlsPublicKey> {
    if recipient_index == 0 {
        return Err(DkgError::ParticipantIndexZero);
    }

    let x = Scalar::from_u64(recipient_index);
    let mut powers = Vec::with_capacity(bundle.commitments.len());
    let mut current = Scalar::one();
    for _ in 0..bundle.commitments.len() {
        powers.push(current.clone());
        current = current.mul(&x);
    }

    let commitment_bytes = bundle.commitments.iter().map(|pk| pk.0).collect::<Vec<_>>();
    let evaluated = combine_public_keys_with_lagrange(&commitment_bytes, &powers)
        .map_err(|error| DkgError::BlsOperation(error.to_string()))?;
    Ok(BlsPublicKey(evaluated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::ops::{sign_with_scalar, verify_signature_bytes};
    use crate::consensus_bls::BlsSignature;
    use crate::threshold_math::lagrange_coefficients_for_indices;
    use rand::{rngs::StdRng, SeedableRng};

    fn combine_signature_shares(
        shares: &[ParticipantShare],
        message: &[u8],
    ) -> DkgResult<BlsSignature> {
        let partials = shares
            .iter()
            .map(|share| {
                let sig = sign_with_scalar(&share.secret_share, message)
                    .map_err(|error| DkgError::BlsOperation(error.to_string()))?;
                Ok((share.participant_index, BlsSignature(sig)))
            })
            .collect::<DkgResult<Vec<_>>>()?;

        BlsSignature::combine_partials(&partials)
            .map_err(|error| DkgError::BlsOperation(error.to_string()))
    }

    #[test]
    fn dealer_contribution_has_expected_shape() {
        let mut rng = StdRng::seed_from_u64(7);
        let (bundle, shares) = create_dealer_contribution(3, 5, 2, &mut rng).expect("contribution");
        assert_eq!(bundle.dealer_index, 2);
        assert_eq!(bundle.threshold, 3);
        assert_eq!(bundle.commitments.len(), 3);
        assert_eq!(shares.len(), 5);
        assert!(shares.iter().all(|share| share.dealer_index == 2));
    }

    #[test]
    fn verify_share_rejects_tampered_share() {
        let mut rng = StdRng::seed_from_u64(8);
        let (bundle, shares) = create_dealer_contribution(3, 5, 1, &mut rng).expect("contribution");
        let mut tampered = shares[0].clone();
        tampered.value = tampered.value.add(&Scalar::one());
        let verified = verify_share(&tampered, &bundle).expect("verification");
        assert!(!verified);
    }

    #[test]
    fn verify_share_rejects_tampered_commitment() {
        let mut rng = StdRng::seed_from_u64(9);
        let (mut bundle, shares) =
            create_dealer_contribution(3, 5, 1, &mut rng).expect("contribution");
        bundle.commitments[0].0[0] ^= 1;
        let result = verify_share(&shares[0], &bundle);
        assert!(result.is_err() || !result.expect("bool"));
    }

    #[test]
    fn joint_feldman_threshold_signing_roundtrip() {
        let mut rng = StdRng::seed_from_u64(11);
        let output = run_in_memory_joint_feldman(5, 3, &mut rng).expect("dkg");
        let selected = vec![
            output.participant_shares[0].clone(),
            output.participant_shares[2].clone(),
            output.participant_shares[4].clone(),
        ];
        let message = b"dkg-threshold-roundtrip";
        let signature = combine_signature_shares(&selected, message).expect("combine sig");

        verify_signature_bytes(&output.group_public_key.0, message, &signature.0).expect("verify");
    }

    #[test]
    fn joint_feldman_below_threshold_fails_verification() {
        let mut rng = StdRng::seed_from_u64(13);
        let output = run_in_memory_joint_feldman(5, 3, &mut rng).expect("dkg");
        let selected = vec![
            output.participant_shares[0].clone(),
            output.participant_shares[1].clone(),
        ];
        let message = b"dkg-below-threshold";
        let signature = combine_signature_shares(&selected, message).expect("combine sig");

        let verify_result =
            verify_signature_bytes(&output.group_public_key.0, message, &signature.0);
        assert!(verify_result.is_err());
    }

    #[test]
    fn dual_dkg_uses_two_distinct_thresholds() {
        let mut rng = StdRng::seed_from_u64(17);
        let output = run_in_memory_dual_dkg(7, 1, &mut rng).expect("dual dkg");
        assert_eq!(output.m_nullify.participant_shares.len(), 7);
        assert_eq!(output.l_notarization.participant_shares.len(), 7);

        let message_m = b"m-nullify-domain";
        let selected_m = vec![
            output.m_nullify.participant_shares[0].clone(),
            output.m_nullify.participant_shares[1].clone(),
            output.m_nullify.participant_shares[2].clone(),
        ];
        let signature_m = combine_signature_shares(&selected_m, message_m).expect("m combine");
        verify_signature_bytes(
            &output.m_nullify.group_public_key.0,
            message_m,
            &signature_m.0,
        )
        .expect("m verify");

        let message_l = b"l-not-domain";
        let selected_l = vec![
            output.l_notarization.participant_shares[0].clone(),
            output.l_notarization.participant_shares[1].clone(),
            output.l_notarization.participant_shares[2].clone(),
            output.l_notarization.participant_shares[3].clone(),
            output.l_notarization.participant_shares[4].clone(),
            output.l_notarization.participant_shares[5].clone(),
        ];
        let signature_l = combine_signature_shares(&selected_l, message_l).expect("l combine");
        verify_signature_bytes(
            &output.l_notarization.group_public_key.0,
            message_l,
            &signature_l.0,
        )
        .expect("l verify");
    }

    #[test]
    fn lagrange_coefficients_for_indices_are_non_zero() {
        let ids = vec![1u64, 3u64, 5u64];
        let lambdas = lagrange_coefficients_for_indices(&ids).expect("lambdas");
        assert_eq!(lambdas.len(), ids.len());
        assert!(lambdas.iter().all(|lambda| !lambda.is_zero()));
    }

    #[test]
    fn aggregate_verified_shares_rejects_empty() {
        let result = aggregate_verified_shares(1, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn aggregate_verified_shares_rejects_recipient_mismatch() {
        let mut rng = StdRng::seed_from_u64(21);
        let (_, shares) = create_dealer_contribution(3, 5, 1, &mut rng).expect("contribution");
        let result = aggregate_verified_shares(99, &shares);
        assert!(result.is_err());
    }

    #[test]
    fn aggregate_verified_shares_success() {
        let mut rng = StdRng::seed_from_u64(22);
        let (_, shares1) = create_dealer_contribution(3, 5, 1, &mut rng).expect("contribution1");
        let (_, shares2) = create_dealer_contribution(3, 5, 2, &mut rng).expect("contribution2");
        let recipient_1_shares = vec![shares1[0].clone(), shares2[0].clone()];
        let result = aggregate_verified_shares(1, &recipient_1_shares);
        assert!(result.is_ok());
    }

    #[test]
    fn derive_group_public_key_rejects_empty() {
        let result = derive_group_public_key(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn derive_group_public_key_rejects_invalid_commitment_length() {
        let mut rng = StdRng::seed_from_u64(23);
        let (bundle, _) = create_dealer_contribution(3, 5, 1, &mut rng).expect("contribution");
        let mut bad_bundle = bundle.clone();
        bad_bundle.commitments.pop();
        let result = derive_group_public_key(&[bad_bundle]);
        assert!(result.is_err());
    }

    #[test]
    fn derive_group_public_key_success() {
        let mut rng = StdRng::seed_from_u64(24);
        let (bundle1, _) = create_dealer_contribution(3, 5, 1, &mut rng).expect("contribution1");
        let (bundle2, _) = create_dealer_contribution(3, 5, 2, &mut rng).expect("contribution2");
        let result = derive_group_public_key(&[bundle1, bundle2]);
        assert!(result.is_ok());
    }

    #[test]
    fn derive_participant_public_key_rejects_empty() {
        let result = derive_participant_public_key(&[], 1);
        assert!(result.is_err());
    }

    #[test]
    fn derive_participant_public_key_rejects_zero_index() {
        let mut rng = StdRng::seed_from_u64(25);
        let (bundle, _) = create_dealer_contribution(3, 5, 1, &mut rng).expect("contribution");
        let result = derive_participant_public_key(&[bundle], 0);
        assert!(result.is_err());
    }

    #[test]
    fn derive_participant_public_key_success() {
        let mut rng = StdRng::seed_from_u64(26);
        let (bundle, _) = create_dealer_contribution(3, 5, 1, &mut rng).expect("contribution");
        let result = derive_participant_public_key(&[bundle], 1);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_share_rejects_dealer_mismatch() {
        let mut rng = StdRng::seed_from_u64(27);
        let (bundle, shares) = create_dealer_contribution(3, 5, 1, &mut rng).expect("contribution");
        let mut bad_share = shares[0].clone();
        bad_share.dealer_index = 99;
        let result = verify_share(&bad_share, &bundle);
        assert!(result.is_err());
    }

    #[test]
    fn verify_share_rejects_commitment_threshold_mismatch() {
        let mut rng = StdRng::seed_from_u64(28);
        let (mut bundle, shares) =
            create_dealer_contribution(3, 5, 1, &mut rng).expect("contribution");
        bundle.threshold = 99;
        let result = verify_share(&shares[0], &bundle);
        assert!(result.is_err());
    }

    #[test]
    fn create_dealer_contribution_rejects_zero_threshold() {
        let mut rng = StdRng::seed_from_u64(29);
        let result = create_dealer_contribution(0, 5, 1, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn create_dealer_contribution_rejects_threshold_exceeds_participants() {
        let mut rng = StdRng::seed_from_u64(30);
        let result = create_dealer_contribution(6, 5, 1, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn create_dealer_contribution_rejects_zero_dealer_index() {
        let mut rng = StdRng::seed_from_u64(31);
        let result = create_dealer_contribution(3, 5, 0, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn create_dealer_contribution_rejects_dealer_index_out_of_range() {
        let mut rng = StdRng::seed_from_u64(32);
        let result = create_dealer_contribution(3, 5, 99, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn run_in_memory_joint_feldman_rejects_zero_threshold() {
        let mut rng = StdRng::seed_from_u64(33);
        let result = run_in_memory_joint_feldman(5, 0, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn run_in_memory_joint_feldman_rejects_threshold_exceeds_participants() {
        let mut rng = StdRng::seed_from_u64(34);
        let result = run_in_memory_joint_feldman(5, 6, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn run_in_memory_dual_dkg_rejects_f_equals_n() {
        let mut rng = StdRng::seed_from_u64(35);
        let result = run_in_memory_dual_dkg(5, 5, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn run_in_memory_dual_dkg_rejects_f_exceeds_n() {
        let mut rng = StdRng::seed_from_u64(36);
        let result = run_in_memory_dual_dkg(5, 6, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn evaluate_commitments_rejects_zero_index() {
        let mut rng = StdRng::seed_from_u64(40);
        let (bundle, _) = create_dealer_contribution(3, 5, 1, &mut rng).expect("contribution");
        let result = evaluate_commitments(&bundle, 0);
        assert!(result.is_err());
    }
}
