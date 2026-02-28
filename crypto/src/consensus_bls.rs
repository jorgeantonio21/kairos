use std::str::FromStr;

use anyhow::{Result, anyhow};
use blst::min_sig::PublicKey;
use rand::{CryptoRng, RngCore};
use rkyv::{Archive, Deserialize, Serialize};

use crate::bls::constants::{
    BLS_PUBLIC_KEY_BYTES,
    BLS_SECRET_KEY_BYTES,
    BLS_SIGNATURE_BYTES,
    PEER_ID_BYTES,
};
use crate::bls::ops::{
    combine_public_keys_with_lagrange,
    combine_signatures_with_lagrange,
    generate_secret_key_bytes,
    public_key_from_secret_key_bytes,
    sign_with_secret_key_bytes,
    verify_signature_bytes,
};
use crate::threshold_math::lagrange_coefficients_for_peer_ids;

pub type PeerId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Archive, Deserialize, Serialize)]
pub struct BlsPublicKey(pub [u8; BLS_PUBLIC_KEY_BYTES]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Archive, Deserialize, Serialize)]
pub struct BlsSignature(pub [u8; BLS_SIGNATURE_BYTES]);

#[derive(Clone, Debug, PartialEq, Eq, Archive, Deserialize, Serialize)]
pub struct BlsSecretKey(pub [u8; BLS_SECRET_KEY_BYTES]);

impl BlsSecretKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(generate_secret_key_bytes(rng))
    }

    pub fn public_key(&self) -> BlsPublicKey {
        let pk_bytes = public_key_from_secret_key_bytes(&self.0)
            .expect("Invalid BLS secret key bytes");
        BlsPublicKey(pk_bytes)
    }

    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        let sig_bytes =
            sign_with_secret_key_bytes(&self.0, message).expect("Invalid BLS secret key bytes");
        BlsSignature(sig_bytes)
    }
}

impl BlsPublicKey {
    pub fn verify(&self, message: &[u8], signature: &BlsSignature) -> bool {
        verify_signature_bytes(&self.0, message, &signature.0).is_ok()
    }

    pub fn verify_threshold(
        public_keys: &[BlsPublicKey],
        peer_ids: &[PeerId],
        message: &[u8],
        signature: &BlsSignature,
    ) -> bool {
        match Self::interpolate_threshold_public_key(public_keys, peer_ids) {
            Ok(pk) => pk.verify(message, signature),
            Err(_) => false,
        }
    }

    pub fn interpolate_threshold_public_key(
        public_keys: &[BlsPublicKey],
        peer_ids: &[PeerId],
    ) -> Result<BlsPublicKey> {
        if public_keys.is_empty() {
            return Err(anyhow!("Cannot interpolate public key from empty set"));
        }
        if public_keys.len() != peer_ids.len() {
            return Err(anyhow!(
                "Mismatched public key and peer ID counts: {} != {}",
                public_keys.len(),
                peer_ids.len()
            ));
        }

        let lambdas = lagrange_coefficients_for_peer_ids(peer_ids)?;
        let public_key_bytes: Vec<[u8; BLS_PUBLIC_KEY_BYTES]> =
            public_keys.iter().map(|pk| pk.0).collect();
        let out = combine_public_keys_with_lagrange(&public_key_bytes, &lambdas)?;

        Ok(BlsPublicKey(out))
    }

    pub fn to_peer_id(&self) -> PeerId {
        let hash = blake3::hash(&self.0);
        let bytes: [u8; PEER_ID_BYTES] = hash.as_bytes()[..PEER_ID_BYTES]
            .try_into()
            .expect("Slice length must match PEER_ID_BYTES");
        u64::from_le_bytes(bytes)
    }

    pub fn serialize_compressed<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.0)
    }

    pub fn deserialize_compressed<R: std::io::Read>(mut reader: R) -> std::io::Result<Self> {
        let mut bytes = [0u8; BLS_PUBLIC_KEY_BYTES];
        reader.read_exact(&mut bytes)?;
        PublicKey::from_bytes(&bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid compressed BLS public key",
            )
        })?;
        Ok(Self(bytes))
    }
}

impl FromStr for BlsPublicKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        let pk = PublicKey::from_bytes(&bytes)
            .map_err(|e| anyhow!("Invalid BLS public key bytes: {:?}", e))?;
        Ok(Self(pk.to_bytes()))
    }
}

impl BlsSignature {
    /// Combine threshold partial signatures using Lagrange interpolation in the exponent.
    pub fn combine_partials(partials: &[(PeerId, BlsSignature)]) -> Result<BlsSignature> {
        if partials.is_empty() {
            return Err(anyhow!("Cannot combine empty partial signature set"));
        }

        let peer_ids: Vec<PeerId> = partials.iter().map(|(peer_id, _)| *peer_id).collect();
        let lambdas = lagrange_coefficients_for_peer_ids(&peer_ids)?;
        let signature_bytes: Vec<[u8; BLS_SIGNATURE_BYTES]> =
            partials.iter().map(|(_, sig)| sig.0).collect();
        let out = combine_signatures_with_lagrange(&signature_bytes, &lambdas)?;

        Ok(BlsSignature(out))
    }

    pub fn serialize_compressed<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.0)
    }
}

impl Default for BlsSignature {
    fn default() -> Self {
        Self([0u8; BLS_SIGNATURE_BYTES])
    }
}

#[derive(Clone, Debug, Archive, Deserialize, Serialize)]
pub struct AggregatedSignature<const N: usize> {
    pub aggregated_signature: BlsSignature,
    pub public_keys: [BlsPublicKey; N],
    pub peer_ids: [PeerId; N],
}

impl<const N: usize> AggregatedSignature<N> {
    pub fn new(
        public_keys: [BlsPublicKey; N],
        peer_ids: [PeerId; N],
        message: &[u8],
        signatures: &[BlsSignature],
    ) -> Option<Self> {
        if signatures.len() != N || N == 0 {
            return None;
        }

        for idx in 0..N {
            if !public_keys[idx].verify(message, &signatures[idx]) {
                return None;
            }
        }

        let partials: Vec<(PeerId, BlsSignature)> = peer_ids
            .iter()
            .copied()
            .zip(signatures.iter().copied())
            .collect();
        let aggregated_signature = BlsSignature::combine_partials(&partials).ok()?;

        Some(Self {
            aggregated_signature,
            public_keys,
            peer_ids,
        })
    }

    pub fn new_from_aggregated_signature(
        public_keys: [BlsPublicKey; N],
        peer_ids: [PeerId; N],
        aggregated_signature: BlsSignature,
    ) -> Self {
        Self {
            public_keys,
            peer_ids,
            aggregated_signature,
        }
    }

    pub fn verify(&self, message: &[u8]) -> bool {
        BlsPublicKey::verify_threshold(
            &self.public_keys,
            &self.peer_ids,
            message,
            &self.aggregated_signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::{ThresholdBLS, ThresholdBLS as Scheme};
    use rand::thread_rng;

    const TEST_THRESHOLD: usize = 3;
    const TEST_TOTAL_PARTICIPANTS: usize = 5;
    const FIRST_SELECTED_INDEX: usize = 0;
    const SECOND_SELECTED_INDEX: usize = 2;
    const THIRD_SELECTED_INDEX: usize = 4;

    #[test]
    fn threshold_combine_and_verify_roundtrip() {
        let mut rng = thread_rng();
        let scheme = ThresholdBLS::new(TEST_THRESHOLD, TEST_TOTAL_PARTICIPANTS);
        let (_, key_shares) = scheme.trusted_setup(&mut rng).expect("setup");

        let message = b"threshold message";
        let selected = [
            &key_shares[FIRST_SELECTED_INDEX],
            &key_shares[SECOND_SELECTED_INDEX],
            &key_shares[THIRD_SELECTED_INDEX],
        ];

        let partials: Vec<(PeerId, BlsSignature)> = selected
            .iter()
            .map(|share| {
                let ps = Scheme::partial_sign(share, message).expect("partial sign");
                (ps.id, BlsSignature(ps.signature.to_bytes()))
            })
            .collect();

        let public_keys: Vec<BlsPublicKey> = selected
            .iter()
            .map(|share| BlsPublicKey(share.public_key.to_bytes()))
            .collect();

        let combined = BlsSignature::combine_partials(&partials).expect("combine");
        let peer_ids: Vec<PeerId> = partials.iter().map(|(id, _)| *id).collect();

        assert!(BlsPublicKey::verify_threshold(
            &public_keys,
            &peer_ids,
            message,
            &combined
        ));
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let message = b"single-signer";
        let signature = sk.sign(message);
        assert!(pk.verify(message, &signature));
    }

    #[test]
    fn combine_partials_rejects_empty() {
        let result = BlsSignature::combine_partials(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn combine_partials_rejects_duplicate_peer_ids() {
        let mut rng = thread_rng();
        let scheme = ThresholdBLS::new(TEST_THRESHOLD, TEST_TOTAL_PARTICIPANTS);
        let (_, key_shares) = scheme.trusted_setup(&mut rng).expect("setup");
        let message = b"duplicate-peer-id";

        let ps0 = Scheme::partial_sign(&key_shares[FIRST_SELECTED_INDEX], message).expect("sign 0");
        let ps1 = Scheme::partial_sign(&key_shares[SECOND_SELECTED_INDEX], message).expect("sign 1");
        let partials = vec![
            (ps0.id, BlsSignature(ps0.signature.to_bytes())),
            (ps0.id, BlsSignature(ps1.signature.to_bytes())),
        ];

        let result = BlsSignature::combine_partials(&partials);
        assert!(result.is_err());
    }

    #[test]
    fn verify_threshold_rejects_wrong_message() {
        let mut rng = thread_rng();
        let scheme = ThresholdBLS::new(TEST_THRESHOLD, TEST_TOTAL_PARTICIPANTS);
        let (_, key_shares) = scheme.trusted_setup(&mut rng).expect("setup");

        let signed_message = b"threshold message";
        let wrong_message = b"wrong message";
        let selected = [
            &key_shares[FIRST_SELECTED_INDEX],
            &key_shares[SECOND_SELECTED_INDEX],
            &key_shares[THIRD_SELECTED_INDEX],
        ];

        let partials: Vec<(PeerId, BlsSignature)> = selected
            .iter()
            .map(|share| {
                let ps = Scheme::partial_sign(share, signed_message).expect("partial sign");
                (ps.id, BlsSignature(ps.signature.to_bytes()))
            })
            .collect();
        let combined = BlsSignature::combine_partials(&partials).expect("combine");
        let public_keys: Vec<BlsPublicKey> = selected
            .iter()
            .map(|share| BlsPublicKey(share.public_key.to_bytes()))
            .collect();
        let peer_ids: Vec<PeerId> = partials.iter().map(|(id, _)| *id).collect();

        assert!(!BlsPublicKey::verify_threshold(
            &public_keys,
            &peer_ids,
            wrong_message,
            &combined
        ));
    }

    #[test]
    fn verify_threshold_rejects_mismatched_lengths() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let sig = sk.sign(b"mismatch");
        let result = BlsPublicKey::verify_threshold(&[pk], &[pk.to_peer_id(), 999], b"mismatch", &sig);
        assert!(!result);
    }

    #[test]
    fn deserialize_compressed_rejects_invalid_bytes() {
        let bytes = [0u8; BLS_PUBLIC_KEY_BYTES];
        let result = BlsPublicKey::deserialize_compressed(bytes.as_slice());
        assert!(result.is_err());
    }
}
