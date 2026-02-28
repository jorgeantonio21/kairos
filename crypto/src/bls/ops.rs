use anyhow::{Result, anyhow};
use blst::{
    BLST_ERROR, blst_hash_to_g1, blst_p1, blst_p1_add_or_double, blst_p1_affine,
    blst_p1_affine_compress, blst_p1_affine_in_g1, blst_p1_from_affine, blst_p1_mult,
    blst_p1_to_affine, blst_p1_uncompress, blst_p2, blst_p2_add_or_double, blst_p2_affine,
    blst_p2_affine_compress, blst_p2_affine_in_g2, blst_p2_from_affine, blst_p2_generator,
    blst_p2_mult, blst_p2_to_affine, blst_p2_uncompress,
    min_sig::{PublicKey, SecretKey, Signature},
};

use crate::bls::constants::{BLS_PUBLIC_KEY_BYTES, BLS_SIGNATURE_BYTES, DST, SCALAR_BITS};
use crate::scalar::Scalar;

/// Derives a compressed BLS public key from a secret scalar.
///
/// The resulting key is `scalar * G2`, encoded in compressed form.
///
/// # Errors
/// Returns an error if the underlying point conversion or serialization fails.
pub fn public_key_from_scalar(scalar: &Scalar) -> Result<[u8; BLS_PUBLIC_KEY_BYTES]> {
    unsafe {
        let generator = blst_p2_generator();
        let mut pk_point = blst_p2::default();
        blst_p2_mult(
            &mut pk_point,
            generator,
            scalar.to_bytes_le().as_ptr(),
            SCALAR_BITS,
        );

        let mut pk_affine = blst_p2_affine::default();
        blst_p2_to_affine(&mut pk_affine, &pk_point);

        let mut bytes = [0u8; BLS_PUBLIC_KEY_BYTES];
        blst_p2_affine_compress(bytes.as_mut_ptr(), &pk_affine);
        Ok(bytes)
    }
}

/// Generates a BLS secret key and returns encoded secret-key bytes.
pub fn generate_secret_key_bytes<R: rand::CryptoRng + rand::RngCore>(
    rng: &mut R,
) -> [u8; crate::bls::constants::BLS_SECRET_KEY_BYTES] {
    let mut ikm = [0u8; crate::bls::constants::BLS_SECRET_KEY_BYTES];
    rng.fill_bytes(&mut ikm);
    SecretKey::key_gen(&ikm, &[])
        .expect("Failed to generate BLS secret key")
        .to_bytes()
}

/// Derives compressed public key bytes from encoded secret key bytes.
pub fn public_key_from_secret_key_bytes(
    secret_key_bytes: &[u8; crate::bls::constants::BLS_SECRET_KEY_BYTES],
) -> Result<[u8; BLS_PUBLIC_KEY_BYTES]> {
    let sk = SecretKey::from_bytes(secret_key_bytes)
        .map_err(|e| anyhow!("Invalid BLS secret key bytes: {:?}", e))?;
    Ok(sk.sk_to_pk().to_bytes())
}

/// Signs a message using encoded secret key bytes and returns compressed signature bytes.
pub fn sign_with_secret_key_bytes(
    secret_key_bytes: &[u8; crate::bls::constants::BLS_SECRET_KEY_BYTES],
    message: &[u8],
) -> Result<[u8; BLS_SIGNATURE_BYTES]> {
    let sk = SecretKey::from_bytes(secret_key_bytes)
        .map_err(|e| anyhow!("Invalid BLS secret key bytes: {:?}", e))?;
    Ok(sk.sign(message, DST, &[]).to_bytes())
}

/// Verifies compressed signature bytes against compressed public key bytes.
pub fn verify_signature_bytes(
    public_key_bytes: &[u8; BLS_PUBLIC_KEY_BYTES],
    message: &[u8],
    signature_bytes: &[u8; BLS_SIGNATURE_BYTES],
) -> Result<()> {
    let pk = PublicKey::from_bytes(public_key_bytes)
        .map_err(|e| anyhow!("Invalid BLS public key bytes: {:?}", e))?;
    let sig = Signature::from_bytes(signature_bytes)
        .map_err(|e| anyhow!("Invalid BLS signature bytes: {:?}", e))?;

    let result = sig.verify(true, message, DST, &[], &pk, true);
    if result == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(anyhow!("Signature verification failed: {:?}", result))
    }
}

/// Creates a compressed partial signature by signing `message` with `secret_scalar`.
///
/// This hashes the message to G1 and multiplies by the provided scalar.
///
/// # Errors
/// Returns an error if hashing, point multiplication, or serialization fails.
pub fn sign_with_scalar(
    secret_scalar: &Scalar,
    message: &[u8],
) -> Result<[u8; BLS_SIGNATURE_BYTES]> {
    unsafe {
        let mut hash_point = blst_p1::default();
        blst_hash_to_g1(
            &mut hash_point,
            message.as_ptr(),
            message.len(),
            DST.as_ptr(),
            DST.len(),
            std::ptr::null(),
            0,
        );

        let mut sig_point = blst_p1::default();
        blst_p1_mult(
            &mut sig_point,
            &hash_point,
            secret_scalar.to_bytes_le().as_ptr(),
            SCALAR_BITS,
        );

        let mut sig_affine = blst_p1_affine::default();
        blst_p1_to_affine(&mut sig_affine, &sig_point);

        let mut bytes = [0u8; BLS_SIGNATURE_BYTES];
        blst_p1_affine_compress(bytes.as_mut_ptr(), &sig_affine);
        Ok(bytes)
    }
}

/// Combines compressed signatures using precomputed Lagrange coefficients.
///
/// This performs weighted interpolation in the exponent:
/// each signature is multiplied by its corresponding coefficient and accumulated.
///
/// # Errors
/// Returns an error when:
/// - `signatures.len() != lambdas.len()`
/// - input is empty
/// - any signature is invalid or not in G1
pub fn combine_signatures_with_lagrange(
    signatures: &[[u8; BLS_SIGNATURE_BYTES]],
    lambdas: &[Scalar],
) -> Result<[u8; BLS_SIGNATURE_BYTES]> {
    if signatures.len() != lambdas.len() {
        return Err(anyhow!(
            "Signatures and Lagrange coefficients length mismatch: {} != {}",
            signatures.len(),
            lambdas.len()
        ));
    }
    if signatures.is_empty() {
        return Err(anyhow!("Cannot combine empty signature set"));
    }

    let mut aggregate = blst_p1::default();
    for (idx, (signature, lambda)) in signatures.iter().zip(lambdas.iter()).enumerate() {
        let mut affine = blst_p1_affine::default();
        unsafe {
            let res = blst_p1_uncompress(&mut affine, signature.as_ptr());
            if res != BLST_ERROR::BLST_SUCCESS {
                return Err(anyhow!(
                    "Failed to uncompress signature at index {idx}: {:?}",
                    res
                ));
            }
            if !blst_p1_affine_in_g1(&affine) {
                return Err(anyhow!("Signature at index {idx} is not in G1"));
            }
        }

        let mut weighted = blst_p1::default();
        let lambda_bytes = lambda.to_bytes_le();
        unsafe {
            let mut proj = blst_p1::default();
            blst_p1_from_affine(&mut proj, &affine);
            blst_p1_mult(&mut weighted, &proj, lambda_bytes.as_ptr(), SCALAR_BITS);
        }

        if idx == 0 {
            aggregate = weighted;
        } else {
            unsafe {
                blst_p1_add_or_double(&mut aggregate, &aggregate, &weighted);
            }
        }
    }

    let mut aggregate_affine = blst_p1_affine::default();
    unsafe {
        blst_p1_to_affine(&mut aggregate_affine, &aggregate);
    }

    let mut out = [0u8; BLS_SIGNATURE_BYTES];
    unsafe {
        blst_p1_affine_compress(out.as_mut_ptr(), &aggregate_affine);
    }

    Ok(out)
}

/// Combines compressed public keys using precomputed Lagrange coefficients.
///
/// This performs weighted interpolation in the exponent:
/// each public key is multiplied by its corresponding coefficient and accumulated.
///
/// # Errors
/// Returns an error when:
/// - `public_keys.len() != lambdas.len()`
/// - input is empty
/// - any public key is invalid or not in G2
pub fn combine_public_keys_with_lagrange(
    public_keys: &[[u8; BLS_PUBLIC_KEY_BYTES]],
    lambdas: &[Scalar],
) -> Result<[u8; BLS_PUBLIC_KEY_BYTES]> {
    if public_keys.len() != lambdas.len() {
        return Err(anyhow!(
            "Public keys and Lagrange coefficients length mismatch: {} != {}",
            public_keys.len(),
            lambdas.len()
        ));
    }
    if public_keys.is_empty() {
        return Err(anyhow!("Cannot combine empty public key set"));
    }

    let mut aggregate = blst_p2::default();
    for (idx, (public_key, lambda)) in public_keys.iter().zip(lambdas.iter()).enumerate() {
        let mut affine = blst_p2_affine::default();
        unsafe {
            let res = blst_p2_uncompress(&mut affine, public_key.as_ptr());
            if res != BLST_ERROR::BLST_SUCCESS {
                return Err(anyhow!(
                    "Failed to uncompress public key at index {idx}: {:?}",
                    res
                ));
            }
            if !blst_p2_affine_in_g2(&affine) {
                return Err(anyhow!("Public key at index {idx} is not in G2"));
            }
        }

        let mut weighted = blst_p2::default();
        let lambda_bytes = lambda.to_bytes_le();
        unsafe {
            let mut proj = blst_p2::default();
            blst_p2_from_affine(&mut proj, &affine);
            blst_p2_mult(&mut weighted, &proj, lambda_bytes.as_ptr(), SCALAR_BITS);
        }

        if idx == 0 {
            aggregate = weighted;
        } else {
            unsafe {
                blst_p2_add_or_double(&mut aggregate, &aggregate, &weighted);
            }
        }
    }

    let mut aggregate_affine = blst_p2_affine::default();
    unsafe {
        blst_p2_to_affine(&mut aggregate_affine, &aggregate);
    }

    let mut out = [0u8; BLS_PUBLIC_KEY_BYTES];
    unsafe {
        blst_p2_affine_compress(out.as_mut_ptr(), &aggregate_affine);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::constants::INVALID_PEER_ID;
    use crate::threshold_math::lagrange_coefficients_for_peer_ids;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn secret_key_roundtrip_sign_verify() {
        let mut rng = StdRng::seed_from_u64(17);
        let sk = generate_secret_key_bytes(&mut rng);
        let pk = public_key_from_secret_key_bytes(&sk).expect("pk");
        let msg = b"ops-sign-verify";
        let sig = sign_with_secret_key_bytes(&sk, msg).expect("sig");
        verify_signature_bytes(&pk, msg, &sig).expect("verify");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let mut rng = StdRng::seed_from_u64(18);
        let sk = generate_secret_key_bytes(&mut rng);
        let pk = public_key_from_secret_key_bytes(&sk).expect("pk");
        let sig = sign_with_secret_key_bytes(&sk, b"msg-a").expect("sig");
        let result = verify_signature_bytes(&pk, b"msg-b", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_invalid_public_key_bytes() {
        let mut rng = StdRng::seed_from_u64(19);
        let sk = generate_secret_key_bytes(&mut rng);
        let msg = b"msg";
        let sig = sign_with_secret_key_bytes(&sk, msg).expect("sig");
        let bad_pk = [0u8; BLS_PUBLIC_KEY_BYTES];
        let result = verify_signature_bytes(&bad_pk, msg, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_invalid_signature_bytes() {
        let mut rng = StdRng::seed_from_u64(20);
        let sk = generate_secret_key_bytes(&mut rng);
        let pk = public_key_from_secret_key_bytes(&sk).expect("pk");
        let bad_sig = [0u8; BLS_SIGNATURE_BYTES];
        let result = verify_signature_bytes(&pk, b"msg", &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn combine_signatures_rejects_empty() {
        let lambdas: Vec<Scalar> = vec![];
        let signatures: Vec<[u8; BLS_SIGNATURE_BYTES]> = vec![];
        let result = combine_signatures_with_lagrange(&signatures, &lambdas);
        assert!(result.is_err());
    }

    #[test]
    fn combine_public_keys_rejects_empty() {
        let lambdas: Vec<Scalar> = vec![];
        let public_keys: Vec<[u8; BLS_PUBLIC_KEY_BYTES]> = vec![];
        let result = combine_public_keys_with_lagrange(&public_keys, &lambdas);
        assert!(result.is_err());
    }

    #[test]
    fn combine_signatures_rejects_bad_lengths() {
        let signatures = vec![[0u8; BLS_SIGNATURE_BYTES]];
        let lambdas = vec![];
        let result = combine_signatures_with_lagrange(&signatures, &lambdas);
        assert!(result.is_err());
    }

    #[test]
    fn combine_public_keys_rejects_bad_lengths() {
        let pks = vec![[0u8; BLS_PUBLIC_KEY_BYTES]];
        let lambdas = vec![];
        let result = combine_public_keys_with_lagrange(&pks, &lambdas);
        assert!(result.is_err());
    }

    #[test]
    fn lagrange_and_combine_roundtrip_like_threshold() {
        let mut rng = StdRng::seed_from_u64(21);
        let mut sks = Vec::new();
        let mut pks = Vec::new();
        let mut ids = Vec::new();
        for idx in 1..=3_u64 {
            let sk = generate_secret_key_bytes(&mut rng);
            let pk = public_key_from_secret_key_bytes(&sk).expect("pk");
            sks.push(sk);
            pks.push(pk);
            ids.push(idx);
        }
        assert_ne!(ids[0], INVALID_PEER_ID);
        let lambdas = lagrange_coefficients_for_peer_ids(&ids).expect("lambdas");
        let msg = b"combine-roundtrip";
        let sigs: Vec<[u8; BLS_SIGNATURE_BYTES]> = sks
            .iter()
            .map(|sk| sign_with_secret_key_bytes(sk, msg).expect("sig"))
            .collect();
        let _combined_sig = combine_signatures_with_lagrange(&sigs, &lambdas).expect("combine sig");
        let _combined_pk = combine_public_keys_with_lagrange(&pks, &lambdas).expect("combine pk");
    }

    #[test]
    fn public_key_from_scalar_matches_secret_key_path_shape() {
        let mut rng = StdRng::seed_from_u64(22);
        let sk_bytes = generate_secret_key_bytes(&mut rng);
        let pk = public_key_from_secret_key_bytes(&sk_bytes).expect("pk");
        assert_eq!(pk.len(), BLS_PUBLIC_KEY_BYTES);
        let scalar = Scalar::from_bytes_le(sk_bytes);
        let alt_pk = public_key_from_scalar(&scalar).expect("pk from scalar");
        assert_eq!(alt_pk.len(), BLS_PUBLIC_KEY_BYTES);
    }
}
