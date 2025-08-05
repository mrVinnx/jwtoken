//! Algorithm implementations for JWT signing and verification.
//!
//! This module provides traits and implementations for various JWT signing algorithms.
//! Provide built-in support for HMAC-SHA256 (HS256) algorithm.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::JwtError;

/// Trait for JWT signing and verification algorithms.
pub trait Algorithm {
    /// Returns the algorithm name (e.g., "HS256").
    fn name(&self) -> &str;

    /// Signs a message and returns the signature.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JwtError>;

    /// Verifies a message against a signature.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, JwtError>;
}

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 (HS256) algorithm implementation.
#[derive(Debug, Clone)]
pub struct HS256 {
    secret: Vec<u8>,
}

impl HS256 {
    /// Creates a new `HS256` instance with the given secret.
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
        }
    }
}

impl Algorithm for HS256 {
    /// Returns "HS256" as the algorithm name.
    fn name(&self) -> &str {
        "HS256"
    }

    /// Signs a message using HMAC-SHA256.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JwtError> {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| JwtError::InvalidSignature)?;
        mac.update(message);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Verifies a message against a signature using HMAC-SHA256.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, JwtError> {
        let expected = self.sign(message)?;
        Ok(expected == signature)
    }
}

/// Generates a random 256-bit secret for JWT signing.
pub fn random_secret() -> Vec<u8> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::{RngCore, rng};

    let mut secret = [0u8; 32];
    rng().fill_bytes(&mut secret);
    URL_SAFE_NO_PAD.encode(&secret).into_bytes()
}
