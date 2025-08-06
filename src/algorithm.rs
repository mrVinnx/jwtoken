//! Algorithm implementations for JWT signing and verification.
//!
//! This module provides traits and implementations for various JWT signing algorithms.
//! Supports HMAC-SHA256 (HS256).

use crate::JwtError;

/// Trait for JWT signing algorithms.
pub trait Signer {
    /// Returns the algorithm name (e.g., "HS256").
    fn name(&self) -> &str;

    /// Signs a message and returns the signature.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JwtError>;
}

/// Trait for JWT verification algorithms.
pub trait Verifier {
    /// Returns the algorithm name (e.g., "HS256").
    fn name(&self) -> &str;

    /// Verifies a message against a signature.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, JwtError>;
}

// HMAC-SHA256 implementation (HS256)
mod hs256 {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

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

    impl Signer for HS256 {
        fn name(&self) -> &str {
            "HS256"
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JwtError> {
            let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
                .map_err(|_| JwtError::InvalidSignature)?;
            mac.update(message);

            Ok(mac.finalize().into_bytes().to_vec())
        }
    }

    impl Verifier for HS256 {
        fn name(&self) -> &str {
            "HS256"
        }

        fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, JwtError> {
            let expected = self.sign(message)?;
            Ok(expected == signature)
        }
    }
}

pub use hs256::*;
