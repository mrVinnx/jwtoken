//! Algorithm implementations for JWT signing and verification.
//!
//! This module provides traits and implementations for various JWT signing algorithms.
//! Supports HMAC-SHA256 (HS256).

use crate::JwtError;

/// Trait for JWT signing algorithms.
pub trait Signer {
    /// Returns the algorithm name.
    fn name(&self) -> &str;

    /// Signs a message and returns the signature.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JwtError>;
}

/// Trait for JWT verification algorithms.
pub trait Verifier {
    /// Returns the algorithm name.
    fn name(&self) -> &str;

    /// Verifies a message against a signature.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, JwtError>;
}

#[cfg(feature = "hs256")]
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

#[cfg(feature = "rs256")]
mod rs256 {
    use super::*;
    use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
    use rsa::pkcs1v15::{SigningKey, VerifyingKey};
    use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
    use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier as RsaVerifier};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;

    /// RSA-SHA256 (RS256) signer implementation with private key.
    #[derive(Debug, Clone)]
    pub struct RS256Signer {
        private_key: RsaPrivateKey,
        public_key: RsaPublicKey, // Cache the public key for verification
    }

    /// RSA-SHA256 (RS256) verifier implementation with public key.
    #[derive(Debug, Clone)]
    pub struct RS256Verifier {
        public_key: RsaPublicKey,
    }

    impl RS256Signer {
        /// Creates a new `RS256Signer` instance with the given private key.
        pub fn new(private_key: RsaPrivateKey) -> Self {
            let public_key = private_key.to_public_key();
            Self {
                private_key,
                public_key,
            }
        }

        /// Creates a new `RS256Signer` from PEM-encoded private key bytes.
        pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, JwtError> {
            let pem_str = std::str::from_utf8(pem_bytes).map_err(|_| JwtError::InvalidKey)?;

            // Try PKCS#8 format first
            let private_key = RsaPrivateKey::from_pkcs8_pem(pem_str)
                .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem_str))
                .map_err(|_| JwtError::InvalidKey)?;

            Ok(Self::new(private_key))
        }

        /// Creates a new `RS256Signer` from DER-encoded private key bytes.
        pub fn from_der(der_bytes: &[u8]) -> Result<Self, JwtError> {
            // Try PKCS#8 format first
            let private_key = RsaPrivateKey::from_pkcs8_der(der_bytes)
                .or_else(|_| RsaPrivateKey::from_pkcs1_der(der_bytes))
                .map_err(|_| JwtError::InvalidKey)?;

            Ok(Self::new(private_key))
        }

        /// Get the public key for this signer
        pub fn public_key(&self) -> &RsaPublicKey {
            &self.public_key
        }
    }

    impl RS256Verifier {
        /// Creates a new `RS256Verifier` instance with the given public key.
        pub fn new(public_key: RsaPublicKey) -> Self {
            Self { public_key }
        }

        /// Creates a new `RS256Verifier` from PEM-encoded public key bytes.
        pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, JwtError> {
            let pem_str = std::str::from_utf8(pem_bytes).map_err(|_| JwtError::InvalidKey)?;

            let public_key = RsaPublicKey::from_public_key_pem(pem_str)
                .or_else(|_| RsaPublicKey::from_pkcs1_pem(pem_str))
                .map_err(|_| JwtError::InvalidKey)?;

            Ok(Self::new(public_key))
        }

        /// Creates a new `RS256Verifier` from DER-encoded public key bytes.
        pub fn from_der(der_bytes: &[u8]) -> Result<Self, JwtError> {
            let public_key = RsaPublicKey::from_public_key_der(der_bytes)
                .or_else(|_| RsaPublicKey::from_pkcs1_der(der_bytes))
                .map_err(|_| JwtError::InvalidKey)?;

            Ok(Self::new(public_key))
        }
    }

    impl Signer for RS256Signer {
        fn name(&self) -> &str {
            "RS256"
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JwtError> {
            let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
            let mut rng = rsa::rand_core::OsRng;

            let signature = signing_key.sign_with_rng(&mut rng, message);
            Ok(signature.to_vec())
        }
    }

    impl Verifier for RS256Verifier {
        fn name(&self) -> &str {
            "RS256"
        }

        fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, JwtError> {
            let verifying_key = VerifyingKey::<Sha256>::new(self.public_key.clone());
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| JwtError::InvalidSignature)?;

            Ok(verifying_key.verify(message, &signature).is_ok())
        }
    }

    impl Verifier for RS256Signer {
        fn name(&self) -> &str {
            "RS256"
        }

        fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, JwtError> {
            let verifying_key = VerifyingKey::<Sha256>::new(self.public_key.clone());
            let signature = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| JwtError::InvalidSignature)?;

            Ok(verifying_key.verify(message, &signature).is_ok())
        }
    }
}

#[cfg(feature = "hs256")]
pub use hs256::*;

#[cfg(feature = "rs256")]
pub use rs256::*;
