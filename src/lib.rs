//! A flexible utility library for encoding and decoding JSON Web Tokens (JWT).
//!
//! This crate provides a type state API for creating, signing, and verifying JWTs with support for HMAC-SHA256 (HS256).
//!
//! # Examples
//!
//! ## Using HS256 (HMAC-SHA256)
//!
//! ```rust
//! # #[cfg(feature = "rnd")]
//! # {
//! use jwtoken::{random_secret, HS256, Jwt, Encoder, Decoded};
//!
//! fn main() -> Result<(), jwtoken::JwtError> {
//!     let secret = random_secret();
//!     let algorithm = HS256::new(&secret);
//!
//!     // Encoding a JWT
//!     let token = Jwt::<Encoder>::new()
//!         .claim("sub", "1234567890")
//!         .claim("name", "John Doe")
//!         .claim("iat", 1516239022)
//!         .encode(&algorithm)?;
//!
//!     println!("Generated token: {}", token);
//!
//!     // Decoding and verifying the same JWT
//!     let decoded = Jwt::<Decoded>::decode(&token, &algorithm)?;
//!     println!("Decoded claims: {:?}", decoded.claims);
//!
//!     Ok(())
//! }
//! # }
//! ```
//!

mod algorithm;
mod error;

pub use algorithm::*;
pub use error::*;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use serde_json::{Map, Value};

#[cfg(feature = "rnd")]
use rand::{RngCore, rng};

/// A encoder state for creating JWTs.
#[derive(Debug, Clone)]
pub struct Encoder;

/// A decoded state JWT to be inspected
#[derive(Debug, Clone)]
pub struct Decoded;

/// A JSON Web Token (JWT) in a specific state (either `Encoder` or `Decoded`).
#[derive(Debug, Clone)]
pub struct Jwt<State> {
    pub headers: Headers,
    pub claims: Claims,
    _state: std::marker::PhantomData<State>,
}

pub type Claims = Map<String, Value>;
pub type Headers = Map<String, Value>;

impl Jwt<Encoder> {
    /// Creates a new JWT builder with default headers.
    pub fn new() -> Self {
        let mut headers = Map::new();
        headers.insert("typ".to_string(), Value::String("JWT".to_string()));

        Self {
            headers,
            claims: Map::new(),
            _state: std::marker::PhantomData,
        }
    }

    /// Adds a claim to the JWT.
    pub fn claim<V: Serialize>(mut self, key: &str, value: V) -> Self {
        if let Ok(value) = serde_json::to_value(value) {
            self.claims.insert(key.to_string(), value);
        }
        self
    }

    /// Adds a claim to the JWT using a pre-serialized JSON value.
    pub fn claim_json<V: Into<Value>>(mut self, key: &str, value: V) -> Self {
        self.claims.insert(key.to_string(), value.into());
        self
    }

    /// Encoders the JWT into a string using the specified signer.
    pub fn encode<S: Signer>(mut self, signer: &S) -> Result<String, JwtError> {
        self.headers
            .insert("alg".to_string(), Value::String(signer.name().to_string()));

        let header_json =
            serde_json::to_string(&self.headers).map_err(|_| JwtError::SerializationError)?;
        let claims_json =
            serde_json::to_string(&self.claims).map_err(|_| JwtError::SerializationError)?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
        let signing_input = format!("{}.{}", header_b64, claims_b64);

        let signature = signer.sign(signing_input.as_bytes())?;
        let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}.{}", header_b64, claims_b64, signature_b64))
    }
}

impl Jwt<Decoded> {
    /// Decodeds and verifies a JWT string using the specified verifier.
    pub fn decode<V: Verifier>(token: &str, verifier: &V) -> Result<Jwt<Decoded>, JwtError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::InvalidFormat);
        }

        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| JwtError::InvalidFormat)?;
        let claims_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| JwtError::InvalidFormat)?;
        let signature = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| JwtError::InvalidFormat)?;

        let headers: Map<String, Value> =
            serde_json::from_slice(&header_bytes).map_err(|_| JwtError::SerializationError)?;
        let claims: Map<String, Value> =
            serde_json::from_slice(&claims_bytes).map_err(|_| JwtError::SerializationError)?;

        if let Some(Value::String(alg)) = headers.get("alg") {
            if alg != verifier.name() {
                return Err(JwtError::InvalidAlgorithm);
            }
        } else {
            return Err(JwtError::InvalidAlgorithm);
        }

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        if !verifier.verify(signing_input.as_bytes(), &signature)? {
            return Err(JwtError::InvalidSignature);
        }

        Ok(Jwt {
            headers,
            claims,
            _state: std::marker::PhantomData,
        })
    }

    /// Retrieves a header value by key.
    pub fn header(&self, key: &str) -> Option<&Value> {
        self.headers.get(key)
    }

    /// Retrieves a claim value by key.
    pub fn claim(&self, key: &str) -> Option<&Value> {
        self.claims.get(key)
    }
}

/// Generates a random 256-bit secret for JWT signing.
#[cfg(feature = "rnd")]
pub fn random_secret() -> Vec<u8> {
    let mut secret = [0u8; 32];
    rng().fill_bytes(&mut secret);
    URL_SAFE_NO_PAD.encode(&secret).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    #[cfg(feature = "rnd")]
    fn test_hs256_encode_decode() {
        let secret = random_secret();
        let algorithm = HS256::new(&secret);

        let jwt = Jwt::<Encoder>::new()
            .claim("sub", "1234567890")
            .claim("name", "John Doe")
            .claim("iat", 1516239022)
            .claim_json("admin", Value::Bool(true));

        let token = jwt.encode(&algorithm).unwrap();
        println!("Token: {}", token);

        let decoded = Jwt::<Decoded>::decode(&token, &algorithm).unwrap();
        assert_eq!(
            decoded.claim("sub"),
            Some(&Value::String("1234567890".to_string()))
        );
        assert_eq!(
            decoded.claim("name"),
            Some(&Value::String("John Doe".to_string()))
        );
        assert_eq!(
            decoded.claim("iat"),
            Some(&Value::Number(1516239022.into()))
        );
        assert_eq!(decoded.claim("admin"), Some(&Value::Bool(true)));
    }

    #[test]
    fn test_invalid_signature() {
        let secret = b"256-bit-secret";
        let wrong_secret = b"wrong-secret";

        let algorithm = HS256::new(secret);
        let wrong_algorithm = HS256::new(wrong_secret);

        let jwt = Jwt::<Encoder>::new()
            .claim("sub", "1234567890")
            .claim("name", "John Doe")
            .claim("iat", 1516239022);

        let token = jwt.encode(&algorithm).unwrap();

        let result = Jwt::<Decoded>::decode(&token, &wrong_algorithm);
        assert!(result.is_err())
    }
}
