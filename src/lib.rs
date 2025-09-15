//! A flexible utility library for encoding and decoding JSON Web Tokens (JWT).
//!
//! This crate provides a type state API for creating, signing, and verifying JWTs with support for HMAC-SHA256 (HS256) and RSA-SHA256 (RS256).
//!
//! # Examples
//!
//! ## Using HS256 (HMAC-SHA256)
//!
//! ```rust
//! # #[cfg(all(feature = "key-gen", feature = "hs256"))]
//! # {
//! use jwtoken::{random_secret, HS256, Jwt, Encoder, Decoded};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Debug, PartialEq, Serialize, Deserialize)]
//! struct MyClaims {
//!     sub: String,
//!     name: String,
//!     iat: u64,
//! }
//!
//! fn main() -> Result<(), jwtoken::JwtError> {
//!      let secret = random_secret();
//!      let algorithm = HS256::new(&secret);
//!
//!      let claims = MyClaims {
//!          sub: "1234567890".to_string(),
//!          name: "John Doe".to_string(),
//!          iat: 1516239022,
//!      };
//!
//!      // Encoding a JWT
//!      let token = Jwt::<Encoder, MyClaims>::new(claims)
//!          .encode(&algorithm)?;
//!
//!      println!("Generated token: {}", token);
//!
//!      // Decoding and verifying the same JWT
//!      let decoded = Jwt::<Decoded, MyClaims>::decode(&token, &algorithm)?;
//!      println!("Decoded claims: {:?}", decoded.claims);
//!
//!      Ok(())
//! }
//! # }
//! ```
//!
//! ## Using RS256 (RSA-SHA256)
//!
//! ```rust
//! # #[cfg(all(feature = "key-gen", feature = "rs256"))]
//! # {
//! use jwtoken::{rsa_keypair, RS256Signer, RS256Verifier, Jwt, Encoder, Decoded};
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Debug, PartialEq, Serialize, Deserialize)]
//! struct MyClaims {
//!     sub: String,
//!     name: String,
//!     admin: bool,
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Generate a new RSA key pair
//!     let (private_key, public_key) = rsa_keypair()?;
//!
//!     // Create a signer with the private key and a verifier with the public key
//!     let signer = RS256Signer::new(private_key);
//!     let verifier = RS256Verifier::new(public_key);
//!
//!     let claims = MyClaims {
//!         sub: "user-id-42".to_string(),
//!         name: "Jane Doe".to_string(),
//!         admin: true,
//!     };
//!
//!     // Encoding a JWT
//!     let token = Jwt::<Encoder, MyClaims>::new(claims)
//!         .encode(&signer)?;
//!
//!     println!("Generated RS256 token: {}", token);
//!
//!     // Decoding and verifying the same JWT
//!     let decoded = Jwt::<Decoded, MyClaims>::decode(&token, &verifier)?;
//!     println!("Decoded RS256 claims: {:?}", decoded.claims);
//!
//!     // You can also verify with the signer itself, as it holds the public key
//!     let decoded_with_signer = Jwt::<Decoded, MyClaims>::decode(&token, &signer)?;
//!     assert_eq!(decoded.claims, decoded_with_signer.claims);
//!
//!     Ok(())
//! }
//! # }
//! ```

mod algorithm;
mod error;
mod keygen;

pub use algorithm::*;
pub use error::*;
pub use keygen::*;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A encoder state for creating JWTs.
#[derive(Debug, Clone)]
pub struct Encoder;

/// A decoded state JWT to be inspected
#[derive(Debug, Clone)]
pub struct Decoded;

/// JWT headers map. Values "typ" to "JWT" and "alg" to the appropriate algorithm are internally set.
pub type Headers = Map<String, Value>;

/// A JSON Web Token (JWT) in a specific state (either `Encoder` or `Decoded`).
#[derive(Debug, Clone)]
pub struct Jwt<State, C> {
    pub headers: Headers,
    pub claims: C,
    _state: std::marker::PhantomData<State>,
}

impl<C> Jwt<Encoder, C>
where
    C: Serialize,
{
    /// Creates a new JWT builder with the provided claims instance.
    pub fn new(claims: C) -> Self {
        let mut headers = Map::new();
        headers.insert("typ".to_string(), Value::String("JWT".to_string()));

        Self {
            headers,
            claims,
            _state: std::marker::PhantomData,
        }
    }

    /// Adds a header to the JWT.
    pub fn header<V: Serialize>(mut self, key: &str, value: V) -> Self {
        if let Ok(value) = serde_json::to_value(value) {
            self.headers.insert(key.to_string(), value);
        }
        self
    }

    /// Encodes the JWT into a string using the specified signer.
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

impl<C> Jwt<Decoded, C>
where
    C: for<'de> Deserialize<'de>,
{
    /// Decodes and verifies a JWT string using the specified verifier.
    pub fn decode<V: Verifier>(token: &str, verifier: &V) -> Result<Jwt<Decoded, C>, JwtError> {
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

        let headers: Headers =
            serde_json::from_slice(&header_bytes).map_err(|_| JwtError::SerializationError)?;
        let claims: C =
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

    /// Retrieves a header value by key and deserializes it to the specified type.
    pub fn header<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        self.header_strict(key).ok().flatten()
    }

    /// Retrieves a header value by key and deserializes it to the specified type.
    /// Distinguish between "missing" and "invalid" values.
    pub fn header_strict<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<Option<T>, JwtError> {
        if let Some(value) = self.headers.get(key) {
            T::deserialize(value)
                .map(Some)
                .map_err(|_| JwtError::SerializationError)
        } else {
            Ok(None)
        }
    }
}
