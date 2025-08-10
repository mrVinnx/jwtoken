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
//!
//! fn main() -> Result<(), jwtoken::JwtError> {
//!      let secret = random_secret();
//!      let algorithm = HS256::new(&secret);
//!
//!      // Encoding a JWT
//!      let token = Jwt::<Encoder>::new()
//!          .claim("sub", "1234567890")
//!          .claim("name", "John Doe")
//!          .claim("iat", 1516239022)
//!          .encode(&algorithm)?;
//!
//!      println!("Generated token: {}", token);
//!
//!      // Decoding and verifying the same JWT
//!      let decoded = Jwt::<Decoded>::decode(&token, &algorithm)?;
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
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Generate a new RSA key pair
//!     let (private_key, public_key) = rsa_keypair()?;
//!
//!     // Create a signer with the private key and a verifier with the public key
//!     let signer = RS256Signer::new(private_key);
//!     let verifier = RS256Verifier::new(public_key);
//!
//!     // Encoding a JWT
//!     let token = Jwt::<Encoder>::new()
//!         .claim("sub", "user-id-42")
//!         .claim("name", "Jane Doe")
//!         .claim("admin", true)
//!         .encode(&signer)?;
//!
//!     println!("Generated RS256 token: {}", token);
//!
//!     // Decoding and verifying the same JWT
//!     let decoded = Jwt::<Decoded>::decode(&token, &verifier)?;
//!     println!("Decoded RS256 claims: {:?}", decoded.claims);
//!
//!     // You can also verify with the signer itself, as it holds the public key
//!     let decoded_with_signer = Jwt::<Decoded>::decode(&token, &signer)?;
//!     assert_eq!(decoded.claims, decoded_with_signer.claims);
//!
//!     Ok(())
//! }
//! # }
//! ```

mod algorithm;
mod error;

pub use algorithm::*;
pub use error::*;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use serde_json::{Map, Value};

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

#[cfg(feature = "key-gen")]
use rand::RngCore;

/// Generates a random 256-bit secret for JWT signing.
#[cfg(feature = "key-gen")]
pub fn random_secret() -> Vec<u8> {
    use rand::rng;

    let mut secret = [0u8; 32];

    rng().fill_bytes(&mut secret);
    URL_SAFE_NO_PAD.encode(&secret).into_bytes()
}

/// Generates a new 2048-bit RSA key pair.
#[cfg(all(feature = "key-gen", feature = "rs256"))]
pub fn rsa_keypair() -> Result<(rsa::RsaPrivateKey, rsa::RsaPublicKey), rsa::Error> {
    let mut rng = rsa::rand_core::OsRng;

    let bits = 2048;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = private_key.to_public_key();
    Ok((private_key, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    #[cfg(feature = "key-gen")]
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
    #[cfg(feature = "hs256")]
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

    #[test]
    #[cfg(all(feature = "key-gen", feature = "rs256"))]
    fn test_rs256_encode_decode() {
        let (private_key, public_key) = rsa_keypair().unwrap();
        let signer = RS256Signer::new(private_key);
        let verifier = RS256Verifier::new(public_key);

        let jwt = Jwt::<Encoder>::new()
            .claim("sub", "test-user")
            .claim("admin", true)
            .claim_json("roles", serde_json::json!(["editor", "viewer"]));

        let token = jwt.encode(&signer).unwrap();
        println!("RS256 Token: {}", token);

        // Verify with the separate verifier
        let decoded = Jwt::<Decoded>::decode(&token, &verifier).unwrap();
        assert_eq!(
            decoded.claim("sub"),
            Some(&Value::String("test-user".to_string()))
        );
        assert_eq!(decoded.claim("admin"), Some(&Value::Bool(true)));
        assert_eq!(
            decoded.claim("roles"),
            Some(&serde_json::json!(["editor", "viewer"]))
        );

        // Also verify with the signer itself, which also implements Verifier
        let decoded_with_signer = Jwt::<Decoded>::decode(&token, &signer).unwrap();
        assert_eq!(decoded.claims, decoded_with_signer.claims);
    }

    #[test]
    #[cfg(all(feature = "key-gen", feature = "rs256"))]
    fn test_rs256_invalid_signature() {
        // Key pair for signing
        let (private_key_signer, _) = rsa_keypair().unwrap();
        let signer = RS256Signer::new(private_key_signer);

        // A different key pair for verifying
        let (_, public_key_verifier) = rsa_keypair().unwrap();
        let wrong_verifier = RS256Verifier::new(public_key_verifier);

        let jwt = Jwt::<Encoder>::new().claim("sub", "some-user");

        let token = jwt.encode(&signer).unwrap();

        // Attempt to decode with the wrong public key
        let result = Jwt::<Decoded>::decode(&token, &wrong_verifier);
        assert!(matches!(result, Err(JwtError::InvalidSignature)));
    }
}
