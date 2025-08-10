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
//! #[derive(Serialize, Deserialize)]
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
//!      let token = Jwt::<Encoder, MyClaims>::with_claims(claims)
//!          .encode(&algorithm)?;
//!
//!      println!("Generated token: {}", token);
//!
//!      // Decoding and verifying the same JWT
//!      let decoded = Jwt::<Decoded, MyClaims>::decode(&token, &algorithm)?;
//!      println!("Decoded claims: {:?}", decoded.claims());
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
//! #[derive(Serialize, Deserialize)]
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
//!     let token = Jwt::<Encoder, MyClaims>::with_claims(claims)
//!         .encode(&signer)?;
//!
//!     println!("Generated RS256 token: {}", token);
//!
//!     // Decoding and verifying the same JWT
//!     let decoded = Jwt::<Decoded, MyClaims>::decode(&token, &verifier)?;
//!     println!("Decoded RS256 claims: {:?}", decoded.claims());
//!
//!     // You can also verify with the signer itself, as it holds the public key
//!     let decoded_with_signer = Jwt::<Decoded, MyClaims>::decode(&token, &signer)?;
//!     assert_eq!(decoded.claims(), decoded_with_signer.claims());
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
    headers: Headers,
    claims: C,
    _state: std::marker::PhantomData<State>,
}

impl<C> Jwt<Encoder, C>
where
    C: Serialize,
{
    /// Creates a new JWT builder with the provided claims instance.
    pub fn with_claims(claims: C) -> Self {
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

    /// Gets a mutable reference to the claims for direct manipulation.
    pub fn claims_mut(&mut self) -> &mut C {
        &mut self.claims
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

    /// Gets an immutable reference to the headers.
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// Gets an immutable reference to the claims.
    pub fn claims(&self) -> &C {
        &self.claims
    }

    /// Retrieves a header value by key.
    pub fn header(&self, key: &str) -> Option<&Value> {
        self.headers.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestClaims {
        sub: String,
        name: String,
        iat: u64,
        admin: Option<bool>,
    }

    #[test]
    fn test_with_claims() {
        let claims = TestClaims {
            sub: "user123".to_string(),
            name: "Test User".to_string(),
            iat: 1234567890,
            admin: Some(true),
        };

        let jwt = Jwt::with_claims(claims.clone());
        assert_eq!(jwt.claims.sub, "user123");
        assert_eq!(jwt.claims.name, "Test User");
        assert_eq!(jwt.claims.iat, 1234567890);
        assert_eq!(jwt.claims.admin, Some(true));
    }

    #[test]
    fn test_claims_mut() {
        let claims = TestClaims {
            sub: "user123".to_string(),
            name: "Test User".to_string(),
            iat: 1234567890,
            admin: Some(false),
        };

        let mut jwt = Jwt::with_claims(claims);
        jwt.claims_mut().admin = Some(true);
        assert_eq!(jwt.claims.admin, Some(true));
    }

    #[test]
    fn test_header_access() {
        let claims = TestClaims {
            sub: "user123".to_string(),
            name: "Test User".to_string(),
            iat: 1234567890,
            admin: None,
        };

        let jwt = Jwt::<Encoder, TestClaims>::with_claims(claims).header("custom", "header_value");

        let decoded_jwt = Jwt::<Decoded, TestClaims> {
            headers: jwt.headers,
            claims: jwt.claims,
            _state: std::marker::PhantomData,
        };

        assert_eq!(
            decoded_jwt.header("typ"),
            Some(&Value::String("JWT".to_string()))
        );
        assert_eq!(
            decoded_jwt.header("custom"),
            Some(&Value::String("header_value".to_string()))
        );
        assert_eq!(decoded_jwt.header("nonexistent"), None);
    }

    #[test]
    fn test_headers_and_claims_getters() {
        let claims = TestClaims {
            sub: "test".to_string(),
            name: "Test User".to_string(),
            iat: 1234567890,
            admin: None,
        };

        let jwt = Jwt::<Decoded, TestClaims> {
            headers: {
                let mut h = Map::new();
                h.insert("typ".to_string(), Value::String("JWT".to_string()));
                h
            },
            claims: claims.clone(),
            _state: std::marker::PhantomData,
        };

        assert_eq!(
            jwt.headers().get("typ"),
            Some(&Value::String("JWT".to_string()))
        );
        assert_eq!(jwt.claims().sub, "test");
    }

    #[test]
    fn test_hs256_encode_decode() {
        let secret = random_secret();
        let algorithm = HS256::new(&secret);

        let claims = TestClaims {
            sub: "1234567890".to_string(),
            name: "John Doe".to_string(),
            iat: 1516239022,
            admin: Some(true),
        };

        let jwt = Jwt::<Encoder, TestClaims>::with_claims(claims.clone());
        let token = jwt.encode(&algorithm).unwrap();
        println!("Token: {}", token);

        let decoded = Jwt::<Decoded, TestClaims>::decode(&token, &algorithm).unwrap();
        assert_eq!(decoded.claims(), &claims);
    }

    #[test]
    fn test_invalid_signature() {
        let secret = b"256-bit-secret";
        let wrong_secret = b"wrong-secret";

        let algorithm = HS256::new(secret);
        let wrong_algorithm = HS256::new(wrong_secret);

        let claims = TestClaims {
            sub: "1234567890".to_string(),
            name: "John Doe".to_string(),
            iat: 1516239022,
            admin: None,
        };

        let jwt = Jwt::<Encoder, TestClaims>::with_claims(claims);
        let token = jwt.encode(&algorithm).unwrap();

        let result = Jwt::<Decoded, TestClaims>::decode(&token, &wrong_algorithm);
        assert!(result.is_err())
    }

    #[test]
    fn test_rs256_encode_decode() {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        struct RS256Claims {
            sub: String,
            admin: bool,
            roles: Vec<String>,
        }

        let (private_key, public_key) = rsa_keypair().unwrap();
        let signer = RS256Signer::new(private_key);
        let verifier = RS256Verifier::new(public_key);

        let claims = RS256Claims {
            sub: "test-user".to_string(),
            admin: true,
            roles: vec!["editor".to_string(), "viewer".to_string()],
        };

        let jwt = Jwt::<Encoder, RS256Claims>::with_claims(claims.clone());
        let token = jwt.encode(&signer).unwrap();
        println!("RS256 Token: {}", token);

        // Verify with the separate verifier
        let decoded = Jwt::<Decoded, RS256Claims>::decode(&token, &verifier).unwrap();
        assert_eq!(decoded.claims(), &claims);

        // Also verify with the signer itself, which also implements Verifier
        let decoded_with_signer = Jwt::<Decoded, RS256Claims>::decode(&token, &signer).unwrap();
        assert_eq!(decoded.claims(), decoded_with_signer.claims());
    }

    #[test]
    fn test_rs256_invalid_signature() {
        let claims = TestClaims {
            sub: "some-user".to_string(),
            name: "Test User".to_string(),
            iat: 1234567890,
            admin: None,
        };

        // Key pair for signing
        let (private_key_signer, _) = rsa_keypair().unwrap();
        let signer = RS256Signer::new(private_key_signer);

        // A different key pair for verifying
        let (_, public_key_verifier) = rsa_keypair().unwrap();
        let wrong_verifier = RS256Verifier::new(public_key_verifier);

        let jwt = Jwt::<Encoder, TestClaims>::with_claims(claims);
        let token = jwt.encode(&signer).unwrap();

        // Attempt to decode with the wrong public key
        let result = Jwt::<Decoded, TestClaims>::decode(&token, &wrong_verifier);
        assert!(matches!(result, Err(JwtError::InvalidSignature)));
    }

    #[test]
    fn test_invalid_format() {
        let algorithm = HS256::new(b"secret");

        // Test with wrong number of parts
        let result = Jwt::<Decoded, TestClaims>::decode("invalid", &algorithm);
        assert!(matches!(result, Err(JwtError::InvalidFormat)));

        let result = Jwt::<Decoded, TestClaims>::decode("too.many.parts.here", &algorithm);
        assert!(matches!(result, Err(JwtError::InvalidFormat)));

        // Test with invalid base64
        let result =
            Jwt::<Decoded, TestClaims>::decode("invalid_base64.claims.signature", &algorithm);
        assert!(matches!(result, Err(JwtError::InvalidFormat)));
    }

    #[test]
    fn test_invalid_algorithm() {
        let hs_algorithm = HS256::new(b"secret");
        let (_, public_key) = rsa_keypair().unwrap();
        let rs_algorithm = RS256Verifier::new(public_key);

        let claims = TestClaims {
            sub: "test".to_string(),
            name: "Test User".to_string(),
            iat: 1234567890,
            admin: None,
        };

        // Encode with HS256
        let jwt = Jwt::<Encoder, TestClaims>::with_claims(claims);
        let token = jwt.encode(&hs_algorithm).unwrap();

        // Try to decode with RS256 - this should fail with InvalidAlgorithm
        let result = Jwt::<Decoded, TestClaims>::decode(&token, &rs_algorithm);
        assert!(matches!(result, Err(JwtError::InvalidAlgorithm)));
    }
}
