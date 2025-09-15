#[cfg(test)]
mod tests {
    use jwtoken::{
        Decoded, Encoder, HS256, Jwt, JwtError, RS256Signer, RS256Verifier, random_secret,
        rsa_keypair,
    };
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestClaims {
        sub: String,
        name: String,
        iat: u64,
        admin: Option<bool>,
    }

    #[test]
    fn test_new() {
        let claims = TestClaims {
            sub: "user123".to_string(),
            name: "Test User".to_string(),
            iat: 1234567890,
            admin: Some(true),
        };

        let jwt = Jwt::new(claims.clone());
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

        let mut jwt = Jwt::new(claims);
        jwt.claims.admin = Some(true);
        assert_eq!(jwt.claims.admin, Some(true));
    }

    #[test]
    fn test_header_access() {
        let secret = random_secret();
        let algorithm = HS256::new(&secret);

        let claims = TestClaims {
            sub: "user123".to_string(),
            name: "Test User".to_string(),
            iat: 1234567890,
            admin: None,
        };

        let jwt = Jwt::<Encoder, TestClaims>::new(claims).header("custom", "header_value");
        let token = jwt.encode(&algorithm).unwrap();
        let decoded_jwt = Jwt::<Decoded, TestClaims>::decode(&token, &algorithm).unwrap();

        // Test generic header method
        let typ: String = decoded_jwt.header("typ").unwrap();
        assert_eq!(typ, "JWT");

        let custom: String = decoded_jwt.header("custom").unwrap();
        assert_eq!(custom, "header_value");

        let nonexistent: Option<String> = decoded_jwt.header("nonexistent");
        assert_eq!(nonexistent, None);
    }

    #[test]
    fn test_headers_and_claims_getters() {
        let secret = random_secret();
        let algorithm = HS256::new(&secret);

        let claims = TestClaims {
            sub: "test".to_string(),
            name: "Test User".to_string(),
            iat: 1234567890,
            admin: None,
        };

        let jwt = Jwt::<Encoder, TestClaims>::new(claims.clone());
        let token = jwt.encode(&algorithm).unwrap();
        let decoded_jwt = Jwt::<Decoded, TestClaims>::decode(&token, &algorithm).unwrap();

        assert_eq!(
            decoded_jwt.headers.get("typ"),
            Some(&Value::String("JWT".to_string()))
        );
        assert_eq!(decoded_jwt.claims.sub, "test");
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

        let jwt = Jwt::<Encoder, TestClaims>::new(claims.clone());
        let token = jwt.encode(&algorithm).unwrap();
        println!("Token: {}", token);

        let decoded = Jwt::<Decoded, TestClaims>::decode(&token, &algorithm).unwrap();
        assert_eq!(decoded.claims, claims);
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

        let jwt = Jwt::<Encoder, TestClaims>::new(claims);
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

        let jwt = Jwt::<Encoder, RS256Claims>::new(claims.clone());
        let token = jwt.encode(&signer).unwrap();
        println!("RS256 Token: {}", token);

        // Verify with the separate verifier
        let decoded = Jwt::<Decoded, RS256Claims>::decode(&token, &verifier).unwrap();
        assert_eq!(decoded.claims, claims);

        // Also verify with the signer itself, which also implements Verifier
        let decoded_with_signer = Jwt::<Decoded, RS256Claims>::decode(&token, &signer).unwrap();
        assert_eq!(decoded.claims, decoded_with_signer.claims);
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

        let jwt = Jwt::<Encoder, TestClaims>::new(claims);
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
        let jwt = Jwt::<Encoder, TestClaims>::new(claims);
        let token = jwt.encode(&hs_algorithm).unwrap();

        // Try to decode with RS256 - this should fail with InvalidAlgorithm
        let result = Jwt::<Decoded, TestClaims>::decode(&token, &rs_algorithm);
        assert!(matches!(result, Err(JwtError::InvalidAlgorithm)));
    }

    #[test]
    fn test_generic_header_types() {
        let secret = random_secret();
        let algorithm = HS256::new(&secret);

        let claims = TestClaims {
            sub: "user123".to_string(),
            name: "Test User".to_string(),
            iat: 1234567890,
            admin: None,
        };

        let jwt = Jwt::<Encoder, TestClaims>::new(claims)
            .header("string_header", "test_value")
            .header("number_header", 42)
            .header("bool_header", true);

        let token = jwt.encode(&algorithm).unwrap();
        let decoded = Jwt::<Decoded, TestClaims>::decode(&token, &algorithm).unwrap();

        // Test different generic types
        let string_val: String = decoded.header("string_header").unwrap();
        assert_eq!(string_val, "test_value");

        let number_val: i32 = decoded.header("number_header").unwrap();
        assert_eq!(number_val, 42);

        let bool_val: bool = decoded.header("bool_header").unwrap();
        assert_eq!(bool_val, true);

        // Test non-existent header
        let missing: Option<String> = decoded.header("missing_header");
        assert_eq!(missing, None);

        // Test wrong type (should fail with header_strict)
        let wrong_type_result: Result<Option<bool>, JwtError> =
            decoded.header_strict("string_header");
        assert!(wrong_type_result.is_err());
    }

    #[test]
    fn test_header_vs_header_strict() {
        let secret = random_secret();
        let algorithm = HS256::new(&secret);

        let claims = TestClaims {
            sub: "user123".to_string(),
            name: "Test User".to_string(),
            iat: 1234567890,
            admin: None,
        };

        let jwt = Jwt::<Encoder, TestClaims>::new(claims)
            .header("valid_string", "test_value")
            .header("invalid_for_number", "not_a_number");

        let token = jwt.encode(&algorithm).unwrap();
        let decoded = Jwt::<Decoded, TestClaims>::decode(&token, &algorithm).unwrap();

        // Valid header - both methods work
        let valid_header: Option<String> = decoded.header("valid_string");
        assert_eq!(valid_header, Some("test_value".to_string()));

        let valid_header_strict: Result<Option<String>, JwtError> =
            decoded.header_strict("valid_string");
        assert_eq!(valid_header_strict.unwrap(), Some("test_value".to_string()));

        // Missing header - both return None/Ok(None)
        let missing_header: Option<String> = decoded.header("missing");
        assert_eq!(missing_header, None);

        let missing_header_strict: Result<Option<String>, JwtError> =
            decoded.header_strict("missing");
        assert_eq!(missing_header_strict.unwrap(), None);

        // Invalid type conversion - header returns None, header_strict returns Err
        let invalid_as_number: Option<i32> = decoded.header("invalid_for_number");
        assert_eq!(invalid_as_number, None);

        let invalid_as_number_strict: Result<Option<i32>, JwtError> =
            decoded.header_strict("invalid_for_number");
        assert!(invalid_as_number_strict.is_err());
    }
}
