# jwtoken

A flexible utility library for encoding and decoding JSON Web Tokens (JWT).

## Installation

Add `jwtoken` to your `Cargo.toml`:

```toml
[dependencies]
# Basic usage
jwtoken = "0.1.4"

# With key generation utilities (for random secrets, RSA keypairs)
jwtoken = { version = "0.1.4", features = ["key-gen"] }

# Enable HS256 algorithm
jwtoken = { version = "0.1.4", features = ["hs256"] }

# Enable RS256 algorithm
jwtoken = { version = "0.1.4", features = ["rs256"] }

# Enable all features
jwtoken = { version = "0.1.4", features = ["full"] }
```

## Usage

### HMAC-SHA256 (HS256)

HS256 uses a shared secret key for both signing and verification:

```rust
use jwtoken::{random_secret, Jwt, Encoder, Decoded, HS256};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct MyClaims {
    sub: String,
    name: String,
    iat: u64,
}

fn main() -> Result<(), jwtoken::JwtError> {
    // Requires the "key-gen" feature
    let secret = random_secret();
    let algorithm = HS256::new(&secret);

    let claims = MyClaims {
        sub: "1234567890".to_string(),
        name: "John Doe".to_string(),
        iat: 1516239022,
    };

    // Encoding a JWT
    let token = Jwt::<Encoder, MyClaims>::new(claims)
        .encode(&algorithm)?;
    println!("Generated token: {}", token);

    // Decoding and verifying the same JWT
    let decoded = Jwt::<Decoded, MyClaims>::decode(&token, &algorithm)?;
    println!("Decoded claims: {:?}", decoded.claims());

    Ok(())
}
```

### RS256 (RSA-SHA256)

RS256 uses an RSA key pair, with the private key for signing and the public key for verification:

```rust
use jwtoken::{rsa_keypair, RS256Signer, RS256Verifier, Jwt, Encoder, Decoded};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct MyClaims {
    sub: String,
    name: String,
    admin: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Requires the "key-gen" and "rs256" features
    let (private_key, public_key) = rsa_keypair()?;

    // Create a signer with the private key
    let signer = RS256Signer::new(private_key);
    // Create a verifier with the public key
    let verifier = RS256Verifier::new(public_key);

    let claims = MyClaims {
        sub: "user-id-42".to_string(),
        name: "Jane Doe".to_string(),
        admin: true,
    };

    // Encoding a JWT
    let token = Jwt::<Encoder, MyClaims>::new(claims)
        .encode(&signer)?;
    println!("Generated RS256 token: {}", token);

    // Decoding and verifying the same JWT with the public key
    let decoded = Jwt::<Decoded, MyClaims>::decode(&token, &verifier)?;
    println!("Decoded RS256 claims: {:?}", decoded.claims());

    // The signer also implements Verifier, so it can be used for verification too
    let decoded_with_signer = Jwt::<Decoded, MyClaims>::decode(&token, &signer)?;
    assert_eq!(decoded.claims(), decoded_with_signer.claims());

    Ok(())
}
```

## API Reference

### JWT Encoder

```rust
    #[derive(Serialize, Deserialize)]
struct MyClaims {
    sub: String,
    name: String,
    role: String,
}

let claims = MyClaims {
    sub: "user123".to_string(),
    name: "John Doe".to_string(),
    role: "admin".to_string(),
};

let jwt = Jwt::<Encoder, MyClaims>::new(claims)
    .header("kid", "key-id-123")                        // Add custom header
    .encode(&algorithm)?;                               // Sign and encode to string
```

### JWT Decoder

```rust
    let decoded = Jwt::<Decoded, MyClaims>::decode(&token, &algorithm)?;

    // Access claims directly through the struct
    let user_id = &decoded.claims().sub;
    let name = &decoded.claims().name;

    // Access headers
    let algorithm = decoded.header("alg");
    let key_id = decoded.header("kid");
```

### Algorithms

#### HS256 (HMAC-SHA256)
```rust
use jwtoken::{random_secret, HS256};
let secret = random_secret();
let algorithm = HS256::new(&secret);
```

#### RS256 (RSA-SHA256)
```rust
use jwtoken::{rsa_keypair, RS256Signer, RS256Verifier};

// Requires the "key-gen" and "rs256" features
let (private_key, public_key) = rsa_keypair().unwrap();

// For signing
let signer = RS256Signer::new(private_key);

// For verifying
let verifier = RS256Verifier::new(public_key);
```

## Error Handling

The library uses a custom `JwtError` enum for error handling:

```rust
use jwtoken::JwtError;

match result {
    Ok(token) => println!("Success: {}", token),
    Err(JwtError::InvalidSignature) => println!("Invalid signature"),
    Err(JwtError::InvalidFormat) => println!("Malformed JWT"),
    Err(JwtError::InvalidAlgorithm) => println!("Algorithm mismatch"),
    Err(JwtError::SerializationError) => println!("JSON error"),
    Err(JwtError::InvalidKey) => println!("Invalid or unsupported cryptographic key"),
    Err(JwtError::Custom(msg)) => println!("Custom error: {}", msg),
}
```
