# jwtoken

A simple Rust utility library for encoding and decoding JSON Web Tokens (JWT).

## Installation

Add `jwtoken` to your `Cargo.toml`:

```toml
[dependencies]
# Only HS256 (default)
jwtoken = "0.1.0"

# With random secret generation
jwtoken = { version = "0.1.0", features = ["rnd"] }
```

## Usage

### HMAC-SHA256 (HS256)

HS256 uses a shared secret key for both signing and verification:

```rust
use jwtoken::{random_secret, Jwt, Builder, Decoded, HS256};

fn main() -> Result<(), jwtoken::JwtError> {
    let secret = random_secret();
    let algorithm = HS256::new(secret);

    // Encoding a JWT
    let token = Jwt::<Builder>::new()
        .claim("sub", "1234567890")
        .claim("name", "John Doe")
        .claim("iat", 1516239022)
        .encode(&algorithm)?;

    println!("Generated token: {}", token);

    // Decoding and verifying the same JWT
    let decoded = Jwt::<Decoded>::decode(&token, &algorithm)?;
    println!("Decoded claims: {:?}", decoded.claims);

    Ok(())
}
```

## API Reference

### JWT Builder

```rust
let jwt = Jwt::<Builder>::new()
    .claim("key", "value")           // Add a claim
    .claim_json("key", json_value)   // Add a Serializable value
    .encode(&algorithm)?;            // Sign and encode to string
```

### JWT Decoder

```rust
let decoded = Jwt::<Decoded>::decode(&token, &algorithm)?;

// Access claims
let user_id = decoded.claim("sub");
let name = decoded.claim("name");

// Access headers
let algorithm = decoded.header("alg");
```

### Algorithms

#### HS256 (HMAC-SHA256)
```rust
let algorithm = HS256::new(secret_bytes);
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
    Err(JwtError::Custom(msg)) => println!("Custom error: {}", msg),
}
```
