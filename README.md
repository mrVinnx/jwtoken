# jwtoken

A simple Rust utility library for encoding and decoding JSON Web Tokens (JWT).

## Installation

Add `jwtoken` to your `Cargo.toml`:

```toml
[dependencies]
jwtoken = "0.1.0"
```

## Usage

### Encoding and Decoding a JWT

```rust
use jwtoken::{Jwt, HS256};

fn main() -> Result<(), jwtoken::JwtError> {
    let secret = random_secret();
    let algorithm = HS256::new(&secret);

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
