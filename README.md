# jwtoken

[![Documentation](https://docs.rs/jwtoken/badge.svg)](https://docs.rs/jwtoken)
[![Crates.io](https://img.shields.io/crates/v/jwtoken.svg)](https://crates.io/crates/jwtoken)

A simple Rust utility library for encoding and decoding JSON Web Tokens (JWT).

## Installation

Add `jwtoken` to your `Cargo.toml`:

```toml
[dependencies]
jwtoken = { version = "0.1.0", features = ["rnd"] }
```

To enable the `random_secret` function, include the `rnd` feature:
```toml
[dependencies]
jwtoken = { version = "0.1.0", features = ["rnd"] }
```

## Usage

### Encoding and Decoding a JWT

Note: The `random_secret` function is only available when the `rnd` feature is enabled.

```rust
use jwtoken::{random_secret, Jwt, HS256};

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
