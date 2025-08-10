//! Error types for JWT encoding and decoding operations.
//!
//! This module defines the `JwtError` enum, which encapsulates all possible errors
//! that can occur during JWT processing.

use std::fmt;

/// Represents errors that can occur during JWT operations.
#[derive(Debug)]
pub enum JwtError {
    /// The JWT format is invalid (e.g., incorrect number of segments).
    InvalidFormat,
    /// The JWT signature is invalid.
    InvalidSignature,
    /// Failed to serialize or deserialize JSON data.
    SerializationError,
    /// The JWT uses an invalid or unsupported algorithm.
    InvalidAlgorithm,
    /// Invalid or unsupported cryptographic key.
    InvalidKey,
    /// A custom error message.
    Custom(String),
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            JwtError::InvalidFormat => write!(f, "Invalid JWT format"),
            JwtError::InvalidSignature => write!(f, "Invalid signature"),
            JwtError::SerializationError => write!(f, "JSON serialization error"),
            JwtError::InvalidAlgorithm => write!(f, "Invalid or unsupported algorithm"),
            JwtError::InvalidKey => write!(f, "Invalid or unsupported cryptographic key"),
            JwtError::Custom(msg) => write!(f, "Custom error: {}", msg),
        }
    }
}

impl std::error::Error for JwtError {}

impl From<String> for JwtError {
    fn from(err: String) -> Self {
        JwtError::Custom(err)
    }
}

impl From<&'static str> for JwtError {
    fn from(err: &'static str) -> Self {
        JwtError::Custom(err.to_string())
    }
}
