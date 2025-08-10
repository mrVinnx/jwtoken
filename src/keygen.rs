#[cfg(feature = "key-gen")]
use rand::RngCore;

/// Generates a random 256-bit secret for JWT signing.
#[cfg(feature = "key-gen")]
pub fn random_secret() -> Vec<u8> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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
