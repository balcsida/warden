//! Key generation and bundle signing (admin side; `warden policy keygen|sign`).

use std::path::Path;

use base64::Engine;
use base64::prelude::BASE64_STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::bundle::{PolicyError, SignatureFile};

pub fn keygen() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("os randomness");
    SigningKey::from_bytes(&seed)
}

pub fn signing_key_to_string(k: &SigningKey) -> String {
    B64.encode(k.to_bytes())
}

pub fn parse_signing_key(b64: &str) -> Result<SigningKey, String> {
    let bytes = B64.decode(b64.trim()).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "key is not 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&arr))
}

pub fn verifying_key(k: &SigningKey) -> VerifyingKey {
    k.verifying_key()
}

/// Sign `<bundle>` and write `<bundle>.sig`. The bundle is parsed first so an
/// unloadable file is never signed.
pub fn sign_file(bundle: &Path, key: &SigningKey) -> Result<(), PolicyError> {
    let bytes = std::fs::read(bundle)?;
    let _: crate::bundle::Bundle = serde_json::from_slice(&bytes)?;
    let sig = key.sign(&bytes);
    let file = SignatureFile {
        sig: B64.encode(sig.to_bytes()),
    };
    std::fs::write(
        format!("{}.sig", bundle.display()),
        serde_json::to_string_pretty(&file)? + "\n",
    )?;
    Ok(())
}
