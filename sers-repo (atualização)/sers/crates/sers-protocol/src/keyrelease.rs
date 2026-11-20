//! Delivery of a package key to one authorized session.
//!
//! The server and the client each contribute an ephemeral X25519 key. The
//! shared secret goes through HKDF with a context that binds application,
//! installation, package, both public keys and the challenge nonce; the
//! package key is then sealed with AES-256-GCM under that session key.
//! The client's ephemeral key was part of the *signed* challenge, so only the
//! authenticated installation can open the result.

use crate::signing::push_len_prefixed;
use sers_core::{ApplicationId, Digest32, InstallationId, Nonce32, SersError, X25519PublicKey};
use sers_crypto::{aead, kdf::derive_key, kex::EphemeralKeyPair, secret::SymmetricKey};
use zeroize::Zeroizing;

const DOMAIN_KEY_RELEASE: &[u8] = b"SERS-KEY-RELEASE-v1\0";

pub struct KeyReleaseContext<'a> {
    pub nonce: &'a Nonce32,
    pub application_id: &'a ApplicationId,
    pub installation_id: &'a InstallationId,
    pub package_digest: &'a Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRelease {
    pub server_public_key: X25519PublicKey,
    /// `nonce || ciphertext || tag` of the package key.
    pub sealed_key: Vec<u8>,
}

fn context_bytes(
    ctx: &KeyReleaseContext<'_>,
    client_public: &X25519PublicKey,
    server_public: &X25519PublicKey,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(DOMAIN_KEY_RELEASE);
    push_len_prefixed(&mut buf, ctx.application_id.as_str().as_bytes());
    buf.extend_from_slice(ctx.installation_id.as_bytes());
    buf.extend_from_slice(ctx.package_digest.as_bytes());
    buf.extend_from_slice(client_public.as_bytes());
    buf.extend_from_slice(server_public.as_bytes());
    buf
}

/// Server side.
pub fn seal_key_release(
    ctx: &KeyReleaseContext<'_>,
    client_public: &X25519PublicKey,
    package_key: &SymmetricKey,
) -> Result<KeyRelease, SersError> {
    let server = EphemeralKeyPair::generate();
    let server_public = X25519PublicKey::from_bytes(server.public_key());
    let shared = server.agree(client_public.as_bytes())?;
    let info = context_bytes(ctx, client_public, &server_public);
    let session = derive_key(&shared[..], ctx.nonce.as_bytes(), &info)?;
    let sealed_key = aead::seal(&session, &info, package_key.expose())?;
    Ok(KeyRelease {
        server_public_key: server_public,
        sealed_key,
    })
}

/// Client side. Consumes the ephemeral key pair used in the challenge request.
pub fn open_key_release(
    ctx: &KeyReleaseContext<'_>,
    client: EphemeralKeyPair,
    release: &KeyRelease,
) -> Result<SymmetricKey, SersError> {
    let client_public = X25519PublicKey::from_bytes(client.public_key());
    let shared = client.agree(release.server_public_key.as_bytes())?;
    let info = context_bytes(ctx, &client_public, &release.server_public_key);
    let session = derive_key(&shared[..], ctx.nonce.as_bytes(), &info)?;
    let key = aead::open(&session, &info, &release.sealed_key)?;
    if key.len() != SymmetricKey::LEN {
        return Err(SersError::Crypto("released key has wrong length"));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&key);
    Ok(SymmetricKey::from_bytes(*bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Parts {
        nonce: Nonce32,
        app: ApplicationId,
        inst: InstallationId,
        digest: Digest32,
    }

    fn parts() -> Parts {
        Parts {
            nonce: Nonce32::from_bytes([1; 32]),
            app: ApplicationId::new("acme.editor").unwrap(),
            inst: InstallationId::from_bytes([2; 32]),
            digest: Digest32::from_bytes([3; 32]),
        }
    }

    fn ctx(p: &Parts) -> KeyReleaseContext<'_> {
        KeyReleaseContext {
            nonce: &p.nonce,
            application_id: &p.app,
            installation_id: &p.inst,
            package_digest: &p.digest,
        }
    }

    #[test]
    fn roundtrip_delivers_the_same_key() {
        let p = parts();
        let package_key = SymmetricKey::generate().unwrap();
        let client = EphemeralKeyPair::generate();
        let client_pub = X25519PublicKey::from_bytes(client.public_key());
        let release = seal_key_release(&ctx(&p), &client_pub, &package_key).unwrap();
        let opened = open_key_release(&ctx(&p), client, &release).unwrap();
        assert_eq!(opened.expose(), package_key.expose());
    }

    #[test]
    fn different_context_cannot_open() {
        let p = parts();
        let package_key = SymmetricKey::generate().unwrap();
        let client = EphemeralKeyPair::generate();
        let client_pub = X25519PublicKey::from_bytes(client.public_key());
        let release = seal_key_release(&ctx(&p), &client_pub, &package_key).unwrap();
        let mut other = parts();
        other.digest = Digest32::from_bytes([9; 32]);
        assert!(open_key_release(&ctx(&other), client, &release).is_err());
    }

    #[test]
    fn another_client_key_cannot_open() {
        let p = parts();
        let package_key = SymmetricKey::generate().unwrap();
        let intended = EphemeralKeyPair::generate();
        let intended_pub = X25519PublicKey::from_bytes(intended.public_key());
        let release = seal_key_release(&ctx(&p), &intended_pub, &package_key).unwrap();
        let attacker = EphemeralKeyPair::generate();
        assert!(open_key_release(&ctx(&p), attacker, &release).is_err());
    }

    #[test]
    fn tampered_sealed_key_is_rejected() {
        let p = parts();
        let package_key = SymmetricKey::generate().unwrap();
        let client = EphemeralKeyPair::generate();
        let client_pub = X25519PublicKey::from_bytes(client.public_key());
        let mut release = seal_key_release(&ctx(&p), &client_pub, &package_key).unwrap();
        let last = release.sealed_key.len() - 1;
        release.sealed_key[last] ^= 1;
        assert!(open_key_release(&ctx(&p), client, &release).is_err());
    }

    #[test]
    fn low_order_client_key_is_rejected() {
        let p = parts();
        let package_key = SymmetricKey::generate().unwrap();
        let zero = X25519PublicKey::from_bytes([0; 32]);
        assert!(seal_key_release(&ctx(&p), &zero, &package_key).is_err());
    }
}
