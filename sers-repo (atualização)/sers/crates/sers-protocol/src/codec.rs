use crate::message::{ProtocolMessage, PROTOCOL_VERSION};
use serde::{de::DeserializeOwned, Serialize};
use sers_core::SersError;

/// Hard upper bound for any single protocol message.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

/// Decodes a message. Rejects oversized input, malformed JSON, unknown or
/// duplicate fields (`deny_unknown_fields`), non-canonical hex, invalid
/// identifiers and any version other than [`PROTOCOL_VERSION`].
/// Error details are deliberately generic.
pub fn decode<T: DeserializeOwned + ProtocolMessage>(bytes: &[u8]) -> Result<T, SersError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(SersError::Protocol("message too large"));
    }
    let msg: T =
        serde_json::from_slice(bytes).map_err(|_| SersError::Protocol("malformed message"))?;
    if msg.version() != PROTOCOL_VERSION {
        return Err(SersError::Protocol("unsupported protocol version"));
    }
    Ok(msg)
}

pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, SersError> {
    serde_json::to_vec(msg).map_err(|_| SersError::Protocol("serialization failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::ChallengeRequest;
    use sers_core::{ApplicationId, Digest32, InstallationId, X25519PublicKey};

    fn sample() -> ChallengeRequest {
        ChallengeRequest {
            version: PROTOCOL_VERSION,
            application_id: ApplicationId::new("acme.editor").unwrap(),
            installation_id: InstallationId::from_bytes([1; 32]),
            package_digest: Digest32::from_bytes([2; 32]),
            client_ephemeral_key: X25519PublicKey::from_bytes([3; 32]),
        }
    }

    fn json_with(version: u16, extra: &str, app: &str, inst: &str) -> String {
        format!(
            r#"{{"version":{version},"application_id":"{app}","installation_id":"{inst}","package_digest":"{}","client_ephemeral_key":"{}"{extra}}}"#,
            "02".repeat(32),
            "03".repeat(32)
        )
    }

    #[test]
    fn roundtrip() {
        let req = sample();
        let bytes = encode(&req).unwrap();
        assert_eq!(decode::<ChallengeRequest>(&bytes).unwrap(), req);
    }

    #[test]
    fn rejects_unknown_field() {
        let j = json_with(1, r#","admin":true"#, "acme.editor", &"01".repeat(32));
        assert!(decode::<ChallengeRequest>(j.as_bytes()).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let j = json_with(2, "", "acme.editor", &"01".repeat(32));
        assert_eq!(
            decode::<ChallengeRequest>(j.as_bytes()),
            Err(SersError::Protocol("unsupported protocol version"))
        );
    }

    #[test]
    fn rejects_uppercase_hex() {
        let j = json_with(1, "", "acme.editor", &"AB".repeat(32));
        assert!(decode::<ChallengeRequest>(j.as_bytes()).is_err());
    }

    #[test]
    fn rejects_invalid_application_id() {
        let j = json_with(1, "", "../../etc", &"01".repeat(32));
        assert!(decode::<ChallengeRequest>(j.as_bytes()).is_err());
    }

    #[test]
    fn rejects_duplicate_field() {
        let j = format!(
            r#"{{"version":1,"version":1,"application_id":"acme.editor","installation_id":"{}","package_digest":"{}","client_ephemeral_key":"{}"}}"#,
            "01".repeat(32),
            "02".repeat(32),
            "03".repeat(32)
        );
        assert!(decode::<ChallengeRequest>(j.as_bytes()).is_err());
    }

    #[test]
    fn rejects_oversized_message() {
        let big = vec![b' '; MAX_MESSAGE_BYTES + 1];
        assert_eq!(
            decode::<ChallengeRequest>(&big),
            Err(SersError::Protocol("message too large"))
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode::<ChallengeRequest>(b"").is_err());
        assert!(decode::<ChallengeRequest>(b"\xff\xfe").is_err());
        assert!(decode::<ChallengeRequest>(b"[]").is_err());
    }
}
