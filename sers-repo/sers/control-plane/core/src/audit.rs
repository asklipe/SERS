use sers_core::TenantId;
use sers_crypto::hash::sha256_parts;

/// One audit record. Records form a hash chain, so removing or editing an
/// entry is detectable by [`AuditLog::verify_chain`]. (A chain held by the same
/// party that can rewrite it only detects *partial* tampering; production must
/// ship records to append-only external storage.)
///
/// Secrets (API keys, license credentials, key material) are never recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub seq: u64,
    pub at: u64,
    pub tenant: Option<String>,
    pub action: &'static str,
    pub subject: String,
    pub allowed: bool,
    pub detail: &'static str,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

fn push_lp(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

fn compute_hash(e: &AuditEvent) -> [u8; 32] {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&e.seq.to_be_bytes());
    buf.extend_from_slice(&e.at.to_be_bytes());
    match &e.tenant {
        Some(t) => {
            buf.push(1);
            push_lp(&mut buf, t.as_bytes());
        }
        None => buf.push(0),
    }
    push_lp(&mut buf, e.action.as_bytes());
    push_lp(&mut buf, e.subject.as_bytes());
    buf.push(u8::from(e.allowed));
    push_lp(&mut buf, e.detail.as_bytes());
    sha256_parts(&[&b"SERS-AUDIT-v1\0"[..], &e.prev_hash[..], &buf[..]])
}

#[derive(Debug, Default)]
pub struct AuditLog {
    events: Vec<AuditEvent>,
}

impl AuditLog {
    pub fn append(
        &mut self,
        at: u64,
        tenant: Option<&TenantId>,
        action: &'static str,
        subject: String,
        allowed: bool,
        detail: &'static str,
    ) {
        let mut event = AuditEvent {
            seq: self.events.len() as u64,
            at,
            tenant: tenant.map(|t| t.as_str().to_owned()),
            action,
            subject,
            allowed,
            detail,
            prev_hash: self.events.last().map(|e| e.hash).unwrap_or([0u8; 32]),
            hash: [0u8; 32],
        };
        event.hash = compute_hash(&event);
        self.events.push(event);
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    pub fn verify_chain(&self) -> bool {
        let mut prev = [0u8; 32];
        for (i, e) in self.events.iter().enumerate() {
            if e.seq != i as u64 || e.prev_hash != prev || compute_hash(e) != e.hash {
                return false;
            }
            prev = e.hash;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_with_three() -> AuditLog {
        let mut log = AuditLog::default();
        let t = TenantId::new("acme").unwrap();
        log.append(1, Some(&t), "a", "s1".into(), true, "ok");
        log.append(2, None, "b", "s2".into(), false, "denied");
        log.append(3, Some(&t), "c", "s3".into(), true, "ok");
        log
    }

    #[test]
    fn untouched_chain_verifies() {
        assert!(log_with_three().verify_chain());
        assert!(AuditLog::default().verify_chain());
    }

    #[test]
    fn edited_event_is_detected() {
        let mut log = log_with_three();
        log.events[1].allowed = true;
        assert!(!log.verify_chain());
    }

    #[test]
    fn removed_event_is_detected() {
        let mut log = log_with_three();
        log.events.remove(1);
        assert!(!log.verify_chain());
    }

    #[test]
    fn reordered_events_are_detected() {
        let mut log = log_with_three();
        log.events.swap(0, 2);
        assert!(!log.verify_chain());
    }
}
