#![no_main]
//! Every wire message type, decoded from arbitrary bytes.

use libfuzzer_sys::fuzz_target;
use sers_protocol::{
    decode, Challenge, ChallengeRequest, ChallengeResponse, RegistrationRequest,
    SignedAuthorization,
};

fuzz_target!(|data: &[u8]| {
    let _ = decode::<RegistrationRequest>(data);
    let _ = decode::<ChallengeRequest>(data);
    let _ = decode::<Challenge>(data);
    let _ = decode::<ChallengeResponse>(data);
    let _ = decode::<SignedAuthorization>(data);
});
