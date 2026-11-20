# ADR 0002: freshness comes from server-side challenge state

Status: accepted (implemented, NOT VERIFIED).

Client timestamps are attacker-controlled and clocks drift. The server issues a
random 256-bit nonce, stores the challenge, and consumes it atomically on the
first verification attempt, whether that attempt succeeds or fails. Replays
find nothing to consume. The challenge is bound to application, installation,
package digest and the client's ephemeral X25519 key, and the signature covers
all of them.

Consequences: the server is stateful (a PostgreSQL store must use
`DELETE ... RETURNING`); a stranger who learns a nonce can burn that
challenge, which only costs the legitimate client a retry (the nonce is only
sent to the requester over TLS); outstanding challenges are bounded per
process and only registered installations can request one.
