# meshmsg-protocol

The shared local IPC serialization boundary for the meshmsg daemon and clients.

## Cargo features

The crate has no default features. Its DTOs, typed IDs, framing, and local IPC
validation therefore do not compile the Iroh networking stack.

Enable `attachment-authenticity` to expose `validate_attachment_event` and its
supporting API. That feature adds Iroh, Iroh Blobs, and Iroh Gossip in order to
verify signed attachment envelopes, topics, and blob tickets. It does not alter
wire formats when enabled. The main `meshmsg` crate enables this feature
explicitly; the daemon never substitutes lightweight validation or an insecure
fallback when authenticity support is unavailable.

## Contract

- `protocol_version: 4` is the only accepted version on every request, response, and event. There is no negotiation or fallback.
- Requests use `RequestFrame`; daemon responses and subscription records use the flattened `ResponseFrame` and `EventFrame` DTOs that match the bytes emitted on the socket. Response/event variants are selected only by their strict `type` tag; there is no per-family `schema_version`.
- Request, operation, message, offer, peer, topic, and digest fields use distinct canonical ID types. Active message requests also use their bounded broadcast/private body types, and offer selectors use `OfferDirection`.
- Protocol errors contain only frame version/correlation, optional typed operation ID, typed `ErrorCode`, and typed `Outcome`. Display text and retry guidance are adapter policy and are never sent over daemon IPC.
- Broadcast and private commands have distinct 65,358-byte and 4,096-byte UTF-8 body bounds.
- Attachment names use the same portable single-component restrictions as the runtime filesystem boundary.
- Frames are newline-delimited JSON with checked worst-case request and event/response limits. Every serialized IPC path is absolute UTF-8 and at most 32,768 bytes. A buffered reader is poisoned by an oversized or incomplete frame so unread suffixes cannot be reinterpreted.

`status` is a typed protocol-v4 IPC request/response. Only `doctor` is a CLI-only diagnostic record and does not cross IPC. There is no built-in web UI or HTTP bridge.
