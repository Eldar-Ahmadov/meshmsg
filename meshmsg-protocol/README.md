# meshmsg-protocol

The shared local IPC serialization boundary for the meshmsg daemon and clients.

The crate has no Cargo features and does not depend on the Iroh networking stack:
it contains only DTOs, typed IDs, framing, and local IPC validation. Signed
attachment offers are opaque bounded tokens here; the daemon authenticates them.

## Contract

- `protocol_version: 5` is the only accepted version on every request, response, and event. There is no negotiation or fallback.
- Requests use `RequestFrame`; daemon responses and subscription records use the flattened `ResponseFrame` and `EventFrame` DTOs that match the bytes emitted on the socket. Response/event variants are selected only by their strict `type` tag; there is no per-family `schema_version`.
- Request, operation, message, offer, peer, topic, and digest fields use distinct canonical ID types. Active message requests also use their bounded broadcast/private body types, and offer selectors use `OfferDirection`.
- Protocol errors contain only frame version/correlation, optional typed operation ID, typed `ErrorCode`, and typed `Outcome`. Display text and retry guidance are adapter policy and are never sent over daemon IPC.
- Broadcast and private commands share a 65,358-byte UTF-8 body bound.
- Attachment names use the same portable single-component restrictions as the runtime filesystem boundary.
- Frames are newline-delimited JSON with checked worst-case request and event/response limits. Every serialized IPC path is absolute UTF-8 and at most 32,768 bytes. A buffered reader is poisoned by an oversized or incomplete frame so unread suffixes cannot be reinterpreted.

`status` is a typed protocol-v5 IPC request/response. Only `doctor` is a CLI-only diagnostic record and does not cross IPC. There is no built-in web UI or HTTP bridge.
