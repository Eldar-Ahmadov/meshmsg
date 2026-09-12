# meshmsg-protocol

The shared local IPC serialization boundary for the meshmsg daemon and clients.

## Contract

- `protocol_version: 2` is the only accepted version on every request, response, and event. There is no negotiation or fallback.
- Requests use `RequestFrame`; daemon responses and subscription records use the flattened `ResponseFrame` and `EventFrame` DTOs that match the bytes emitted on the socket.
- Request, operation, message, offer, peer, topic, and digest fields use distinct canonical ID types. Active message requests also use their bounded broadcast/private body types, and offer selectors use `OfferDirection`.
- Broadcast and private commands have distinct 3900-byte and 4096-byte UTF-8 body bounds.
- Attachment names use the same portable single-component restrictions as the runtime filesystem boundary.
- Frames are newline-delimited JSON with separate hard request and event/response limits. A buffered reader is poisoned by an oversized or incomplete frame so unread suffixes cannot be reinterpreted.

Diagnostic-status commands and responses are not part of protocol v2. Web and benchmark commands remain represented for now; their extraction is later scope.
