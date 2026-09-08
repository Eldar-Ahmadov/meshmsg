# Attachments

Attachments use Iroh Blobs for content transfer and Iroh Gossip for small, signed offers. Receiving an offer never downloads it automatically.

## Sharing and downloading

Share one regular file:

```sh
meshmsg --json share ./report.pdf
meshmsg download --offer-file ./signed-offer.txt --output ./received-report.pdf
```

Share a directory as a deterministic tar snapshot:

```sh
meshmsg --json share ./results
meshmsg download '<signed-directory-offer>' --output ./received-results
```

Copy the `offer` value from the `share` or `listen` JSON output. `--offer-file` and `--offer-stdin` avoid exposing this reusable plaintext capability in argv and shell history. A raw Iroh `BlobTicket` is also accepted for interoperability, but is treated only as a file and has no meshmsg-signed name, kind, or declared size.

List attachment blobs currently pinned in the local store:

```sh
meshmsg offers
meshmsg --json offers
```

This is a best-effort storage view. `outgoing` entries were durably pinned before this node attempted to publish their offers; `incoming` entries were successfully downloaded from a peer. Tags retain the offered filename and kind, and the command also reports the offer ID, provider ID when available, content hash, format, local status, and known size. Tags do not retain signed offer tokens, timestamps, output paths, or offers that were seen but never downloaded.

Listing returns at most the first 512 valid tags in the blob store's ordered tag stream and performs at most 4,096 tag inspections. It uses one valid item of lookahead rather than calculating an exact total. JSON sets `"truncated":true` and `"has_more":true` when more valid entries were observed, the inspection bound was reached, or a per-item store error made completeness uncertain. `"item_errors"` reports the number of per-item store errors encountered; malformed meshmsg tags are ignored. Human output prints an explicit warning whenever the result is truncated or items could not be read. Only one listing runs at once; another fails immediately with `offers_busy`. The store API constructs its ordered range result internally before meshmsg consumes this bounded prefix, but listing runs outside the daemon event loop.

## Acceptance and overwrite behavior

Downloads are always explicit. The output path is required and must not exist.

File installation uses a same-filesystem hard link from a staging file. Filesystems without hard-link support reject installation instead of falling back to an overwrite-prone move. Directory extraction occurs in a sibling staging directory and is renamed into place only after validation succeeds. Concurrent destination creation is also rejected.

## Directory snapshots

Directory offers use `directory_tar_v1`. Archive order, metadata, and modes are normalized for reproducible snapshots.

Sharing rejects:

- symbolic links and special files;
- non-UTF-8 or non-portable path components;
- more than 10,000 entries;
- paths deeper than 64 components;
- oversized paths or archives;
- files changed incompatibly while being read.

Extraction accepts only regular files and directories. It rejects absolute or traversal paths, links, special entries, duplicates, case collisions, and file/directory collisions.

Regular source files are opened without following links. A directory share is a snapshot operation, but not a transactional filesystem snapshot; concurrent source mutation can make it fail.

## Limits and persistence

- Default maximum file or archive blob: 4 GiB
- Maximum concurrent attachment operations per daemon: 2; excess shares fail with `share_busy` and excess downloads fail with `download_busy` before a task or `download_started` event is created
- Transfer timeout: 1 hour
- Download progress event interval: each additional 8 MiB, plus completion

Configure the per-daemon attachment limit with `meshmsg daemon --max-attachment-bytes <BYTES>` or the `MESHMSG_MAX_ATTACHMENT_BYTES` environment variable. The value must be greater than zero and applies to both shares and downloads. The daemon's JSON startup and status records expose the active value as `max_attachment_bytes`.

Before transferring missing content, the downloader verifies its size against the content hash, rejects blobs larger than the local daemon's configured limit, and compares the result with the size in a signed offer.

Blob data and named pins live under `blobs-v1/<node-public-key>` in the state directory. Outgoing content is named and synced before its offer is broadcast, so an observed offer is already available. An ordinarily returned pre-broadcast failure attempts to remove and sync the named pin. Forced task cancellation or process termination can interrupt publication or cleanup and may therefore leave a conservative pin even when no offer was sent. Once broadcast is attempted, an error has an unknown delivery outcome and the pin is deliberately retained so any peer that may have observed the offer can still fetch it. Successful outgoing shares use `meshmsg/out/v1/...` pins and successful downloads—including downloads prepared for the web UI—use `meshmsg/in/v1/...` pins. They survive daemon restarts and currently have no automatic expiry or removal command; expiry of a browser's temporary file does not release this persistent blob pin. Unpinned partial data can remain until store garbage collection.

## Security and compatibility

A signed offer authenticates the provider and advertised metadata. The BLAKE3 content hash verifies downloaded bytes. Neither provides confidentiality: offers are reusable capabilities to fetch plaintext from the named provider, and attachment content is not end-to-end encrypted.

Attachment offers use the topic-bound broadcast envelope V2. Raw Iroh `BlobTicket` values remain accepted as described above. Legacy meshmsg signed-envelope tokens are rejected explicitly because their signatures do not bind a topic; they are never silently treated as trusted V2 offers. Ask the provider to share the attachment again with a V2 daemon. V2 daemons use `/meshmsg/broadcast-gossip/2`, so pre-V2 peers neither receive nor inject V2 attachment offers.

## JSON events

The optional web UI shows live-only cards for incoming and locally shared attachments. Incoming cards can explicitly download the verified content to the browser; directory snapshots download as their deterministic `.tar` archive. The bridge retains signed offers only in bounded, expiring server memory and gives the browser opaque IDs that can be retried during their short TTL, never raw offers, blob tickets, or server filesystem paths. Ready temporary files likewise remain retryable/resumable for 65 minutes after readiness or their latest retrieval; a user must click the displayed **Save file** link after preparation. The composer can upload and share one browser-selected regular file at a time. The bridge streams it into an owner-only, size-bounded staging path, asks the daemon to use its normal verified share operation, and removes the staging file after a definite response. The live daemon event—not the upload response—creates the outgoing card. Directory selection, offers/history, and arbitrary attachment mutation remain unavailable.

Representative records:

```json
{"type":"attachment_shared","schema_version":2,"from":"<peer-id>","message_id":"<32-hex-digits>","timestamp_ms":1700000000000,"offer_id":"<id>","kind":"file","name":"report.pdf","size":1234,"ticket":"<blob-ticket>","offer":"<signed-offer>","delivery_acknowledged":false}
{"type":"attachment_offer","schema_version":2,"from":"<peer-id>","message_id":"<32-hex-digits>","timestamp_ms":1700000000000,"offer_id":"<id>","kind":"directory_tar_v1","name":"results.tar","size":4096,"ticket":"<blob-ticket>","offer":"<signed-offer>"}
{"type":"download_complete","schema_version":1,"offer_id":"<id>","kind":"file","name":"report.pdf","size":1234,"from":"<peer-id>","output":"./received-report.pdf"}
```
