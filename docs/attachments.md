# Attachments

Attachments use Iroh Blobs for content transfer and Iroh Gossip for small, signed offers. Receiving an offer never downloads it automatically.

## Sharing and downloading

Share one regular file:

```sh
meshmsg --json share --operation-id 0123456789abcdef0123456789abcdef ./report.pdf
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

This is a best-effort storage view. `outgoing` entries were durably pinned before this node attempted to publish their offers; `incoming` entries were successfully downloaded from a peer. Signed-offer tags retain the offered filename and kind. Raw tickets have no authenticated filename, so their permanent tag uses the stable name `raw-ticket.blob` and a deterministic ID derived from the provider and content hash; retries and destination changes therefore update one pin rather than accumulating random pins. The command also reports the offer ID, provider ID when available, content hash, format, local status, and known size. Tags do not retain signed offer tokens, timestamps, output paths, or offers that were seen but never downloaded.

Listing returns at most the first 512 valid tags in the blob store's ordered tag stream and performs at most 4,096 tag inspections. It uses one valid item of lookahead rather than calculating an exact total. JSON sets `"truncated":true` and `"has_more":true` when more valid entries were observed, the inspection bound was reached, or a per-item store error made completeness uncertain. `"item_errors"` reports the number of per-item store errors encountered; malformed meshmsg tags are ignored. Human output prints an explicit warning whenever the result is truncated or items could not be read. Only one listing runs at once; another fails immediately with `offers_busy`. The store API constructs its ordered range result internally before meshmsg consumes this bounded prefix, but listing runs outside the daemon event loop.

## Acceptance and overwrite behavior

Downloads are always explicit. The output path is required and must not exist. Its immediate parent must already exist and be a directory; meshmsg does not create output ancestors. This keeps durability precise: only that existing parent's namespace changes, and meshmsg syncs it after installation.

File installation uses a same-filesystem hard link from a synced staging file. Filesystems without hard-link support reject installation instead of falling back to an overwrite-prone move. Directory extraction occurs in a sibling staging directory; extracted files and directories are synced before the tree is renamed into place after validation. Concurrent destination creation is also rejected. Atomic no-replace directory installation is supported on Linux, Android, and Windows. Other compiled targets explicitly reject extracted-directory installation; use the raw tar export path instead. There is no replacement-capable rename fallback.

The durable inbound blob tag is written and synced **before** that final no-clobber installation. Therefore any ordinary `download_failed` response means meshmsg did not install the requested output, and retrying the same destination is safe (subject to another process creating it). A failed pre-install attempt may conservatively leave the idempotent blob pin; a retry reuses it.

After the atomic installation, meshmsg separately syncs the installed content and the existing immediate parent, then removes the staging name. Those operations necessarily occur after the output exists. Their failure is reported as `download_complete`, never `download_failed`, with `installed:true`, `pinned:true`, the relevant `destination_synced:false` or `cleanup_complete:false`, and a nonempty `warnings` array. The output is verified and installed in this partial-success case, so callers must not retry it at the same path. `destination_synced:false` means durability across an immediate operating-system crash could not be confirmed. `cleanup_complete:false` means a hidden sibling staging name may remain; the destination remains valid and the in-process guard makes one final best-effort cleanup attempt.

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

Blob data and named pins live under `blobs-v1/<node-public-key>` in the state directory. On daemon startup, meshmsg removes only regular state-root share artifacts whose names exactly match `.meshmsg-part-<16 lowercase hex>.blob` or `.tar`; the owner-only state directory provides the validated cleanup scope. It does not follow links or remove similarly named directories or other suffixes. Download staging is beside an arbitrary caller-selected output, where ownership cannot be safely inferred, so startup never scans or deletes it. An abrupt process exit can leave `.meshmsg-part-<16 lowercase hex>.download`; directory extraction can leave a `.meshmsg-part-<16 lowercase hex>` sibling directory. If exit occurred after file installation, the `.download` file may be a second hard link to the valid destination. These precisely named leftovers require manual inspection/removal. Blob data and named pins remain safe and reusable.

Incoming content is named and synced before destination installation; after a crash or an ordinary pre-install failure, retrying repeats the same idempotent pin commit and can reuse the verified blob. Outgoing content is named and synced before its offer is broadcast, so an observed offer is already available. The share operation ID is reused as its offer ID and signed wire message ID. IPC also carries a lowercase SHA-256 source digest (domain-separated by file/directory kind), and the daemon binds both that digest and the exact submitted absolute path representation into the operation fingerprint. Thus changed bytes—even with the same name and size—and alternate path spellings conflict, while same-ID/same-path/same-content retries in the current daemon return the cached result without another import/publication. CLI relative paths are made absolute but are not filesystem-canonicalized, because canonicalization could follow a symlink that attachment validation must reject. An ordinarily returned pre-broadcast failure attempts to remove and sync the named pin. Forced task cancellation or process termination can interrupt publication or cleanup and may therefore leave a conservative pin even when no offer was sent. Once broadcast is attempted, an error has an unknown delivery outcome and the pin is deliberately retained so any peer that may have observed the offer can still fetch it. Successful outgoing shares use `meshmsg/out/v1/...` pins and successful downloads—including downloads prepared for the web UI—use `meshmsg/in/v1/...` pins. They survive daemon restarts and currently have no automatic expiry or removal command; expiry of a browser's temporary file does not release this persistent blob pin. Unpinned partial data can remain until store garbage collection.

## Security and compatibility

A signed offer authenticates the provider and advertised metadata. The BLAKE3 content hash verifies downloaded bytes. Neither provides confidentiality: offers are reusable capabilities to fetch plaintext from the named provider, and attachment content is not end-to-end encrypted.

Attachment offers use the topic-bound broadcast envelope V2. Raw Iroh `BlobTicket` values remain accepted as described above. Legacy meshmsg signed-envelope tokens are rejected explicitly because their signatures do not bind a topic; they are never silently treated as trusted V2 offers. Ask the provider to share the attachment again with a V2 daemon. V2 daemons use `/meshmsg/broadcast-gossip/2`, so pre-V2 peers neither receive nor inject V2 attachment offers.

## JSON events

The optional web UI shows live-only cards for incoming and locally shared attachments. Incoming cards can explicitly download the verified content to the browser; directory snapshots download as their deterministic `.tar` archive. The bridge retains signed offers only in bounded, expiring server memory and gives the browser opaque IDs that can be retried during their short TTL, never raw offers, blob tickets, or server filesystem paths. Ready temporary files likewise remain retryable/resumable for 65 minutes after readiness or their latest retrieval; a user must click the displayed **Save file** link after preparation. The composer can upload and share one browser-selected regular file at a time. The bridge streams it into an owner-only, size-bounded staging path, asks the daemon to use its normal verified share operation, and removes the staging file after a definite response. The live daemon event—not the upload response—creates the outgoing card. Directory selection, offers/history, and arbitrary attachment mutation remain unavailable.

Representative records:

```json
{"type":"attachment_shared","schema_version":3,"operation_id":"<32-lowercase-hex>","from":"<peer-id>","message_id":"<same-operation-id>","timestamp_ms":1700000000000,"offer_id":"<same-operation-id>","source_digest":"<64-lowercase-hex>","kind":"file","name":"report.pdf","size":1234,"ticket":"<blob-ticket>","offer":"<signed-offer>","delivery_acknowledged":false}
{"type":"attachment_offer","schema_version":2,"from":"<peer-id>","message_id":"<32-hex-digits>","timestamp_ms":1700000000000,"offer_id":"<id>","kind":"directory_tar_v1","name":"results.tar","size":4096,"ticket":"<blob-ticket>","offer":"<signed-offer>"}
{"type":"download_complete","schema_version":1,"offer_id":"<id>","kind":"file","name":"report.pdf","size":1234,"from":"<peer-id>","output":"./received-report.pdf","installed":true,"pinned":true,"destination_synced":true,"cleanup_complete":true,"warnings":[]}
```
