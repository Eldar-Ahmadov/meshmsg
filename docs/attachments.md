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
meshmsg offers remove <offer-id> [--direction incoming|outgoing] [--provider <public-key>]
meshmsg offers prune [--older-than-secs <SECONDS>] [--direction incoming|outgoing] [--max-delete 512] [--dry-run]
```

This is a best-effort storage view. `outgoing` entries were durably pinned before this node attempted to publish their offers; `incoming` entries were successfully downloaded from a peer. Signed-offer tags retain the offered filename and kind. Raw tickets have no authenticated filename, so their permanent tag uses the stable name `raw-ticket.blob` and a deterministic ID derived from the provider and content hash; retries and destination changes therefore update one pin rather than accumulating random pins. The command also reports the offer ID, provider ID when available, content hash, format, local status, and known size. Tags do not retain signed offer tokens, timestamps, output paths, or offers that were seen but never downloaded.

Listing returns at most the first 512 valid tags in the blob store's ordered tag stream and performs at most 4,096 tag inspections. It uses one valid item of lookahead rather than calculating an exact total. JSON sets `"truncated":true` and `"has_more":true` when more valid entries were observed, the inspection bound was reached, or a per-item store error made completeness uncertain. `"item_errors"` reports the number of per-item store errors encountered; malformed meshmsg tags are ignored. Human output prints an explicit warning whenever the result is truncated or items could not be read. Only one listing runs at once; another fails immediately with `offers_busy`. The store API constructs its ordered range result internally before meshmsg consumes this bounded prefix, but listing runs outside the daemon event loop.

## Acceptance and overwrite behavior

Downloads are always explicit. The output path is required and must not exist. Its immediate parent must already exist and be a directory; meshmsg does not create output ancestors. This keeps durability precise: only that existing parent's namespace changes, and meshmsg syncs it after installation.

File installation uses a same-filesystem hard link from a synced staging file. Filesystems without hard-link support reject installation instead of falling back to an overwrite-prone move. Directory extraction occurs in a sibling staging directory; extracted files and directories are synced before the tree is renamed into place after validation. Concurrent destination creation is also rejected. Atomic no-replace directory installation is supported on Linux, Android, and Windows. Other compiled targets explicitly reject extracted-directory installation; use the raw tar export path instead. There is no replacement-capable rename fallback.

The durable inbound blob tag is written and synced **before** that final no-clobber installation. Therefore any ordinary `download_failed` response means meshmsg did not install the requested output, and retrying the same destination is safe (subject to another process creating it). An ordinary pre-install failure rolls back a newly created tag and retention reservation; a pre-existing deduplicated pin is untouched. If rollback itself is uncertain, meshmsg performs a bounded authoritative reconciliation and reports an unknown retryable outcome. An abrupt process exit after durable tag sync can conservatively leave the pin; startup reconciles and a retry reuses it.

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
- Default total retained unique-blob quota: 16 GiB
- Default minimum filesystem free-space reserve: 1 GiB
- Default automatic pin retention: disabled; when explicitly configured, checked hourly with at most 512 oldest eligible tags per pass
- Maximum tracked meshmsg attachment pins: 8,192 (also bounds zero-byte/deduplicated-tag metadata)
- Maximum concurrent attachment operations admitted per daemon: 2. Store mutation is serialized so quota, deduplication, transfer pins, removal, and prune cannot race. Excess or conflicting lifecycle work returns the strict retryable `attachment_storage_busy` error; an admitted second transfer can wait for the active storage transaction.
- Transfer timeout: 1 hour
- Download progress event interval: each additional 8 MiB, plus completion

Configure controls on each daemon invocation:

```sh
meshmsg daemon \
  --max-attachment-bytes 4294967296 \
  --max-attachment-storage-bytes 17179869184 \
  --min-attachment-free-bytes 1073741824 \
  --attachment-retention-secs 2592000
```

The corresponding environment variables are `MESHMSG_MAX_ATTACHMENT_BYTES`, `MESHMSG_MAX_ATTACHMENT_STORAGE_BYTES`, `MESHMSG_MIN_ATTACHMENT_FREE_BYTES`, and `MESHMSG_ATTACHMENT_RETENTION_SECS`. Per-blob and total quota values must be nonzero. Retention defaults to zero, so upgrades never begin deleting existing pins without explicit operator opt-in. A value of zero disables automatic pruning; manual prune remains available, and `--older-than-secs 0` selects all matching pins. The exact age boundary is inclusive. Selection is deterministic: creation time oldest first, then tag name, with a hard 512-tag command/pass limit. Use `--dry-run` to inspect counts and dedup-aware releasable bytes.

Status and daemon startup expose `attachment_retention_secs` and `attachment_storage`: unique tagged bytes/blob count, tag count/capacity, quota, filesystem available/minimum-free bytes, `sampled_at_ms`, and `pressure`, `over_quota`, and `below_min_free` booleans. Accounting is reconciled once during startup outside the daemon command loop, then maintained transactionally in a bounded cache; status is constant work and never scans tags or blobs. Every reserved-prefix tag must reference a complete raw blob: startup/reconciliation fails closed on missing or partial content instead of charging zero or a reported partial size. Pin commit rechecks authoritative completion and exact size before reservation, then updates tag/index/cache as one serialized transaction, so a partial-to-complete retry is charged immediately without waiting for restart. Free space is sampled off-loop after mutations and every 30 seconds. The web status allowlist exposes the same non-sensitive aggregate metrics. Existing stores already over quota remain readable and removable, but cannot add a new unique pin until usage recovers. A pin for content already referenced by another meshmsg tag adds zero quota bytes.

Before transferring missing content, the downloader verifies its size against the content hash, rejects blobs larger than the local daemon's configured limit, compares the result with the size in a signed offer, and reserves quota/free-space headroom. Lifecycle storage accepts only raw blobs; a meshmsg attachment tag or signed offer using `hash_seq` fails closed. Dedup identity is the complete `(hash, format)` pair, while foreign tags are neither counted nor deleted. Shares check free space before staging and again before import, then perform an exact hash/dedup quota check. Stable failures are `attachment_quota_exceeded` (`outcome:not_started`, non-retryable until pins are removed or configuration changes) and `attachment_min_free_space` (`outcome:not_started`, retryable after space recovery), and `attachment_tag_capacity` (`outcome:not_started`; prune/remove pins first). Conservative temporary/unpinned bytes can remain until Iroh store GC after a failed import or interrupted transfer, so the minimum-free check accounts for new data but status's tagged-byte metric intentionally reports durable meshmsg references rather than all store overhead.

Blob data and named pins live under `blobs-v1/<node-public-key>` in the state directory. On daemon startup, meshmsg removes only regular state-root share artifacts whose names exactly match `.meshmsg-part-<16 lowercase hex>.blob` or `.tar`; the owner-only state directory provides the validated cleanup scope. It does not follow links or remove similarly named directories or other suffixes. Download staging is beside an arbitrary caller-selected output, where ownership cannot be safely inferred, so startup never scans or deletes it. An abrupt process exit can leave `.meshmsg-part-<16 lowercase hex>.download`; directory extraction can leave a `.meshmsg-part-<16 lowercase hex>` sibling directory. If exit occurred after file installation, the `.download` file may be a second hard link to the valid destination. These precisely named leftovers require manual inspection/removal. Blob data and named pins remain safe and reusable.

Incoming content is named and synced before destination installation; after a crash or an ordinary pre-install failure, retrying repeats the same idempotent pin commit and can reuse the verified blob. Outgoing content is named and synced before its offer is broadcast, so an observed offer is already available. The share operation ID is reused as its offer ID and signed wire message ID. IPC also carries a lowercase SHA-256 source digest (domain-separated by file/directory kind), and the daemon binds both that digest and the exact submitted absolute path representation into the operation fingerprint. Thus changed bytes—even with the same name and size—and alternate path spellings conflict, while same-ID/same-path/same-content retries in the current daemon return the cached result without another import/publication. CLI relative paths are made absolute but are not filesystem-canonicalized, because canonicalization could follow a symlink that attachment validation must reject. An ordinarily returned pre-broadcast failure attempts to remove and sync the named pin. Forced task cancellation or process termination can interrupt publication or cleanup and may therefore leave a conservative pin even when no offer was sent. Once broadcast is attempted, an error has an unknown delivery outcome and the pin is deliberately retained so any peer that may have observed the offer can still fetch it. Successful outgoing shares use `meshmsg/out/v1/...` pins and successful downloads—including downloads prepared for the web UI—use `meshmsg/in/v1/...` pins. They survive daemon restarts until explicit or retention removal; expiry of a browser's temporary file does not itself release this persistent blob pin. Creation times live in the strict, versioned, atomically replaced `attachment-retention-v1.json`. A new pin uses an in-memory reservation, durable tag/database commit, and atomic index commit; every ordinary failure rolls the reservation and newly created tag back, with bounded authoritative reconciliation if rollback fails. Startup reconciles the index against authoritative blob tags: a tag committed just before a crash gets a conservative restart-time creation timestamp, and stale index entries disappear. Startup examines at most 16,385 reserved-prefix records, accepts at most 8,192 valid pins, rejects meshmsg `hash_seq` tags, and fails closed on oversized/malformed-prefix-populated stores; tags outside `meshmsg/` do not consume this scan or capacity.

`offers remove` deletes every meshmsg tag matching the offer ID and optional selectors; it is idempotent when no tags match. `offers prune` uses the configured age unless overridden. Removal deletes only selected meshmsg tags, syncs the blob database, then persists the reconciled retention index. Deduplicated data remains while any selected-out or non-meshmsg tag references it. `released_bytes` reports deduplicated meshmsg quota bytes released, so it is zero until the last meshmsg reference is removed; a non-meshmsg tag can still retain the physical data, and physical reclamation is asynchronous GC. Transfer and lifecycle operations share an exclusive storage gate: remove/prune returns versioned `attachment_storage_busy` without starting rather than racing an active local share/download. Removing a provider pin prevents future availability after GC. Before deleting any selected named pin, meshmsg acquires a bounded temporary store pin for each unique blob and marks it nonexpiring while tag deletion and database sync are in flight. Periodic status maintenance cannot remove in-flight guards. Only after that durability boundary completes does meshmsg start the full one-hour transfer-timeout grace; failed or uncertain deletion attempts receive the same conservative grace, while values whose deletion never started restore their prior guard state or drop a newly created guard. This closes both long-deletion and tag-deletion/GC races and protects an already started remote transfer even when GC runs immediately after removal. Per-tag, database-sync, or index failures produce `attachment_removal_partial` with partial/unknown outcome and retryable counts; retrying is safe. Abrupt exit is recovered from authoritative tags/index reconciliation. All attachment lifecycle errors use one strict schema-version-1 DTO with a stable `code`, bounded `message`, `outcome`, `retryable`, relevant operation/offer IDs, and partial removal/quota-release counts where applicable. CLI and HTTP attachment paths reject unknown fields, versions, codes, outcomes, or mismatched IDs rather than accepting arbitrary `type:error` values. Unpinned partial data can remain until store garbage collection.

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
