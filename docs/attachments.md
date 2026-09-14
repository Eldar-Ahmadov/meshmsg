# Attachments

Attachments use Iroh Blobs for content transfer and Iroh Gossip for small, signed offers. Receiving an offer never downloads it automatically.

## Sharing and downloading

Share one regular file (the CLI converts both source and output paths to the absolute lexical paths required by the [IPC contract](contracts.md#ipc)):

```sh
meshmsg --json share --operation-id 0123456789abcdef0123456789abcdef ./report.pdf
meshmsg download --operation-id fedcba9876543210fedcba9876543210 --offer-file ./signed-offer.txt --output ./received-report.pdf
```

Share a directory as a deterministic tar snapshot:

```sh
meshmsg --json share ./results
meshmsg download '<signed-directory-offer>' --output ./received-results
```

Copy the `offer` value from the `share` or `listen` JSON output. Signed offers bind the message/offer identity, canonical raw ticket, provider, content hash/format, name, kind, size, timestamp, and topic. The full relationships are revalidated at wire, IPC, saved-token, and generated-event boundaries; malformed offers are rejected before admission, fanout, transfer work, or pin creation. Persistent tags retain only the fields they need and cannot revalidate a discarded signed envelope. Live-event freshness, saved-token validation, identity, and exact token bounds are normative in the [IPC contract](contracts.md#ipc). `--offer-file` and `--offer-stdin` avoid exposing this reusable plaintext capability in argv and shell history. A raw Iroh `BlobTicket` is also accepted for interoperability, but is treated only as a file and has no meshmsg-signed name, kind, or declared size.

List attachment blobs currently pinned in the local store:

```sh
meshmsg offers
meshmsg --json offers
meshmsg offers remove [--operation-id <32-lowercase-hex>] <offer-id> [--direction incoming|outgoing] [--provider <public-key>]
meshmsg offers prune [--operation-id <32-lowercase-hex>] [--older-than-secs <SECONDS>] [--direction incoming|outgoing] [--max-delete <COUNT>] [--dry-run]
```

This is a best-effort storage view. `outgoing` entries were durably pinned before this node attempted to publish their offers; `incoming` entries were successfully downloaded from a peer. Signed-offer tags retain the offered filename and kind. Raw tickets have no authenticated filename, so their permanent tag uses the stable name `raw-ticket.blob` and a deterministic ID derived from the provider and content hash; retries and destination changes therefore update one pin rather than accumulating random pins. The command also reports the offer ID, provider ID when available, content hash, format, local status, and known size. Tags do not retain signed offer tokens, timestamps, output paths, or offers that were seen but never downloaded.

Listing is a bounded prefix rather than pagination. The exact entry/inspection limits and [`truncated`/`item_errors` semantics](contracts.md#offer-listing) are centralized in the contract. In particular, malformed reserved meshmsg tags are omitted **and counted in `item_errors`**; they are not silently ignored. Human output warns whenever the result is truncated or items could not be read. Only one listing runs at once; another fails immediately with `offers_busy` and `outcome:not_started`. Listing is not a mutation and does not enter the operation cache. Wait for an active listing to finish, then retry the same request. The store API constructs its ordered range result internally before meshmsg consumes this bounded prefix, but listing runs outside the daemon event loop.

## Acceptance and overwrite behavior

Downloads are always explicit. `--output` is required; IPC receives an **absolute UTF-8 output path**, and the destination must not exist. Its immediate parent must already exist and be a directory; meshmsg does not create output ancestors. This keeps durability precise: only that existing parent's namespace changes, and meshmsg syncs it after installation. The CLI makes a relative argument absolute without filesystem canonicalization. Exact lexical path matching and progress invariants are defined in the [IPC contract](contracts.md#ipc).

File installation uses a same-filesystem hard link from a synced staging file. Filesystems without hard-link support reject installation instead of falling back to an overwrite-prone move. Directory extraction occurs in a sibling staging directory; extracted files and directories are synced before the tree is renamed into place after validation. Concurrent destination creation is also rejected. Atomic no-replace directory installation is supported on Linux, Android, and Windows. Other compiled targets explicitly reject directory attachment installation because meshmsg has no safe no-replace implementation there. File attachments remain supported when the filesystem permits hard links. There is no raw-export mode or replacement-capable rename fallback.

All remove, prune, and download requests carry a reusable operation ID distinct from their per-attempt request IDs and from the selected offer ID. Download supports only installation. Exact operation fingerprints join in-flight duplicates and replay terminal results without repeating work; changed inputs conflict before storage or network work. Prune cutoff ownership and remove/prune DTOs—including canonical v4 examples and selection bounds—are defined in the [Lifecycle contract](contracts.md#lifecycle-contract). Follow the contract's retry advice: an identical ID reconciles an uncertain operation, while a cached condition-dependent `not_started` result needs a new ID after the condition changes.

The durable inbound blob tag is written and synced **before** that final no-clobber installation. Therefore any ordinary `download_failed` response means meshmsg did not install the requested output. That not-started result remains cached under its operation ID; after its cause changes, retrying the same destination is safe only as a new operation with a new ID (subject to another process creating it). An ordinary pre-install failure rolls back a newly created tag and retention reservation; a pre-existing deduplicated pin is untouched. If rollback itself is uncertain, meshmsg performs a bounded authoritative reconciliation and reports an unknown outcome, for which callers reconcile or use only the same operation ID. An abrupt process exit after durable tag sync can conservatively leave the pin; startup reconciles and an exact same-operation retry reuses it.

After the atomic installation, meshmsg separately syncs the installed content and the existing immediate parent, then removes the staging name. Those operations necessarily occur after the output exists. Their failure is reported as `download_complete`, never `download_failed`, with `installed:true`, `pinned:true`, the relevant `destination_synced:false` or `cleanup_complete:false`, and a nonempty `warnings` array. The output is verified and installed in this partial-success case. An exact retry
within the daemon's cache lifetime replays that same `download_complete` without
network, export, or installation work. After cache expiry, eviction, or daemon
restart, no-clobber rejects the existing path; callers must reconcile it rather than
choose the same operation ID and assume durable replay. `destination_synced:false` means durability across an immediate operating-system crash could not be confirmed. `cleanup_complete:false` means a hidden sibling staging name may remain; the destination remains valid and the in-process guard makes one final best-effort cleanup attempt.

## Directory snapshots

Directory offers use `directory_tar_v1`. Archive order, metadata, and modes are normalized for reproducible snapshots.

Sharing rejects:

- symbolic links and special files;
- non-UTF-8 or non-portable path components;
- archive entry-count or path-depth bounds from the canonical [attachment limits table](contracts.md#attachment-limits-and-defaults);
- oversized paths or archives;
- files changed incompatibly while being read.

Extraction accepts only regular files and directories. It rejects absolute or traversal paths, links, special entries, duplicates, case collisions, and file/directory collisions.

Regular source files are opened without following links. A directory share is a snapshot operation, but not a transactional filesystem snapshot; concurrent source mutation can make it fail.

## Configuration and persistence

Exact blob/quota/free-space defaults, retention cadence, pin and operation capacities, lifecycle bounds, transfer timing, progress cadence, and archive bounds live only in the canonical [attachment limits and defaults table](contracts.md#attachment-limits-and-defaults). Store mutation is serialized so quota, deduplication, transfer pins, removal, and prune cannot race. Excess or conflicting lifecycle work returns `attachment_storage_busy` with `outcome:not_started`; wait for storage availability, then use a new operation ID because the old result remains cached.

Configure controls on each daemon invocation:

```sh
meshmsg daemon \
  --max-attachment-bytes "$MAX_BLOB_BYTES" \
  --max-attachment-storage-bytes "$MAX_STORAGE_BYTES" \
  --min-attachment-free-bytes "$MIN_FREE_BYTES" \
  --attachment-retention-secs "$RETENTION_SECONDS"
```

The corresponding environment variables are `MESHMSG_MAX_ATTACHMENT_BYTES`, `MESHMSG_MAX_ATTACHMENT_STORAGE_BYTES`, `MESHMSG_MIN_ATTACHMENT_FREE_BYTES`, and `MESHMSG_ATTACHMENT_RETENTION_SECS`. Per-blob and total quota values must be nonzero. Automatic pruning is opt-in; manual prune remains available, and `--older-than-secs 0` selects all matching pins through the daemon's admission time. The exact age boundary is inclusive. Saturating arithmetic makes every `u64` age valid; very large ages resolve to cutoff zero. Because the boundary is resolved once after admission, command-queue delay and later clock changes do not alter it. Selection is deterministic by creation time and then tag name, within the canonical lifecycle bound. `--max-delete` is a per-operation bound: a lost response retried with the same ID replays the original selected set/result. Use `--dry-run` to inspect counts and dedup-aware releasable bytes. Exact cache retention is defined in [Operation retries and cache](contracts.md#operation-retries-and-cache).

The canonical `meshmsg status` command and protocol-v4 status IPC response expose `attachment_retention_secs` and `attachment_storage`: unique tagged bytes/blob count, tag count/capacity, quota, filesystem available/minimum-free bytes, `sampled_at_ms`, and `pressure`, `over_quota`, and `below_min_free` booleans. Accounting is reconciled once during daemon startup outside the command loop, then maintained transactionally in a bounded cache; status is constant work and never scans tags or blobs. Every reserved-prefix tag must reference a complete raw blob: startup/reconciliation fails closed on missing or partial content instead of charging zero or a reported partial size. Pin commit rechecks authoritative completion and exact size before reservation, then updates tag/index/cache as one serialized transaction, so a partial-to-complete retry is charged immediately without waiting for restart. Free space is sampled off-loop after mutations and at the interval in the canonical attachment limits table. Existing stores already over quota remain readable and removable, but cannot add a new unique pin until usage recovers. A pin for content already referenced by another meshmsg tag adds zero quota bytes.

Before transferring missing content, the downloader verifies its size against the content hash, rejects blobs larger than the local daemon's configured limit, compares the result with the size in a signed offer, and reserves quota/free-space headroom. Lifecycle storage accepts only raw blobs; a meshmsg attachment tag or signed offer using `hash_seq` fails closed. Dedup identity is the complete `(hash, format)` pair, while foreign tags are neither counted nor deleted. Shares check free space before staging and again before import, then perform an exact hash/dedup quota check. Stable admitted failures are `attachment_quota_exceeded` (`outcome:not_started`; change pins or configuration, then use a new operation ID), `attachment_min_free_space` (`outcome:not_started`; after space recovery use a new operation ID), and `attachment_tag_capacity` (`outcome:not_started`; prune/remove pins, then use a new operation ID). Conservative temporary/unpinned bytes can remain until Iroh store GC after a failed import or interrupted transfer, so the minimum-free check accounts for new data but status's tagged-byte metric intentionally reports durable meshmsg references rather than all store overhead.

Blob data and named pins live under `blobs-v1/<node-public-key>` in the state directory. On daemon startup, meshmsg removes only regular state-root share artifacts whose names exactly match `.meshmsg-part-<16 lowercase hex>.blob` or `.tar`; the owner-only state directory provides the validated cleanup scope. It does not follow links or remove similarly named directories or other suffixes. Download staging is beside an arbitrary caller-selected output, where ownership cannot be safely inferred, so startup never scans or deletes it. An abrupt process exit can leave `.meshmsg-part-<16 lowercase hex>.download`; directory extraction can leave a `.meshmsg-part-<16 lowercase hex>` sibling directory. If exit occurred after file installation, the `.download` file may be a second hard link to the valid destination. These precisely named leftovers require manual inspection/removal. Blob data and named pins remain safe and reusable.

Incoming content is named and synced before destination installation; after a crash or an ordinary pre-install failure, retrying repeats the same idempotent pin commit and can reuse the verified blob. Outgoing content is named and synced before its offer is broadcast, so an observed offer is already available. The share operation ID is reused as its offer ID and signed wire message ID. IPC also carries a lowercase SHA-256 source digest (domain-separated by file/directory kind), and the daemon binds both that digest and the exact submitted absolute path representation into the operation fingerprint. Thus changed bytes—even with the same name and size—and alternate path spellings conflict, while same-ID/same-path/same-content retries in the current daemon return the cached result without another import/publication. CLI relative paths are made absolute but are not filesystem-canonicalized, because canonicalization could follow a symlink that attachment validation must reject. An ordinarily returned pre-broadcast failure attempts to remove and sync the named pin. Forced task cancellation or process termination can interrupt publication or cleanup and may therefore leave a conservative pin even when no offer was sent. Once broadcast is attempted, an error has an unknown delivery outcome and the pin is deliberately retained so any peer that may have observed the offer can still fetch it. Successful outgoing shares use `meshmsg/out/v1/...` pins and successful downloads use `meshmsg/in/v1/...` pins. They survive daemon restarts until explicit or retention removal. Creation times live in the strict, versioned, atomically replaced `attachment-retention-v1.json`. A new pin uses an in-memory reservation, durable tag/database commit, and atomic index commit; every ordinary failure rolls the reservation and newly created tag back, with bounded authoritative reconciliation if rollback fails. Startup reconciles a valid current index against authoritative blob tags: a tag committed just before its index entry gets a conservative restart-time creation timestamp, and stale index entries disappear. A missing index initializes empty only when the store has no managed attachment pins; existing managed pins without the index fail startup with restoration/removal guidance rather than receiving reconstructed timestamps. Startup examines and accepts records only within the canonical scan and pin bounds, requires incoming provider keys to use their canonical lowercase round-trip encoding, rejects meshmsg `hash_seq` tags, and fails closed on oversized/malformed-prefix-populated stores; tags outside `meshmsg/` do not consume this scan or capacity.

`offers remove` deletes every meshmsg tag matching the offer ID and optional selectors; it is idempotent when no tags match. `offers prune` uses the configured age unless overridden. Removal deletes only selected meshmsg tags, syncs the blob database, then persists the reconciled retention index. Deduplicated data remains while any selected-out or non-meshmsg tag references it. `released_bytes` reports deduplicated meshmsg quota bytes released, so it is zero until the last meshmsg reference is removed; a non-meshmsg tag can still retain the physical data, and physical reclamation is asynchronous GC. Transfer and lifecycle operations share an exclusive storage gate: remove/prune returns versioned `attachment_storage_busy` without starting rather than racing an active local share/download. Removing a provider pin prevents future availability after GC. Before deleting any selected named pin, meshmsg acquires a bounded temporary store pin for each unique blob and marks it nonexpiring while tag deletion and database sync are in flight. Periodic status maintenance cannot remove in-flight guards. Only after that durability boundary completes does meshmsg start the canonical transfer-timeout grace; failed or uncertain deletion attempts receive the same conservative grace, while values whose deletion never started restore their prior guard state or drop a newly created guard. This closes both long-deletion and tag-deletion/GC races and protects an already started remote transfer even when GC runs immediately after removal. Per-tag, database-sync, or index failures produce compact `attachment_removal_partial` errors with a partial/unknown outcome; retry guidance is derived by clients. Abrupt exit is recovered from authoritative tags/index reconciliation. All attachment errors use the strict protocol-v4 error boundary with typed code, outcome, request ID, and operation ID. Partial removal/quota counts are not repeated in errors; lifecycle counts remain in typed success variants. Remove/prune lifecycle and download success/progress records all use the canonical protocol-v4 frame and retain the operation ID. CLI attachment paths reject unknown fields, versions, codes, outcomes, or mismatched IDs rather than accepting arbitrary `type:error` values. Unpinned partial data can remain until store garbage collection.

## Security and compatibility

A signed offer authenticates the provider and advertised metadata. The BLAKE3 content hash verifies downloaded bytes. Neither provides confidentiality: offers are reusable capabilities to fetch plaintext from the named provider, and attachment content is not end-to-end encrypted.

Attachment offers use the topic-bound broadcast envelope V3. Only the current signed shape is decoded; V2 and malformed signed tokens fail closed. Envelope/token limits and compatibility are centralized in the [authoritative contract](contracts.md#compatibility-and-migration). Raw Iroh `BlobTicket` values remain accepted as described above.

## JSON events

Attachment responses and events use the canonical protocol-v4 frames listed in [Stable JSON and IPC contracts](contracts.md#ipc), including the [remove and prune lifecycle examples](contracts.md#lifecycle-contract). Every download request and progress/completion record carries the required absolute output path; clients reject a response whose path differs from the exact submitted representation.
