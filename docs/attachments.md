# Attachments

Attachments use Iroh Blobs for content transfer and Iroh Gossip for small, signed offers. Receiving an offer never downloads it automatically.

## Sharing and downloading

Share one regular file:

```sh
meshmsg --json share ./report.pdf
meshmsg download '<signed-offer>' --output ./received-report.pdf
```

Share a directory as a deterministic tar snapshot:

```sh
meshmsg --json share ./results
meshmsg download '<signed-directory-offer>' --output ./received-results
```

Copy the `offer` value from the `share` or `listen` JSON output. A raw Iroh `BlobTicket` is also accepted for interoperability, but is treated only as a file and has no meshmsg-signed name, kind, or declared size.

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

- Maximum file or archive blob: 1 GiB
- Maximum concurrent attachment operations per daemon: 2
- Transfer timeout: 1 hour
- Download progress event interval: each additional 8 MiB, plus completion

Before transferring missing content, the downloader verifies its size against the content hash, rejects oversized blobs, and compares the result with the size in a signed offer.

Blob data and named pins live under `blobs-v1/<node-public-key>` in the state directory. Successful outgoing shares use `meshmsg/out/v1/...` pins and successful downloads use `meshmsg/in/v1/...` pins. They survive daemon restarts and currently have no automatic expiry or removal command. Unpinned partial data can remain until store garbage collection.

## Security and compatibility

A signed offer authenticates the provider and advertised metadata. The BLAKE3 content hash verifies downloaded bytes. Neither provides confidentiality: offers are reusable capabilities to fetch plaintext from the named provider, and attachment content is not end-to-end encrypted.

New clients decode typed, versioned attachment payloads while continuing to accept existing signed text envelopes. Older compatible clients see attachment payloads as prefixed text and never download them automatically.

## JSON events

Representative records:

```json
{"type":"attachment_shared","schema_version":1,"from":"<peer-id>","offer_id":"<id>","kind":"file","name":"report.pdf","size":1234,"ticket":"<blob-ticket>","offer":"<signed-offer>","delivery_acknowledged":false}
{"type":"attachment_offer","schema_version":1,"from":"<peer-id>","timestamp_ms":1700000000000,"offer_id":"<id>","kind":"directory_tar_v1","name":"results.tar","size":4096,"ticket":"<blob-ticket>","offer":"<signed-offer>"}
{"type":"download_complete","schema_version":1,"offer_id":"<id>","kind":"file","name":"report.pdf","size":1234,"from":"<peer-id>","output":"./received-report.pdf"}
```
