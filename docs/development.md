# Development

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked
bash tests/integration-5-peer.sh target/debug/meshmsg
bash tests/integration-attachments.sh target/debug/meshmsg
```

CI also runs dependency audit and policy checks.

## Releases

Pushing a version tag matching `Cargo.toml` builds:

- GNU Linux on an older Ubuntu baseline;
- portable Linux musl;
- native Windows x86-64.

The workflow packages the Windows binary with the README and both licenses, generates one `SHA256SUMS` file for all archives, and creates or updates the GitHub release. It does not run for ordinary commits.
