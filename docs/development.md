# Development

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked
node --check src/web/app.js
node tests/web-ui.cjs
python3 tests/integration-cli-errors.py target/debug/meshmsg
python3 tests/integration-web.py target/debug/meshmsg
python3 tests/integration-web-peer.py target/debug/meshmsg
python3 tests/integration-peer-directory.py target/debug/meshmsg
bash tests/integration-ipc-version-compat.sh target/debug/meshmsg
bash tests/integration-5-peer.sh target/debug/meshmsg
bash tests/integration-attachments.sh target/debug/meshmsg
bash tests/integration-direct-messages.sh target/debug/meshmsg
```

The fake-daemon CLI regression and web HTTP harness require Unix sockets and run in Linux CI. Every push and pull request also runs the full Rust test suite, Clippy, and a debug build natively on Windows Server 2022; platform-gated tests exercise named-pipe ownership, cancellation-safe accept, the shared 64-client admission path, initial-frame timeout recovery, and shutdown drain/abort. The peer-directory, IPC-version compatibility, real-peer web, and direct-message harnesses require working Iroh networking. The Node UI checks use a DOM mock, not a mobile browser. Neither harness changes Tailscale configuration. See [web validation limits](web.md#tests-and-validation-limits).

CI also runs dependency audit and policy checks.

## Releases

Pushing a version tag matching `Cargo.toml` builds:

- GNU Linux on an older Ubuntu baseline;
- portable Linux musl;
- native Windows x86-64.

The workflow packages the Windows binary with the README and both licenses, generates one `SHA256SUMS` file for all archives, and creates or updates the GitHub release. It does not run for ordinary commits.
