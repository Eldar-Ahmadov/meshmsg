# Development

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked
node --check src/web/app.js
node tests/web-ui.cjs
python3 tests/integration-web.py target/debug/meshmsg
python3 tests/integration-web-peer.py target/debug/meshmsg
bash tests/integration-5-peer.sh target/debug/meshmsg
bash tests/integration-attachments.sh target/debug/meshmsg
```

The web HTTP harness requires Unix sockets; the real-peer web harness requires working Iroh networking. The Node UI checks use a DOM mock, not a mobile browser. Neither harness changes Tailscale configuration. See [web validation limits](web.md#tests-and-validation-limits).

CI also runs dependency audit and policy checks.

## Releases

Pushing a version tag matching `Cargo.toml` builds:

- GNU Linux on an older Ubuntu baseline;
- portable Linux musl;
- native Windows x86-64.

The workflow packages the Windows binary with the README and both licenses, generates one `SHA256SUMS` file for all archives, and creates or updates the GitHub release. It does not run for ordinary commits.
