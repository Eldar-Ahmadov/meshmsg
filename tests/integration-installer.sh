#!/usr/bin/env bash
set -euo pipefail

BIN=${1:-target/debug/meshmsg}
BIN=$(realpath "$BIN")
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/meshmsg-installer.XXXXXX")
trap 'rm -rf "$ROOT"' EXIT
TAG="v$($BIN --version | awk '{print $2}')"
TARGET=x86_64-unknown-linux-musl
NAME="meshmsg-${TAG}-${TARGET}"
ARCHIVE="${NAME}.tar.gz"
mkdir -p "$ROOT/fixture/$NAME/docs" "$ROOT/mock-bin" "$ROOT/install"
install -m 0755 "$BIN" "$ROOT/fixture/$NAME/meshmsg"
install -m 0644 README.md LICENSE-MIT LICENSE-APACHE "$ROOT/fixture/$NAME/"
cp -R docs/. "$ROOT/fixture/$NAME/docs/"
tar -C "$ROOT/fixture" -czf "$ROOT/fixture/$ARCHIVE" "$NAME"
(cd "$ROOT/fixture" && sha256sum "$ARCHIVE" >SHA256SUMS)

cat >"$ROOT/mock-bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
output=
url=
while (($#)); do
  case "$1" in
    --output) output=$2; shift 2 ;;
    --write-out) shift 2 ;;
    --proto|--retry) shift 2 ;;
    --tlsv1.2|--fail|--silent|--show-error|--location) shift ;;
    *) url=$1; shift ;;
  esac
done
if [[ $url == */latest ]]; then
  printf '%s/download/%s\n' "${MESHMSG_TEST_RELEASES_URL:?}" "${MESHMSG_TEST_TAG:?}"
else
  cp "${MESHMSG_TEST_FIXTURE:?}/${url##*/}" "$output"
fi
MOCK
chmod +x "$ROOT/mock-bin/curl"

run_installer() {
  PATH="$ROOT/mock-bin:$PATH" \
  MESHMSG_TEST_RELEASES_URL=https://fixture.invalid/releases \
  MESHMSG_TEST_TAG="$TAG" MESHMSG_TEST_FIXTURE="$ROOT/fixture" \
  MESHMSG_INSTALL_DIR="$ROOT/install" bash install.sh
}
run_installer
[[ $($ROOT/install/meshmsg --version) == "meshmsg ${TAG#v}" ]]

# A generated archive with a checksum list that does not authenticate its exact
# expected name must fail without replacing the installed binary.
cp "$ROOT/fixture/SHA256SUMS" "$ROOT/fixture/SHA256SUMS.good"
printf '%064d  wrong.tar.gz\n' 0 >"$ROOT/fixture/SHA256SUMS"
if run_installer >"$ROOT/bad.out" 2>"$ROOT/bad.err"; then
  echo "installer accepted a checksum list without its archive" >&2
  exit 1
fi
cmp "$BIN" "$ROOT/install/meshmsg"
mv "$ROOT/fixture/SHA256SUMS.good" "$ROOT/fixture/SHA256SUMS"

echo "installer integration: ok"
