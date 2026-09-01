#!/usr/bin/env bash
set -euo pipefail

readonly REPOSITORY="Eldar-Ahmadov/meshmsg"
readonly RELEASES_URL="https://github.com/${REPOSITORY}/releases"

fail() {
  printf 'meshmsg installer: %s\n' "$*" >&2
  exit 1
}

for command in curl tar install mktemp sha256sum; do
  command -v "${command}" >/dev/null 2>&1 || fail "required command not found: ${command}"
done

case "$(uname -s)" in
  Linux) ;;
  *) fail "unsupported operating system: $(uname -s) (only Linux release binaries are available through this installer)" ;;
esac

case "$(uname -m)" in
  x86_64|amd64) readonly TARGET="x86_64-unknown-linux-musl" ;;
  *) fail "unsupported architecture: $(uname -m) (available: x86_64)" ;;
esac

latest_url=$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  --retry 3 --output /dev/null --write-out '%{url_effective}' "${RELEASES_URL}/latest")
readonly TAG="${latest_url##*/}"
[[ "${TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] \
  || fail "could not determine a valid latest release tag from ${latest_url}"

readonly ARCHIVE="meshmsg-${TAG}-${TARGET}.tar.gz"
readonly DOWNLOAD_URL="${RELEASES_URL}/download/${TAG}"
work_dir=$(mktemp -d)
trap 'rm -rf "${work_dir}"' EXIT

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
  --output "${work_dir}/${ARCHIVE}" "${DOWNLOAD_URL}/${ARCHIVE}"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
  --output "${work_dir}/SHA256SUMS" "${DOWNLOAD_URL}/SHA256SUMS"

expected_checksum=$(awk -v archive="${ARCHIVE}" '$2 == archive { print $1 }' "${work_dir}/SHA256SUMS")
[[ "${expected_checksum}" =~ ^[0-9a-fA-F]{64}$ ]] \
  || fail "release checksum for ${ARCHIVE} is missing or invalid"
actual_checksum=$(sha256sum "${work_dir}/${ARCHIVE}" | awk '{ print $1 }')
[[ "${actual_checksum}" == "${expected_checksum}" ]] \
  || fail "checksum verification failed for ${ARCHIVE}"

archive_dir="${ARCHIVE%.tar.gz}"
tar -xzf "${work_dir}/${ARCHIVE}" -C "${work_dir}"
[[ -f "${work_dir}/${archive_dir}/meshmsg" && ! -L "${work_dir}/${archive_dir}/meshmsg" ]] \
  || fail "release archive does not contain the expected meshmsg binary"

if [[ -n "${MESHMSG_INSTALL_DIR:-}" ]]; then
  install_dir="${MESHMSG_INSTALL_DIR}"
elif [[ "$(id -u)" -eq 0 ]]; then
  install_dir="/usr/local/bin"
else
  install_dir="${HOME:?HOME is not set}/.local/bin"
fi

install -d "${install_dir}"
install -m 0755 "${work_dir}/${archive_dir}/meshmsg" "${install_dir}/meshmsg"
printf 'Installed meshmsg %s to %s/meshmsg\n' "${TAG}" "${install_dir}"

case ":${PATH}:" in
  *:"${install_dir}":*) ;;
  *) printf 'Add %s to PATH to run meshmsg.\n' "${install_dir}" ;;
esac
