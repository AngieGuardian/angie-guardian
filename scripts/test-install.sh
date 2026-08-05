#!/usr/bin/env bash
# Contract checks for the standalone, root-only installer.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
installer="$script_dir/install.sh"

bash -n "$installer"
help_output="$(bash "$installer" --help)"
[[ "$help_output" == *'raw.githubusercontent.com/AngieGuardian/angie-guardian/main/scripts/install.sh'* ]]
[[ "$help_output" == *'Debian/Ubuntu systemd hosts'* ]]

test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT

# Source only the helpers, then mock the network response used by latest_version.
# shellcheck disable=SC1090
source "$installer"
work_dir="$test_dir"
download() {
  printf '%s\n' '{"tag_name":"0.18.0"}' >"$2"
}
[[ "$(latest_version)" == 0.18.0 ]]

archive='angie-guardian-0.18.0-linux-amd64.tar.gz'
printf '%s\n' payload >"$test_dir/$archive"
checksum="$(sha256sum "$test_dir/$archive" | awk '{print $1}')"
printf '%s  %s\n' "$checksum" "$archive" >"$test_dir/SHA256SUMS"
(
  cd "$test_dir"
  verify_archive "$archive" SHA256SUMS
)
printf '%s\n' altered >"$test_dir/$archive"
if (
  cd "$test_dir"
  verify_archive "$archive" SHA256SUMS
) 2>/dev/null; then
  echo 'checksum mismatch unexpectedly passed' >&2
  exit 1
fi

grep -Fq 'install_if_missing' "$installer"
grep -Fq 'systemctl restart' "$installer"
grep -Fq 'Angie was not changed or reloaded' "$installer"
