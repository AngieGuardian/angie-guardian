#!/usr/bin/env bash
# Contract checks for the standalone, root-only installer.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
installer="$script_dir/install.sh"

bash -n "$installer"
help_output="$(bash "$installer" --help)"
[[ "$help_output" == *'raw.githubusercontent.com/AngieGuardian/angie-guardian/main/scripts/install.sh'* ]]
[[ "$help_output" == *'Debian/Ubuntu systemd hosts'* ]]

# Bash leaves BASH_SOURCE unset for scripts consumed from standard input.
pipe_help_output="$(bash -s -- --help <"$installer")"
[[ "$pipe_help_output" == *'raw.githubusercontent.com/AngieGuardian/angie-guardian/main/scripts/install.sh'* ]]
[[ "$pipe_help_output" == *'Debian/Ubuntu systemd hosts'* ]]

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

unit_source="$test_dir/guardiand.service"
unit_destination="$test_dir/system/guardiand.service"
printf '%s\n' '[Service]' >"$unit_source"
install_preserving_local "$unit_source" "$unit_destination" 0644
cmp -s "$unit_source" "$unit_destination"

printf '%s\n' 'Environment=EXTRA=value' >>"$unit_destination"
warning_output="$(install_preserving_local "$unit_source" "$unit_destination" 0644 2>&1 >/dev/null)"
[[ "$warning_output" == *'ACTION REQUIRED: preserving locally modified'* ]]
[[ "$warning_output" == *'SHA-256 differs from the release file'* ]]
grep -Fqx 'Environment=EXTRA=value' "$unit_destination"

grep -Fq 'install_if_missing' "$installer"
grep -Fq 'install_preserving_local' "$installer"
grep -Fq 'systemctl restart' "$installer"
grep -Fq 'Angie was not changed or reloaded' "$installer"
grep -Fq 'angie-hardening-http.conf' "$installer"
grep -Fq 'angie-hardening-server.conf' "$installer"

# Verify real CLI file installation/upgrade without touching the host service.
cli_package="$test_dir/cli-package"
cli_install="$test_dir/cli-install"
mkdir -p "$cli_package"
printf '%s\n' '#!/bin/sh' 'echo fixture-v1' >"$cli_package/guardianctl"
chmod 0755 "$cli_package/guardianctl"
install_operator_cli "$cli_package" "$cli_install"
[[ "$("$cli_install/guardianctl")" == fixture-v1 ]]
[[ "$(stat -c %a "$cli_install/guardianctl")" == 755 ]]
printf '%s\n' '#!/bin/sh' 'echo fixture-v2' >"$cli_package/guardianctl"
install_operator_cli "$cli_package" "$cli_install"
[[ "$("$cli_install/guardianctl")" == fixture-v2 ]]
rm "$cli_package/guardianctl"
legacy_notice="$(install_operator_cli "$cli_package" "$cli_install" 2>&1)"
[[ "$legacy_notice" == *'release predates guardianctl'* ]]
[[ "$("$cli_install/guardianctl")" == fixture-v2 ]]
# A present but broken binary must not be silently treated as historical.
printf '%s\n' broken >"$cli_package/guardianctl"
if (install_operator_cli "$cli_package" "$cli_install") 2>/dev/null; then
  echo 'non-executable guardianctl unexpectedly installed' >&2
  exit 1
fi

# The trainer must be installed and upgraded with the daemon's release.
trainer_package="$test_dir/trainer-package"
trainer_install="$test_dir/trainer-install"
mkdir -p "$trainer_package"
printf '%s\n' '#!/bin/sh' 'echo trainer-v1' >"$trainer_package/guardian-train"
chmod 0755 "$trainer_package/guardian-train"
install_trainer "$trainer_package" "$trainer_install"
[[ "$("$trainer_install/guardian-train")" == trainer-v1 ]]
[[ "$(stat -c %a "$trainer_install/guardian-train")" == 755 ]]
printf '%s\n' '#!/bin/sh' 'echo trainer-v2' >"$trainer_package/guardian-train"
install_trainer "$trainer_package" "$trainer_install"
[[ "$("$trainer_install/guardian-train")" == trainer-v2 ]]
chmod 0644 "$trainer_package/guardian-train"
if (install_trainer "$trainer_package" "$trainer_install") 2>/dev/null; then
  echo 'non-executable guardian-train unexpectedly installed' >&2
  exit 1
fi
rm "$trainer_package/guardian-train"
if (install_trainer "$trainer_package" "$trainer_install") 2>/dev/null; then
  echo 'missing guardian-train unexpectedly accepted' >&2
  exit 1
fi
[[ "$("$trainer_install/guardian-train")" == trainer-v2 ]]
