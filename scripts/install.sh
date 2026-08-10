#!/usr/bin/env bash
# Angie Guardian host installer. It intentionally never edits Angie vhosts.
set -euo pipefail

readonly REPOSITORY='AngieGuardian/angie-guardian'
readonly SERVICE_NAME='guardiand'
readonly CONFIG_DIR='/etc/guardian'
readonly ANGIE_DIR='/etc/angie'
readonly STATE_DIR='/var/lib/guardian'
readonly INSTALL_DIR='/usr/local/bin'

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[1;33m'
reset='\033[0m'

error() { printf '%berror:%b %s\n' "$red" "$reset" "$*" >&2; exit 1; }
info() { printf '%b::%b %s\n' "$green" "$reset" "$*"; }
warn() { printf '%bwarning:%b %s\n' "$yellow" "$reset" "$*" >&2; }

cleanup() {
  if [[ -n "${work_dir:-}" && -d "$work_dir" ]]; then
    rm -rf "$work_dir"
  fi
  if [[ -n "${validation_binary:-}" ]]; then
    rm -f -- "$validation_binary"
  fi
}

require_root() {
  [[ "$(id -u)" -eq 0 ]] || error 'run this installer as root (for example: curl ... | sudo bash)'
}

require_platform() {
  [[ "$(uname -s)" == Linux ]] || error "Linux is required (got $(uname -s))"
  [[ -r /etc/os-release ]] || error 'cannot identify the Linux distribution'
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}" in
    debian|ubuntu) ;;
    *) error "only Debian and Ubuntu are supported (got ${PRETTY_NAME:-unknown})" ;;
  esac
  command -v systemctl >/dev/null 2>&1 || error 'systemd is required (systemctl was not found)'
}

install_dependencies() {
  local missing=()
  command -v curl >/dev/null 2>&1 || missing+=(curl)
  command -v tar >/dev/null 2>&1 || missing+=(tar)
  command -v sha256sum >/dev/null 2>&1 || missing+=(coreutils)
  dpkg-query --show --showformat='${db:Status-Status}' ca-certificates 2>/dev/null | grep -qx installed || missing+=(ca-certificates)
  if ((${#missing[@]})); then
    info "Installing required packages: ${missing[*]}"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates "${missing[@]}"
  fi
}

detect_architecture() {
  case "$(uname -m)" in
    x86_64|amd64) printf '%s\n' amd64 ;;
    aarch64|arm64) printf '%s\n' arm64 ;;
    *) error "unsupported architecture: $(uname -m) (supported: x86_64, aarch64)" ;;
  esac
}

download() {
  local url=$1 destination=$2
  curl --fail --location --show-error --silent --retry 3 --retry-delay 1 --output "$destination" "$url"
}

latest_version() {
  local release_json version
  release_json="$work_dir/release.json"
  download "https://api.github.com/repos/${REPOSITORY}/releases/latest" "$release_json" || error 'could not resolve the latest GitHub release'
  version="$(sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v?([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' "$release_json" | head -n1)"
  [[ -n "$version" ]] || error 'the latest GitHub release has no supported semantic-version tag'
  printf '%s\n' "$version"
}

verify_archive() {
  local archive=$1 checksums=$2 checksum_line
  checksum_line="$(grep -E "^[[:xdigit:]]{64}[[:space:]]{2}${archive}$" "$checksums" || true)"
  [[ -n "$checksum_line" ]] || error "SHA256SUMS has no checksum for ${archive}"
  printf '%s\n' "$checksum_line" | sha256sum --check --status - || error "checksum verification failed for ${archive}"
}

install_if_missing() {
  local source=$1 destination=$2 mode=$3
  if [[ -e "$destination" ]]; then
    warn "preserving existing ${destination}"
    return
  fi
  install -D -m "$mode" "$source" "$destination"
}

install_preserving_local() {
  local source=$1 destination=$2 mode=$3 source_checksum destination_checksum
  if [[ ! -e "$destination" ]]; then
    install -D -m "$mode" "$source" "$destination"
    return
  fi

  if [[ ! -f "$destination" ]]; then
    warn "ACTION REQUIRED: preserving existing non-regular ${destination}; review and update it manually if needed"
    return
  fi

  source_checksum="$(sha256sum "$source" | awk '{print $1}')"
  destination_checksum="$(sha256sum "$destination" | awk '{print $1}')"
  if [[ "$source_checksum" != "$destination_checksum" ]]; then
    warn "ACTION REQUIRED: preserving locally modified ${destination}; its SHA-256 differs from the release file. Review the release file and update this file manually if desired."
  fi
}

main() {
  require_root
  require_platform
  install_dependencies

  local arch version archive package_dir validation_output was_active=false
  arch="$(detect_architecture)"
  work_dir="$(mktemp -d)"
  trap cleanup EXIT
  version="$(latest_version)"
  archive="angie-guardian-${version}-linux-${arch}.tar.gz"
  package_dir="$work_dir/angie-guardian-${version}-linux-${arch}"

  info "Installing Angie Guardian ${version} for linux-${arch}"
  download "https://github.com/${REPOSITORY}/releases/download/${version}/${archive}" "$work_dir/$archive" || error "could not download GitHub release ${version}"
  download "https://github.com/${REPOSITORY}/releases/download/${version}/SHA256SUMS" "$work_dir/SHA256SUMS" || error "could not download checksums for GitHub release ${version}"
  # SHA256SUMS contains a relative archive name; verify it from the download directory.
  (cd "$work_dir" && verify_archive "$archive" SHA256SUMS)
  tar --no-same-owner -xzf "$work_dir/$archive" -C "$work_dir"

  [[ -x "$package_dir/guardiand" ]] || error 'release archive does not contain guardiand'
  [[ -f "$package_dir/guardian.example.yaml" ]] || error 'release archive does not contain guardian.example.yaml'
  [[ -f "$package_dir/deploy/rules-common.yaml" ]] || error 'release archive does not contain starter rules'
  [[ -f "$package_dir/deploy/guardiand.service" ]] || error 'release archive does not contain the systemd unit'
  [[ -f "$package_dir/deploy/angie-guardian.conf" ]] || error 'release archive does not contain the Angie endpoint snippet'
  [[ -f "$package_dir/deploy/angie-guardian-location.conf" ]] || error 'release archive does not contain the Angie location snippet'

  getent group guardian >/dev/null || groupadd --system guardian
  id guardian >/dev/null 2>&1 || useradd --system --gid guardian --home-dir "$STATE_DIR" --shell /usr/sbin/nologin guardian
  install -d -o root -g guardian -m 0710 "$CONFIG_DIR"
  install -d -o root -g guardian -m 0750 "$CONFIG_DIR/rules.d"
  install_if_missing "$package_dir/guardian.example.yaml" "$CONFIG_DIR/guardian.yaml" 0640
  install_if_missing "$package_dir/deploy/rules-common.yaml" "$CONFIG_DIR/rules.d/common.yaml" 0640
  chown root:guardian "$CONFIG_DIR/guardian.yaml" "$CONFIG_DIR/rules.d/common.yaml"

  # Validate from an executable filesystem: /tmp may be mounted noexec.
  validation_binary="$INSTALL_DIR/.guardiand-validation.$$"
  install -D -m 0755 "$package_dir/guardiand" "$validation_binary"
  if ! validation_output="$(runuser -u guardian -- "$validation_binary" -config "$CONFIG_DIR/guardian.yaml" -t 2>&1)"; then
    printf '%s\n' "$validation_output" >&2
    error 'Guardian configuration validation failed'
  fi
  rm -f -- "$validation_binary"
  validation_binary=''

  install -D -m 0755 "$package_dir/guardiand" "$INSTALL_DIR/guardiand"
  install_preserving_local "$package_dir/deploy/guardiand.service" "/etc/systemd/system/${SERVICE_NAME}.service" 0644
  install_preserving_local "$package_dir/deploy/angie-guardian.conf" "$ANGIE_DIR/angie-guardian.conf" 0644
  install_preserving_local "$package_dir/deploy/angie-guardian-location.conf" "$ANGIE_DIR/angie-guardian-location.conf" 0644
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    was_active=true
  fi
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  if [[ "$was_active" == true ]]; then
    systemctl restart "$SERVICE_NAME"
  else
    systemctl start "$SERVICE_NAME"
  fi

  printf '\n%s\n' 'Angie Guardian is installed and running.'
  printf '%s\n' "  Config:  ${CONFIG_DIR}/guardian.yaml (preserved on upgrades)"
  printf '%s\n' '  Health:  curl --fail http://127.0.0.1:8071/healthz'
  printf '%s\n' '           curl --fail http://127.0.0.1:8072/readyz'
  printf '\n%s\n' 'Angie was not changed or reloaded. After reviewing guardian.yaml, add these inside each protected server block:'
  printf '%s\n' '  include angie-guardian.conf;'
  printf '%s\n' '  include angie-guardian-location.conf;'
  printf '%s\n' 'Define the guardian upstream once in Angie http{} as documented, then run angie -t and reload Angie yourself.'
}

# BASH_SOURCE is unset when Bash reads this script from standard input, which is
# the documented curl | sudo bash invocation.  Fall back to $0 in that case,
# while retaining the guard that prevents main from running when sourced.
if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
  case "${1:-}" in
    --help|-h)
      printf '%s\n' 'Usage: curl -fsSL https://raw.githubusercontent.com/AngieGuardian/angie-guardian/main/scripts/install.sh | sudo bash'
      printf '%s\n' 'Installs the latest GitHub release on Debian/Ubuntu systemd hosts.'
      ;;
    '') main ;;
    *) error "unknown option: $1 (try --help)" ;;
  esac
fi
