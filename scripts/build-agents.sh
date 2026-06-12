#!/usr/bin/env bash
# Build static musl agent binaries for the supported remote targets and
# install them into the dist cache the client deploys from
# (~/.cache/portmanager/dist/agent-<triple>).
#
# Tries cargo-zigbuild first (best on macOS), then cross on Linux
# (container-based), then native cargo if a suitable musl-gcc is available.
set -euo pipefail

cd "$(dirname "$0")/.."
DIST="${XDG_CACHE_HOME:-$HOME/.cache}/portmanager/dist"
mkdir -p "$DIST"
HOST_OS="$(uname -s)"

build_target() {
    local triple="$1"
    local cc="${triple%%-*}-linux-musl-gcc"

    if command -v cargo-zigbuild >/dev/null 2>&1; then
        rustup target add "$triple" >/dev/null 2>&1 || true
        cargo zigbuild --release --target "$triple"
    elif [[ "$HOST_OS" == "Linux" ]] && command -v cross >/dev/null 2>&1; then
        cross build --release --target "$triple"
    elif command -v "$cc" >/dev/null 2>&1; then
        rustup target add "$triple" >/dev/null 2>&1 || true
        cargo build --release --target "$triple"
    else
        cat >&2 <<EOF
skipping $triple: no suitable Linux-musl cross toolchain found.
Install one of:
  cargo install cargo-zigbuild && brew install zig
  cargo install cross     # Linux hosts only
  $cc
EOF
        return 0
    fi

    install -m 0755 "target/$triple/release/portmanager" "$DIST/agent-$triple"
    echo "built $DIST/agent-$triple"
}

build_target x86_64-unknown-linux-musl
build_target aarch64-unknown-linux-musl
