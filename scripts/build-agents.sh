#!/usr/bin/env bash
# Build static musl agent binaries for the supported remote targets and
# install them into the dist cache the client deploys from
# (~/.cache/portmanager/dist/agent-<triple>).
#
# x86_64: native cargo build (needs `rustup target add x86_64-unknown-linux-musl`
#         and musl-gcc).
# aarch64: tries cargo-zigbuild first, then `cross` (container-based).
set -euo pipefail

cd "$(dirname "$0")/.."
DIST="${XDG_CACHE_HOME:-$HOME/.cache}/portmanager/dist"
mkdir -p "$DIST"

build_x86_64() {
    local triple=x86_64-unknown-linux-musl
    rustup target add "$triple" >/dev/null 2>&1 || true
    cargo build --release --target "$triple"
    install -m 0755 "target/$triple/release/portmanager" "$DIST/agent-$triple"
    echo "built $DIST/agent-$triple"
}

build_aarch64() {
    local triple=aarch64-unknown-linux-musl
    if command -v cargo-zigbuild >/dev/null 2>&1; then
        rustup target add "$triple" >/dev/null 2>&1 || true
        cargo zigbuild --release --target "$triple"
    elif command -v cross >/dev/null 2>&1; then
        cross build --release --target "$triple"
    else
        echo "skipping $triple: install cargo-zigbuild (preferred) or cross" >&2
        return 0
    fi
    install -m 0755 "target/$triple/release/portmanager" "$DIST/agent-$triple"
    echo "built $DIST/agent-$triple"
}

build_x86_64
build_aarch64
