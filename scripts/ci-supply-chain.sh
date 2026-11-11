#!/bin/sh
# SPDX-License-Identifier: MIT
# Supply-chain gate: cargo vet, cargo audit, cargo deny and the -sys crate check.
set -eu
cd "$(dirname "$0")/.."

cargo vet --locked
cargo audit --deny warnings
cargo deny --locked check

# No -sys crate except libc and windows-sys, so no dependency compiles C. linux-raw-sys is pure-Rust
# syscall bindings (no build script) pulled by tempfile -> rustix; it is listed so a new one fails.
allowed='^(libc|windows-sys|linux-raw-sys)$'
bad=$(cargo tree --locked -e normal --target all --prefix none \
    | sed 's/ v.*//' | sort -u | grep -- '-sys$' | grep -Ev "$allowed" || true)
if [ -n "$bad" ]; then
    echo "unexpected -sys crates: $bad" >&2
    exit 1
fi
echo "supply chain ok"
