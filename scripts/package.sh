#!/bin/sh
# SPDX-License-Identifier: MIT
# Builds the release binary and a tar.gz with it, LICENSE and README.md under dist/.
# Builds the binary only for now.
set -eu
cd "$(dirname "$0")/.."
cargo build --release --locked
