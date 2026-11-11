<!-- SPDX-License-Identifier: MIT -->
# Contributing

## Checks

Run before every push; CI runs the same.

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --locked --target x86_64-pc-windows-msvc -- -D warnings
cargo test --locked --all-features
cargo package --locked
scripts/ci-supply-chain.sh
shellcheck scripts/*.sh
```

## Code

- Every file starts with `SPDX-License-Identifier: MIT`.
- `unsafe` is denied crate-wide. Only `src/sys/unix.rs` and `src/sys/windows.rs` allow it, and
  every block has a `// SAFETY:` comment.
- No `unwrap` or `expect` outside tests. Input from the kernel, tools and file names never causes a
  panic. OS strings are converted lossily.
- Every read and child process goes through the bounded helpers in `procio` and the `Guard`.
- Document what is not obvious from the name and signature; do not restate it.
## Commits

- Subject `area: imperative summary`, at most 72 characters, for example
  `redact: treat percent-encoded separators as name boundaries`.
- Body wrapped at 72 columns: the problem, then the change. No lists of everything touched.
- One logical change per commit; each commit builds and passes the tests.
- End with `Signed-off-by: Name <email>` (`git commit -s`).

## Tests

- Unit tests sit next to their module, inline or in `<module>_tests.rs` (`tests.rs` in a module
  directory). They do not depend on a GPU, `xpu-smi`, root or a particular distribution.
- `tests/bundle_linux.rs` and `tests/bundle_windows.rs` run the binary end to end and read the
  archive with the independent zip reader in `tests/common/`.
- A change to a source row, profile or gate updates `tests/golden/` in the same commit.
- Windows code must pass `cargo clippy --target x86_64-pc-windows-msvc` on Linux; the Windows tests
  run on the `windows-latest` CI runner.
- The redaction timing test runs only in release builds:
  `cargo test --release --locked redact -- --ignored`.

## Dependencies

- Prefer the standard library. A new crate needs a reason, a small dependency graph, no C build
  and no new `-sys` crate.
- Add it to `bans.allow` in `deny.toml`.
- `cargo vet`, `cargo deny check` and `cargo audit` must pass; record new audits in
  `supply-chain/audits.toml`.
- `Cargo.lock` is committed; build with `--locked`. Dependabot updates are reviewed with
  `cargo vet diff`.
- Open item: the exemptions in `supply-chain/config.toml` still need audits.

## Packaging

- `scripts/package.sh` builds the release binary into `dist/`: a `.tar.gz` always, a `.deb` when
  `dpkg-deb` exists, an `.rpm` when `rpmbuild` exists. `DEB_DIST=<tag>` names the `.deb` per
  distribution (version `<version>-1~<tag>`).
- `scripts/package-arch.sh` builds the pacman package, its source tarball and the AUR `PKGBUILD`
  and `.SRCINFO`. It runs on Arch as a non-root user.
- The `.deb` depends on `libc6 (>= <glibc the binary references>)` and `libgcc-s1`.

## Releasing

- A version bump in `Cargo.toml` on `main` builds the release packages.
