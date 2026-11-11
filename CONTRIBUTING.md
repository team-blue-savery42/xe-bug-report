<!-- SPDX-License-Identifier: MIT -->
# Contributing

## Checks

Run before every push; CI runs the same.

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --locked --target x86_64-pc-windows-msvc -- -D warnings
cargo test --locked --all-features
scripts/ci-supply-chain.sh
shellcheck scripts/ci-supply-chain.sh
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

## Dependencies

- Prefer the standard library. A new crate needs a reason, a small dependency graph, no C build
  and no new `-sys` crate.
- Add it to `bans.allow` in `deny.toml`.
- `cargo vet`, `cargo deny check` and `cargo audit` must pass; record new audits in
  `supply-chain/audits.toml`.
- `Cargo.lock` is committed; build with `--locked`. Dependabot updates are reviewed with
  `cargo vet diff`.
- Open item: the exemptions in `supply-chain/config.toml` still need audits.

