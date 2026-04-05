# Rust for Secure Systems Programming

Source for the book *Rust for Secure Systems Programming* by Mounir IDRASSI.

This repository contains:

- The `mdBook` manuscript under `src/`
- Companion Rust crates under `companion/`
- The generated static site under `book/`

Published book:

- https://amcrypto.jp/rust-secure-systems/

Author:

- Mounir IDRASSI
- https://amcrypto.jp

## Repository Layout

```text
src/          Book chapters and front matter
companion/    Tested multi-file examples used by the book
book/         Generated static HTML output from mdBook
theme/        Custom mdBook styling
```

## Build

Install Rust and `mdbook`, then run:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check -p rust-secure-systems-book --target-dir target/book-snippets-check
mdbook build
mdbook test -L target/book-snippets-check/debug/deps
```

If you rerun the snippet tests locally after editing the helper crate, clear `target/book-snippets-check/` first or choose a fresh `--target-dir`. Otherwise `mdbook test` can see multiple stale metadata files for `rust-secure-systems-book` and fail with duplicate-crate errors.

The generated site is written to `book/`.

## Publishing

The book is configured for deployment under:

- https://amcrypto.jp/rust-secure-systems/

Repository links in the generated site point to:

- https://github.com/idrassi/rust-secure-systems

## License

All content in this repository, including the manuscript, companion code, and generated site assets added by this project, is licensed under the Apache License, Version 2.0.

See [LICENSE](LICENSE) and [NOTICE](NOTICE).
