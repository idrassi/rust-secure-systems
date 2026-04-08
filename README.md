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
mdbook build
BOOK_SNIPPETS_TARGET_DIR="target/book-snippets-check-$(cargo -vV | awk '/^host:/ {print $2}')"
rm -rf "$BOOK_SNIPPETS_TARGET_DIR"
cargo check -p rust-secure-systems-book --target-dir "$BOOK_SNIPPETS_TARGET_DIR"
mdbook test -L "$BOOK_SNIPPETS_TARGET_DIR/debug/deps"
```

In PowerShell, use the same host-specific target-dir pattern:

```powershell
$BookSnippetsTargetDir = "target/book-snippets-check-$((cargo -vV | Select-String '^host:' | ForEach-Object { $_.ToString().Split()[1] }))"
if (Test-Path $BookSnippetsTargetDir) { Remove-Item -LiteralPath $BookSnippetsTargetDir -Recurse -Force }
cargo check -p rust-secure-systems-book --target-dir $BookSnippetsTargetDir
mdbook test -L "$BookSnippetsTargetDir/debug/deps"
```

The fresh, host-specific helper directory avoids stale metadata collisions when the same working tree is reused across different hosts or toolchains.

The generated site is written to `book/`.

## Publishing

The book is configured for deployment under:

- https://amcrypto.jp/rust-secure-systems/

Repository links in the generated site point to:

- https://github.com/idrassi/rust-secure-systems

## License

All content in this repository, including the manuscript, companion code, and generated site assets added by this project, is licensed under the Apache License, Version 2.0.

See [LICENSE](LICENSE) and [NOTICE](NOTICE).
