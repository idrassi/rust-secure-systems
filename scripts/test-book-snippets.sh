#!/usr/bin/env bash
set -euo pipefail

HOST_TRIPLE="$(cargo -vV | awk '/^host:/ {print $2}')"
BOOK_SNIPPETS_TARGET_DIR="target/book-snippets-check-${HOST_TRIPLE}"

rm -rf "$BOOK_SNIPPETS_TARGET_DIR"
cargo check -p rust-secure-systems-book --target-dir "$BOOK_SNIPPETS_TARGET_DIR" "$@"
mdbook test -L "$BOOK_SNIPPETS_TARGET_DIR/debug/deps"
