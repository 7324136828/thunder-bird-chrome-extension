#!/usr/bin/env sh
# Start the mail backend (mail-backend) on http://127.0.0.1:48101.
# Usage: ./run-backend.sh [--port PORT] [--addr HOST:PORT]
# Keep the terminal open while you use the extension; Ctrl+C stops it.
# Mailbox passwords are kept in memory only: stopping the backend locks every account.
set -e
cd "$(dirname "$0")"

if command -v cargo >/dev/null 2>&1; then
  echo "Building and starting mail-backend (the first build takes a few minutes)..."
  exec cargo run --release -p mail-backend -- "$@"
elif [ -x target/release/mail-backend ]; then
  echo "cargo not found - starting the previously built target/release/mail-backend"
  exec target/release/mail-backend "$@"
else
  echo
  echo "Rust is not installed, so mail-backend cannot be built."
  echo " 1. Install Rust from https://rustup.rs"
  echo " 2. Open a new terminal and run this script again."
  echo
  echo "The mail extension needs this backend for every mailbox operation."
  exit 1
fi
