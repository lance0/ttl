#!/bin/sh
# ttl installer - https://github.com/lance0/ttl
# Usage: curl -fsSL https://raw.githubusercontent.com/lance0/ttl/master/install.sh | sh

set -e

REPO="lance0/ttl"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
  linux)
    case "$ARCH" in
      x86_64)  TARGET="x86_64-unknown-linux-musl" ;;
      aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
      arm64)   TARGET="aarch64-unknown-linux-gnu" ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  darwin)
    case "$ARCH" in
      arm64)   TARGET="aarch64-apple-darwin" ;;
      aarch64) TARGET="aarch64-apple-darwin" ;;
      x86_64)  TARGET="x86_64-apple-darwin" ;;
      *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

# Get latest version
VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
if [ -z "$VERSION" ]; then
  echo "Failed to get latest version"
  exit 1
fi

URL="https://github.com/$REPO/releases/download/$VERSION/ttl-$TARGET.tar.gz"

echo "Installing ttl $VERSION for $TARGET..."

# Download and extract
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -fsSL "$URL" | tar xz -C "$TMPDIR"

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMPDIR/ttl" "$INSTALL_DIR/ttl"
else
  echo "Installing to $INSTALL_DIR (requires sudo)..."
  sudo mv "$TMPDIR/ttl" "$INSTALL_DIR/ttl"
fi

echo "Installed ttl to $INSTALL_DIR/ttl"

# Set capability on Linux so ttl can run without sudo
if [ "$OS" = "linux" ]; then
  echo ""
  echo "ttl requires raw socket access for ICMP probing."
  echo "You can either:"
  echo "  1. Run with sudo each time: sudo ttl <target>"
  echo "  2. Grant capability now (recommended): allows running without sudo"
  echo ""
  printf "Grant cap_net_raw capability? [Y/n] "
  read -r REPLY
  case "$REPLY" in
    [nN]*)
      echo "Skipped. Run with: sudo ttl <target>"
      ;;
    *)
      echo "Running: sudo setcap cap_net_raw+ep $INSTALL_DIR/ttl"
      if sudo setcap cap_net_raw+ep "$INSTALL_DIR/ttl"; then
        echo ""
        echo "Done! You can now run: ttl <target>"
      else
        echo "Failed to set capability. Run with: sudo ttl <target>"
      fi
      ;;
  esac
else
  # macOS - no capabilities, always needs sudo
  echo ""
  echo "On macOS, run with sudo: sudo ttl <target>"
fi
