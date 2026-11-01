#!/usr/bin/env bash
# Regenerates internal/gen from api/proto with the tool versions pinned in
# tools/go.mod. CI runs it and fails if the result differs from the commit.
set -euo pipefail
cd "$(dirname "$0")/.."

bin="$(pwd)/.bin"
mkdir -p "$bin"
GOFLAGS=-modfile=tools/go.mod go build -o "$bin/" \
  github.com/bufbuild/buf/cmd/buf \
  google.golang.org/protobuf/cmd/protoc-gen-go \
  connectrpc.com/connect/cmd/protoc-gen-connect-go

export PATH="$bin:$PATH"
buf lint
rm -rf internal/gen
buf generate
