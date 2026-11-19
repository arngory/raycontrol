#!/usr/bin/env bash
# Regenerates internal/gen and api/openapi from api/proto with the tool
# versions pinned in tools/go.mod and tools/openapi/go.mod. CI runs it and
# fails if the result differs from the commit.
set -euo pipefail
cd "$(dirname "$0")/.."

bin="$(pwd)/.bin"
mkdir -p "$bin"
GOFLAGS=-modfile=tools/go.mod go build -o "$bin/" \
  github.com/bufbuild/buf/cmd/buf \
  google.golang.org/protobuf/cmd/protoc-gen-go \
  connectrpc.com/connect/cmd/protoc-gen-connect-go

# The OpenAPI generator comes from a module of its own (tools/openapi):
# its dependencies would move protoc-gen-go.
GOFLAGS=-modfile=tools/openapi/go.mod go build -o "$bin/" \
  connectrpc.com/protoc-gen-connect-openapi

export PATH="$bin:$PATH"
buf lint
rm -rf internal/gen
buf generate
# OpenAPI of the integrations' roles (integrations-v1 §5.1).
rm -f api/openapi/*.openapi.yaml
buf generate --template buf.gen.openapi.yaml
