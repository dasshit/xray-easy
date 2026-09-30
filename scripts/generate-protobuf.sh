#!/bin/sh
set -eu

# Pin Buf and the protoc plugins used by private runtime gRPC contracts.
# Runtime images consume checked-in generated Go code and do not need Buf.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

docker run --rm \
  -v "$repo_root:/workspace" \
  -w /workspace \
  bufbuild/buf:1.57.2 \
  generate internal/controller/api/v1/controller.proto

docker run --rm \
  -v "$repo_root:/workspace" \
  -w /workspace \
  bufbuild/buf:1.57.2 \
  generate internal/xrayruntime/api/v1/runtime.proto \
  --template buf.gen.xray-runtime.yaml

docker run --rm \
  -v "$repo_root:/workspace" \
  -w /workspace \
  bufbuild/buf:1.57.2 \
  generate awg-contract/api/v1/control.proto \
  --template buf.gen.awg.yaml
