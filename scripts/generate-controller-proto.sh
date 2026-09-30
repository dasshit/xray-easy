#!/bin/sh
set -eu

# Pin Buf and the protoc plugins in this project. The runtime images do not
# include generation tooling; this command is for maintainers changing the API.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
docker run --rm \
  -v "$repo_root:/workspace" \
  -w /workspace \
  bufbuild/buf:1.57.2 \
  generate internal/controller/api/v1/controller.proto
