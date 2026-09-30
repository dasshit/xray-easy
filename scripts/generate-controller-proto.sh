#!/bin/sh
set -eu

# Backward-compatible entry point. The shared generator also emits the
# Embedded Xray runtime's typed private gRPC contract is generated separately.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec "$repo_root/scripts/generate-protobuf.sh"
