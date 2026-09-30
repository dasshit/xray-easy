#!/bin/sh
set -eu

# Backward-compatible entry point. The shared generator also emits the
# Supervisor's typed private runtime contract.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec "$repo_root/scripts/generate-protobuf.sh"
