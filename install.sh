#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_dir"

if [ ! -t 0 ] || [ ! -t 1 ]; then
  echo 'Run ./install.sh in an interactive terminal on the Docker host.' >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo 'Docker is required. Install Docker Engine and the Compose plugin first.' >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo 'Docker Compose v2 is required.' >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo 'Cannot reach the Docker daemon. Start Docker or check your Docker access.' >&2
  exit 1
fi

case "$(uname -s)" in
  Linux) target_os=linux ;;
  Darwin) target_os=darwin ;;
  *) echo 'The installer supports Linux and macOS hosts.' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) target_arch=amd64 ;;
  arm64|aarch64) target_arch=arm64 ;;
  *) echo 'The installer supports amd64 and arm64 hosts.' >&2; exit 1 ;;
esac

build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM

echo 'Preparing the Xray-easy installer...'
docker run --rm --network none \
  --user "$(id -u):$(id -g)" \
  -e GOOS="$target_os" -e GOARCH="$target_arch" \
  -e GOTOOLCHAIN=local -e GOPROXY=off -e GOCACHE=/tmp/go-build \
  -v "$project_dir:/src:ro" -v "$build_dir:/out" -w /src \
  golang:1.24-alpine \
  sh -ec 'CGO_ENABLED=0 go build -trimpath -o /out/xray-easy-install ./cmd/xray-easy-install'

"$build_dir/xray-easy-install" "$project_dir"
