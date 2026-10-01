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
installer_container=
cleanup() {
  if [ -n "$installer_container" ]; then
    docker rm -f "$installer_container" >/dev/null 2>&1 || true
  fi
  rm -rf "$build_dir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

read_env_value() {
  env_key=$1
  env_value=
  if [ -f "$project_dir/.env" ]; then
    env_value=$(sed -n "s/^${env_key}=//p" "$project_dir/.env" | sed -n '1p')
  fi
  case "$env_value" in
    \"*\") env_value=${env_value#\"}; env_value=${env_value%\"} ;;
    \'*\') env_value=${env_value#\'}; env_value=${env_value%\'} ;;
  esac
  printf '%s' "$env_value"
}

configured_image_namespace=$(read_env_value XRAY_EASY_IMAGE_NAMESPACE)
image_namespace=${XRAY_EASY_IMAGE_NAMESPACE:-$configured_image_namespace}
if [ -z "${XRAY_EASY_IMAGE_NAMESPACE:-}" ] && [ "$image_namespace" = "dasshit" ]; then
  image_namespace=xray-easy
fi
image_namespace=${image_namespace:-xray-easy}
image_tag=${XRAY_EASY_IMAGE_TAG:-$(read_env_value XRAY_EASY_IMAGE_TAG)}
image_tag=${image_tag:-latest}
case "$image_namespace" in
  ''|[-.]*|*[!a-z0-9_./-]*)
    echo "Invalid XRAY_EASY_IMAGE_NAMESPACE: $image_namespace" >&2
    exit 1
    ;;
esac
case "$image_tag" in
  ''|[-.]*|*[!A-Za-z0-9_.-]*)
    echo "Invalid XRAY_EASY_IMAGE_TAG: $image_tag" >&2
    exit 1
    ;;
esac
installer_image=${XRAY_EASY_INSTALLER_IMAGE:-$image_namespace/installer:$image_tag}

if app_version=$(git -C "$project_dir" describe --tags --always --dirty 2>/dev/null); then
  :
else
  app_version=source
fi

echo "Pulling installer image $installer_image..."
if docker pull "$installer_image"; then
  echo 'Using the published installer image.'
else
  echo 'The installer image could not be pulled; building it locally from this checkout.'
  docker build --platform "linux/$target_arch" \
    --file Dockerfile.installer \
    --tag "$installer_image" \
    "$project_dir"
fi

installer_container=$(docker create --platform "linux/$target_arch" "$installer_image")
if ! docker cp \
  "$installer_container:/usr/share/xray-easy-installer/$target_os/$target_arch/xray-easy-install" \
  "$build_dir/xray-easy-install"; then
  echo "The installer image does not contain a $target_os/$target_arch binary." >&2
  exit 1
fi
docker rm "$installer_container" >/dev/null
installer_container=
chmod 700 "$build_dir/xray-easy-install"

XRAY_EASY_BUILD_VERSION="$app_version" \
XRAY_EASY_IMAGE_NAMESPACE="$image_namespace" \
XRAY_EASY_IMAGE_TAG="$image_tag" \
  "$build_dir/xray-easy-install" "$project_dir"
