#!/usr/bin/env bash
# Builds and pushes the ko docker image and helm chart (OCI) to GHCR.
#
# Basic usage:
#   GITHUB_TOKEN=... ./tools/build.sh
#
# Optional environment:
#   KO_TAG         image tag (default: dev-<user>-<sha>-<timestamp>)
#   KO_ARCHS       comma separated list (default: amd64,arm64)
#   KO_PUSH_CHART  push the helm chart (default: true)
#   GITHUB_USER    GHCR username for login (default: anjmao)

set -euo pipefail

REGISTRY="ghcr.io/castai"
IMAGE_REPOSITORY="${REGISTRY}/ko"
CHART_REPOSITORY="${REGISTRY}/ko-chart"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHART_DIR="${ROOT_DIR}/charts/ko"

TAG="${KO_TAG:-dev-$(whoami)-$(git rev-parse --short HEAD)-$(date +%s)}"
ARCHS="${KO_ARCHS:-amd64,arm64}"
PUSH_CHART="${KO_PUSH_CHART:-true}"
GITHUB_USER="${GITHUB_USER:-anjmao}"

BUILDER="ko-multiarch"

# Keep helm's registry credentials in an isolated file: the default OS
# keychain store fails with a duplicate item error once docker login has
# already stored the ghcr.io entry.
HELM_REGISTRY_CONFIG="$(mktemp)"
echo '{}' > "${HELM_REGISTRY_CONFIG}"
export HELM_REGISTRY_CONFIG
trap 'rm -f "${HELM_REGISTRY_CONFIG}"' EXIT

log() {
  echo "==> $*" >&2
}

ensure_builder() {
  if ! docker buildx inspect "${BUILDER}" >/dev/null 2>&1; then
    log "creating buildx builder '${BUILDER}'"
    docker buildx create --name "${BUILDER}" --use
  else
    docker buildx use "${BUILDER}"
  fi
}

login_ghcr() {
  if [ -z "${GITHUB_TOKEN:-}" ]; then
    log "GITHUB_TOKEN not set, assuming an existing ghcr.io login"
    return
  fi
  echo "${GITHUB_TOKEN}" | docker login ghcr.io -u "${GITHUB_USER}" --password-stdin
  echo "${GITHUB_TOKEN}" | helm registry login ghcr.io -u "${GITHUB_USER}" --password-stdin
}

build_platforms() {
  local platforms=""
  local first=1
  for arch in ${ARCHS//,/ }; do
    if [ $first -eq 1 ]; then
      platforms="linux/${arch}"
      first=0
    else
      platforms="${platforms},linux/${arch}"
    fi
  done
  echo "${platforms}"
}

build_and_push_image() {
  local archs
  read -r -a archs <<< "${ARCHS//,/ }"

  log "building and pushing image: ${IMAGE_REPOSITORY}:${TAG} (${ARCHS})"
  cd "${ROOT_DIR}"

  local tags=()
  local arch
  for arch in "${archs[@]}"; do
    log "compiling linux/${arch} binary"
    CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath \
      -ldflags="-s -w -X main.version=${TAG}" \
      -o ko ./cmd/ko

    local image_tag="${IMAGE_REPOSITORY}:${TAG}"
    if [ "${#archs[@]}" -gt 1 ]; then
      image_tag="${image_tag}-${arch}"
    fi
    tags+=("${image_tag}")

    docker buildx build \
      --builder "${BUILDER}" \
      --platform "linux/${arch}" \
      -t "${image_tag}" \
      -f Dockerfile \
      --push .
  done
  rm -f ko

  if [ "${#archs[@]}" -gt 1 ]; then
    log "merging into multi-arch manifest: ${IMAGE_REPOSITORY}:${TAG}"
    docker buildx imagetools create \
      -t "${IMAGE_REPOSITORY}:${TAG}" \
      "${tags[@]}"
  fi
}

chart_version_from_tag() {
  local tag="$1"
  if [[ "${tag}" =~ ^dev-(.+)$ ]]; then
    local suffix="${BASH_REMATCH[1]}"
    suffix="${suffix//[^a-zA-Z0-9.]/.}"
    echo "0.0.0-dev.${suffix}"
  else
    echo "${tag}"
  fi
}

push_chart_oci() {
  local chart_version
  chart_version="$(chart_version_from_tag "${TAG}")"

  log "packaging and pushing helm chart: ${CHART_REPOSITORY}/ko:${chart_version}"
  cd "${CHART_DIR}"

  local pkg_file
  # appVersion carries the built image tag: the chart's default image.tag
  # resolves to it, so installs need no --set image.tag.
  pkg_file="$(helm package --version "${chart_version}" --app-version "${TAG}" . | awk '{print $NF}')"

  helm push "${pkg_file}" "oci://${CHART_REPOSITORY}"
  rm -f "${pkg_file}"
}

print_summary() {
  local chart_version
  chart_version="$(chart_version_from_tag "${TAG}")"

  log "build complete!"
  echo "" >&2
  echo "  archs:            ${ARCHS}" >&2
  echo "  image:            ${IMAGE_REPOSITORY}:${TAG}" >&2
  if [ "${PUSH_CHART}" = "true" ]; then
    echo "  helm chart (OCI): ${CHART_REPOSITORY}/ko:${chart_version}" >&2
  fi
  echo "" >&2
  echo "  Helm upgrade command:" >&2
  echo "" >&2
  if [ "${PUSH_CHART}" = "true" ]; then
    printf '  helm upgrade ko -n ko \\\n    oci://%s/ko \\\n    --version="%s" \\\n    --create-namespace\n' \
      "${CHART_REPOSITORY}" "${chart_version}" >&2
  else
    printf '  helm upgrade ko -n ko \\\n    %s/charts/ko \\\n    --create-namespace \\\n    --set image.tag=%s\n' \
      "${ROOT_DIR}" "${TAG}" >&2
  fi
}

main() {
  if ! command -v go >/dev/null 2>&1; then
    log "go is required to build the binary"
    exit 1
  fi

  log "build bundle"
  log "  image registry:   ${IMAGE_REPOSITORY}"
  log "  chart registry:   ${CHART_REPOSITORY}"
  log "  tag:              ${TAG}"
  log "  archs:            ${ARCHS}"
  log "  platforms:        $(build_platforms)"

  ensure_builder
  login_ghcr

  build_and_push_image

  if [ "${PUSH_CHART}" = "true" ]; then
    push_chart_oci
  fi

  print_summary
}

main "$@"
