#!/bin/bash

set -e

CLUSTER=ko-e2e
IMAGE_REPO=ko-e2e
IMAGE_TAG=local

if kind get clusters 2>/dev/null | grep -q "^$CLUSTER$"; then
  kind delete cluster --name "$CLUSTER"
fi
kind create cluster --name "$CLUSTER" --config "$(dirname "$0")/kind-config.yaml"

CGO_ENABLED=0 GOOS=linux GOARCH="$(docker version -f '{{.Server.Arch}}')" \
  go build -trimpath -ldflags="-s -w -X main.version=$IMAGE_TAG" -o ko ./cmd/ko

docker build -t "$IMAGE_REPO:$IMAGE_TAG" .

kind load docker-image "$IMAGE_REPO:$IMAGE_TAG" --name "$CLUSTER"

if E2E_KUBECONTEXT="kind-$CLUSTER" E2E_IMAGE_REPO="$IMAGE_REPO" E2E_IMAGE_TAG="$IMAGE_TAG" \
  go test -tags e2e ./e2e -v -count=1 -timeout 10m; then
  kind delete cluster --name "$CLUSTER"
else
  echo "e2e failed, cluster kept for debugging: kind export kubeconfig --name $CLUSTER; kubectl --context kind-$CLUSTER logs -n ko-e2e ds/ko-node-agent"
  exit 1
fi
