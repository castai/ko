# Expects a statically linked linux binary in the context root, e.g.:
#   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
#     go build -trimpath -ldflags="-s -w -X main.version=dev" -o ko ./cmd/ko
# tools/build.sh builds one binary per target arch and merges the images
# into a multi-arch manifest.
FROM gcr.io/distroless/static
COPY ko /ko
ENTRYPOINT ["/ko"]
