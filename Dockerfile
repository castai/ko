FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /ko ./cmd/ko

FROM gcr.io/distroless/static
COPY --from=build /ko /ko
ENTRYPOINT ["/ko"]
