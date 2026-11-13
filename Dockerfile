# Base images are pinned by digest; Dependabot (docker ecosystem) proposes
# updates. The release workflow scans the result with Trivy before pushing,
# and a fixable HIGH/CRITICAL stops the release. There is no docker CLI or
# compose in the image: the panel talks to Docker through the Engine API.

# Stage 1: build the Go binary on the build machine's native platform and
# cross-compile for the target (no QEMU emulation of the Go toolchain).
FROM --platform=$BUILDPLATFORM golang:1.27.0-alpine3.24@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/crowsnest ./cmd/crowsnest

# Stage 2: minimal runtime image.
FROM alpine:3.24.4@sha256:93b41ef40b1677fce8fcc64ff4af09daddfacf5040afde618bc46c1e2d1cc7d4
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata
COPY --from=build /out/crowsnest /app/crowsnest

# Non-root user. Docker socket/proxy access is granted at runtime via
# `group_add` in compose.yaml, matching the host's docker group GID —
# not baked into the image.
RUN adduser -D -u 1000 appuser
USER appuser
WORKDIR /app

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/app/crowsnest", "healthcheck"]

ENTRYPOINT ["/app/crowsnest"]
CMD ["serve"]
