# Base images are pinned by digest; Dependabot (docker ecosystem) proposes
# updates. The release workflow scans the result with Trivy before pushing,
# and a fixable HIGH/CRITICAL stops the release. The docker CLI and compose
# plugin are Go binaries too, so keeping the docker:*-cli stage current
# matters as much as the Go toolchain.

# Stage 1: grab Docker CLI + compose plugin binaries only (avoids installing
# the full Docker apt repo and its dependencies). Pulled for the target
# platform.
FROM docker:29.9.3-cli@sha256:2357639ad1ea7d0194134bf3292622fd4e562483966ed674e5d7c945b5f3b28d AS docker-cli

# Stage 1b: build the compose plugin from source. The released v5.7.0 binary
# (also the one inside docker:29.9.3-cli) is built with golang.org/x/net
# v0.60.0, which carries a fixable HIGH (CVE-2026-78661) and a MEDIUM
# (CVE-2026-97045) in x/net/html; no upstream binary with the fix exists yet.
# Same tag, same flags as upstream's Makefile, with only x/net bumped.
# Drop this stage (and copy docker-compose from docker-cli again) once a
# compose release ships x/net >= v0.62.0.
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS compose
ARG TARGETOS
ARG TARGETARCH
ARG COMPOSE_VERSION=v5.7.0
ARG COMPOSE_COMMIT=5bceecf985347fcf6dd23029ce440b502a0d4301
ARG XNET_VERSION=v0.62.0
RUN apk add --no-cache git
WORKDIR /compose
RUN git init -q . && git remote add origin https://github.com/docker/compose \
 && git fetch -q --depth 1 origin "$COMPOSE_COMMIT" && git checkout -q FETCH_HEAD \
 && go mod edit -require=golang.org/x/net@$XNET_VERSION && go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags e2e -ldflags "-s -w -X github.com/docker/compose/v5/internal.Version=$COMPOSE_VERSION" \
    -o /out/docker-compose ./cmd

# Stage 2: build the Go binary on the build machine's native platform and
# cross-compile for the target (no QEMU emulation of the Go toolchain).
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/crowsnest ./cmd/crowsnest

# Stage 3: minimal runtime image.
FROM alpine:3.24.4@sha256:93b41ef40b1677fce8fcc64ff4af09daddfacf5040afde618bc46c1e2d1cc7d4
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=compose /out/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
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
