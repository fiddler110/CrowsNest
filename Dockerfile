# Stage 1: grab Docker CLI + compose plugin binaries only (avoids installing
# the full Docker apt repo and its dependencies).
FROM docker:27-cli AS docker-cli

# Stage 2: build the Go binary.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/crowsnest ./cmd/crowsnest

# Stage 3: minimal runtime image.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
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
