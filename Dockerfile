# Lanora server image.
#
# The server is one statically linked binary, so the final image holds
# nothing else: no shell, no package manager, and it does not run as root.

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=1.0.0
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X lanora/internal/version.Version=${VERSION}" \
        -o /out/lanora-server ./cmd/lanora-server \
    && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/lanora-server /usr/local/bin/lanora-server
# The data directory exists in the image and belongs to the unprivileged
# user, so a named volume mounted over it starts out writable.
COPY --from=build --chown=nonroot:nonroot /out/data /data

ENV LANORA_DATA_DIR=/data \
    LANORA_LISTEN=:8443
VOLUME /data
# One port number, two protocols: HTTPS (API, dashboard, TCP relay) and the
# UDP relay.
EXPOSE 8443/tcp 8443/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/usr/local/bin/lanora-server", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/lanora-server"]
