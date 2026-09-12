# Track a supported Go release; rebuild with --pull. See SELFHOSTING.md.
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS build

WORKDIR /app

COPY go.* ./
RUN go mod download

COPY . ./

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
      -ldflags='-w -s -extldflags "-static"' -a \
      -o /privacy-gateway-server

FROM gcr.io/distroless/static

ARG GIT_REVISION=unknown
LABEL revision=${GIT_REVISION}
COPY --from=build /privacy-gateway-server /privacy-gateway-server

EXPOSE 8080

CMD ["/privacy-gateway-server"]
