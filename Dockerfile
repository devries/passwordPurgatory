FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go:latest as build
WORKDIR /src
COPY go.mod .
RUN go mod download
ARG TARGETOS TARGETARCH
COPY . .
RUN set -x && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o goapp

FROM cgr.dev/chainguard/static:latest
COPY --from=build /src/goapp /app/goapp
WORKDIR /app
CMD ["/app/goapp"]
