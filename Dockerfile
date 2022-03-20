FROM --platform=$BUILDPLATFORM golang:1.18 as build
WORKDIR /src
COPY go.mod .
RUN go mod download
ARG TARGETOS TARGETARCH
COPY . .
RUN set -x && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /out/goapp

FROM gcr.io/distroless/static-debian11:nonroot
COPY --from=build /out/goapp /app/goapp
WORKDIR /app
CMD ["/app/goapp"]
