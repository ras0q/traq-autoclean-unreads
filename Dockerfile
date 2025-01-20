FROM golang:1.23-bullseye AS builder
WORKDIR /app
RUN --mount=type=cache,target=/go/pkg/mod/ \
  --mount=type=bind,source=go.mod,target=go.mod \
  --mount=type=bind,source=go.sum,target=go.sum \
  go mod download
RUN --mount=type=cache,target=/go/pkg/mod/ \
  --mount=type=bind,target=. \
  go build -o /usr/local/bin/app

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y ca-certificates openssl
WORKDIR /app
COPY --from=builder /usr/local/bin/app .
EXPOSE 8080
CMD ["./app"]

