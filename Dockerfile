FROM golang:1.23-bullseye AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod/ \
  go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod/ \
  go build -o app .

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y ca-certificates openssl
WORKDIR /app
COPY --from=builder /app/app .
EXPOSE 8080
CMD ["./app"]

