# syntax=docker/dockerfile:1
FROM golang:1.21-alpine AS builder

WORKDIR /src
COPY go.mod ./
RUN go mod tidy

COPY . .

# Build ultra-lightweight standalone binary with no CGO
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -trimpath \
    -o /bin/authelia-ui .

FROM scratch

# Root CA certificates and binary
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /bin/authelia-ui /authelia-ui

EXPOSE 8080 2375

ENTRYPOINT ["/authelia-ui"]

