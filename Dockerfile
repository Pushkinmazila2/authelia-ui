# syntax=docker/dockerfile:1
FROM golang:1.21-alpine AS builder

# Установка git и ca-certificates (могут понадобиться для загрузки некоторых go-модулей)
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Copy all source files first so go mod tidy sees all imports
COPY . .

# Download dependencies and generate valid go.sum
RUN go mod tidy && go mod download

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


