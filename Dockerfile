# syntax=docker/dockerfile:1
FROM golang:1.21-alpine AS builder

# Установка git и ca-certificates (могут понадобиться для загрузки некоторых go-модулей)
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# 1. Копируем файлы модулей И хэшей (если go.sum еще нет, скопируется только go.mod)
COPY go.mod go.sum* ./

# 2. Скачиваем зависимости в кэш Docker
RUN go mod download

# 3. ТОЛЬКО ТЕПЕРЬ копируем весь остальной исходный код
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
