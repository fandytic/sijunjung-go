# Build stage
FROM golang:1.22 AS builder
WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o coffee-chat cmd/server/main.go

# Final runtime stage
FROM gcr.io/distroless/base-debian12
WORKDIR /app

COPY --from=builder /app/coffee-chat /app/coffee-chat
COPY --from=builder /app/.env.example /app/.env.example

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/app/coffee-chat"]
