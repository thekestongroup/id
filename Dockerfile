# syntax=docker/dockerfile:1

# ---- Stage 1: build the login/consent web UI ----
FROM node:22-alpine AS web
WORKDIR /app
COPY web/package.json web/pnpm-lock.yaml web/.npmrc ./
RUN corepack enable && corepack prepare pnpm@11.6.0 --activate && pnpm install
COPY web/ ./
RUN pnpm build

# ---- Stage 2: build the Go binary ----
FROM golang:1.27-alpine AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
COPY --from=web /app/dist ./web/dist
RUN CGO_ENABLED=0 go build -o /keston-id .

# ---- Stage 3: runtime ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /keston-id .
EXPOSE 4444
ENTRYPOINT ["/app/keston-id"]
