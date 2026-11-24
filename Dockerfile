# No BuildKit-only features (RUN --mount): Cloud Run builds repositories with
# the classic docker build.

# ── 1. Web UI (Vue + Keston UI) ─────────────────────────────────────────────
FROM node:24-alpine AS web
WORKDIR /web
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
# The footer shows the build: pass the commit with --build-arg APP_BUILD=<sha>.
ARG APP_BUILD=""
ENV APP_BUILD=$APP_BUILD
RUN pnpm build

# ── 2. Go binary, with the web UI embedded ──────────────────────────────────
FROM golang:1.27-alpine AS go
WORKDIR /src
COPY go.mod go.sum ./
COPY kit ./kit
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY web/embed.go ./web/
COPY --from=web /web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /keston-id ./cmd/keston-id

# ── 3. Runtime: no shell, no package manager, runs as a non-root user ───────
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go /keston-id /keston-id
COPY deploy/ /etc/keston-id/
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 CMD ["/keston-id", "healthcheck"]
ENTRYPOINT ["/keston-id"]
CMD ["serve"]
