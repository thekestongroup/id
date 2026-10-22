.PHONY: web build run clean

# Build the Vue login/consent UI (outputs to web/dist, embedded by Go).
web:
	cd web && pnpm install && pnpm build

# Build the Go binary (requires web/dist to exist for go:embed).
build: web
	go build -o keston-id .

run: build
	./keston-id

clean:
	rm -f keston-id
	rm -rf web/dist
