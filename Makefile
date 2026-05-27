BIN := bin/ossprey
PKG := ./cmd/ossprey

# -s -w strip symbol table + DWARF debug info (~30% reduction).
# -trimpath strips local build paths.
LDFLAGS := -s -w
BUILDFLAGS := -trimpath -ldflags="$(LDFLAGS)"

.PHONY: build build-debug test test-race test-smoke test-smoke-short fmt vet tidy clean

build:
	mkdir -p bin
	go build $(BUILDFLAGS) -o $(BIN) $(PKG)

build-debug:
	mkdir -p bin
	go build -o $(BIN) $(PKG)

test:
	go test ./...

test-race:
	go test -race ./...

# End-to-end smoke tests — build binary, scan static fixtures.
test-smoke:
	go test -tags smoke -v ./test/smoke/...

# Smoke tests minus slow/network (skips GitHub clone tests).
test-smoke-short:
	go test -tags smoke -short -v ./test/smoke/...

fmt:
	go fmt ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf bin
