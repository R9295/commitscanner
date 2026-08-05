GO ?= go
BUILD_FLAGS := -trimpath -ldflags=-s -ldflags=-w

.PHONY: all build test dist clean

all: test build

build:
	$(GO) build -o gitsecscan .

test:
	$(GO) vet ./...
	$(GO) test ./...

# Static, CGO-free binaries. The scanner shells out to git, so the host still
# needs git on PATH; nothing else is required at runtime.
dist:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 $(GO) build -trimpath -ldflags="-s -w" -o dist/gitsecscan-linux-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags="-s -w" -o dist/gitsecscan-darwin-arm64 .

clean:
	rm -rf dist gitsecscan
