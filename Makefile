.PHONY: all build server client \
        test proto clean

GORELEASER ?= goreleaser
CURRENT_GOOS := $(shell go env GOOS)

all: build

## Build both binaries for the current platform
build:
	$(GORELEASER) build --snapshot --clean

## Build only the server binary (current platform)
server:
	$(GORELEASER) build --snapshot --clean --single-target --id container-server

## Build only the client binary (current platform)
client:
	$(GORELEASER) build --snapshot --clean --single-target --id container-client

## Run all tests
test:
	go test ./...

## Regenerate protobuf Go code
proto:
	protoc --go_out=. \
	       --go_opt=module=github.com/cprimera/container-security \
	       proto/security.proto

## Remove built binaries
clean:
	rm -rf dist
