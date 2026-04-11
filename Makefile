.PHONY: all build server client \
        server-darwin-arm64 client-darwin-arm64 build-darwin-arm64 \
        server-linux-arm64  client-linux-arm64  build-linux-arm64  \
        test proto clean

all: build

## Build both binaries for the current platform
build: server client

## Build only the server binary (current platform)
server:
	go build -o container-server ./cmd/server

## Build only the client binary (current platform)
client:
	go build -o container-client ./cmd/client

## ---------- macOS arm64 targets ----------

## Build both binaries for macOS arm64
## NOTE: The server uses go-keychain (CGO + macOS Security framework) and must
## be compiled on a macOS host. Cross-compilation from Linux is not supported.
build-darwin-arm64: server-darwin-arm64 client-darwin-arm64

## Build the server binary for macOS arm64 (must be run on a macOS host)
server-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -o container-server-darwin-arm64 ./cmd/server

## Build the client binary for macOS arm64
client-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -o container-client-darwin-arm64 ./cmd/client

## ---------- Linux arm64 targets ----------

## Build both binaries for Linux arm64
build-linux-arm64: server-linux-arm64 client-linux-arm64

## Build the server binary for Linux arm64
server-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o container-server-linux-arm64 ./cmd/server

## Build the client binary for Linux arm64
client-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o container-client-linux-arm64 ./cmd/client

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
	rm -f container-server container-client \
	      container-server-darwin-arm64 container-client-darwin-arm64 \
	      container-server-linux-arm64  container-client-linux-arm64
