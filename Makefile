.PHONY: all build server client test proto clean

all: build

## Build both binaries
build: server client

## Build only the server binary
server:
	go build -o container-server ./cmd/server

## Build only the client binary
client:
	go build -o container-client ./cmd/client

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
	rm -f container-server container-client
