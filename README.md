# container-security
Bridge for interfacing with the macOS Keychain from a Docker container

## Overview

`container-security` is a pair of CLI tools — **server** and **client** — that
bridge a small, supported subset of macOS Keychain operations to processes
running inside a Docker container (or any other environment that cannot access
the macOS Keychain APIs directly).

Communication happens over a **Unix domain socket** using
[Protocol Buffers](https://protobuf.dev/) with a 4-byte big-endian length
prefix before every message.

```
┌───────────────────┐       Unix socket       ┌──────────────────────┐
│  container-client │ ──SecurityRequest──────► │  container-server    │
│  (inside Docker)  │ ◄──SecurityResponse───── │  (macOS host)        │
└───────────────────┘                          └──────────────────────┘
                                                       │
                                                       ▼
                                                macOS Keychain APIs
```

## Repository structure

```
.
├── proto/                      # Protobuf schema
│   └── security.proto
├── internal/
│   ├── command/                # Shared command definitions and flag parsing
│   │   ├── command.go
│   │   └── command_test.go
│   ├── proto/                  # Generated Go protobuf code (do not edit)
│   │   └── security.pb.go
│   └── socket/                 # Shared socket read/write helpers
│       ├── socket.go
│       └── socket_test.go
├── cmd/
│   ├── server/                 # Server binary
│   │   ├── main.go
│   │   ├── keychain_darwin.go
│   │   ├── keychain_other.go
│   │   └── main_test.go
│   └── client/                 # Client binary
│       ├── main.go
│       └── main_test.go
├── go.mod
├── go.sum
└── README.md
```

## Wire format

Each message (request or response) is transmitted as:

```
[ 4 bytes big-endian uint32 – message length ][ N bytes protobuf payload ]
```

## Building

### Requirements

* Go 1.24 or later
* macOS (for the real server implementation and macOS-specific builds)
* Protobuf compiler (`protoc`) and `protoc-gen-go` plugin — only required when
  regenerating `internal/proto/security.pb.go`

### Build the server

```bash
go build -o container-server ./cmd/server
# or
make server
```

### Build the client

```bash
go build -o container-client ./cmd/client
# or
make client
```

### Cross-compile for arm64

macOS arm64:

```bash
make build-darwin-arm64
# produces container-server-darwin-arm64 and container-client-darwin-arm64
```

Linux arm64:

```bash
make build-linux-arm64
# produces container-server-linux-arm64 and container-client-linux-arm64
```

Individual targets are also available: `server-darwin-arm64`, `client-darwin-arm64`,
`server-linux-arm64`, `client-linux-arm64`.

### Regenerate protobuf code

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
export PATH="$PATH:$(go env GOPATH)/bin"
protoc --go_out=. \
       --go_opt=module=github.com/cprimera/container-security \
       proto/security.proto
```

## Usage

### Server (macOS host)

```
container-server [-socket <path>]
```

| Flag      | Default                          | Description                    |
|-----------|----------------------------------|--------------------------------|
| `-socket` | `/tmp/container-security.sock`   | Unix domain socket to listen on |

The server removes any stale socket file on startup and cleans it up on exit.
It shuts down gracefully on `SIGINT` or `SIGTERM`.

### Client (container or any host)

```
container-client [-socket <path>] <command> [flags]
```

| Flag      | Default                          | Description                     |
|-----------|----------------------------------|---------------------------------|
| `-socket` | `/tmp/container-security.sock`   | Unix domain socket to connect to |

The client validates the command locally, sends it to the server, prints the
server's stdout/stderr verbatim, and exits with the same exit code returned by
the server.

Supported commands:

* `find-generic-password`
* `find-internet-password`
* `add-generic-password`
* `add-internet-password`
* `delete-generic-password`
* `delete-internet-password`

#### Examples

```bash
# Look up a password
container-client find-generic-password -s my-service -w

# Add or update a password
container-client add-generic-password -a alice -s my-service -w secret -U

# Use a custom socket path
container-client -socket /var/run/cs.sock find-internet-password -s example.com
```

## Testing

Run the complete test suite:

```bash
go test ./...
```

Test individual packages:

```bash
go test ./internal/socket/          # socket read/write helpers
go test ./internal/command/         # shared command parsing
go test ./cmd/server/               # server handlers
go test ./cmd/client/               # client logic
```

Run a single test:

```bash
go test ./cmd/client -run TestRunSuccess
go test ./cmd/server -run TestHandleConnRoundTrip
```

## Security considerations

* The server performs supported keychain operations on behalf of the client.
  Ensure the Unix domain socket is accessible only to trusted processes
  (e.g. restrict permissions with `chmod 0600`).
* Normal macOS Keychain authorization checks still apply when the request is
  handled through the server. Accessing protected items can still trigger the
  usual password or approval prompts.
* The socket path can be overridden with the `-socket` flag on both binaries.
