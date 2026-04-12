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
* [GoReleaser](https://goreleaser.com/) v2 or later for project builds
* macOS (for the real server implementation and macOS-specific builds)
* Protobuf compiler (`protoc`) and `protoc-gen-go` plugin — only required when
  regenerating `internal/proto/security.pb.go`

### Build the project

```bash
make all
# or
goreleaser build --snapshot --clean
```

This builds the GoReleaser matrix configured in `.goreleaser.yaml` into `dist/`.
On this branch that means:

* `container-client` for darwin/linux on amd64 and arm64
* `container-server` for darwin on amd64 and arm64

Because the server build is CGO-backed and darwin-only, run this on a macOS
host.

### Build the server

```bash
make server
```

This uses GoReleaser to build the current-platform `container-server` binary
into `dist/`. Since the server target is darwin-only, run this on a macOS host.

### Build the client

```bash
make client
```

This uses GoReleaser to build the current-platform `container-client` binary
into `dist/`.

### Build release archives locally

```bash
goreleaser release --snapshot --clean
```

This produces the full archive/checksum set under `dist/` without publishing a
GitHub release. Because the darwin server build is CGO-backed, run this on a
macOS host for the full release matrix.

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

| Flag        | Default                        | Description                         |
|-------------|--------------------------------|-------------------------------------|
| `-socket`   | `/tmp/container-security.sock` | Unix domain socket to listen on     |
| `-version`  |                                | Print version and commit information |

The server removes any stale socket file on startup and cleans it up on exit.
It shuts down gracefully on `SIGINT` or `SIGTERM`.

### Client (container or any host)

```
container-client [-socket <path>] <command> [flags]
```

| Flag        | Default                        | Description                         |
|-------------|--------------------------------|-------------------------------------|
| `-socket`   | `/tmp/container-security.sock` | Unix domain socket to connect to    |
| `-version`  |                                | Print version and commit information |

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
# Show build version information
container-client -version

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
go test ./cmd/client -run TestRunVersion
go test ./cmd/server -run TestRunVersion
```

## Security considerations

* The server performs supported keychain operations on behalf of the client.
  Ensure the Unix domain socket is accessible only to trusted processes
  (e.g. restrict permissions with `chmod 0600`).
* Normal macOS Keychain authorization checks still apply when the request is
  handled through the server. Accessing protected items can still trigger the
  usual password or approval prompts.
* The socket path can be overridden with the `-socket` flag on both binaries.
