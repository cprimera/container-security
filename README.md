# container-security
Bridge for interfacing with the MacOS Keychain from a Docker container

## Overview

`container-security` is a pair of CLI tools — **server** and **client** — that
expose the macOS [`security`](https://ss64.com/osx/security.html) CLI to
processes running inside a Docker container (or any other environment that
cannot call the binary directly).

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
                                               /usr/bin/security …
```

## Repository structure

```
.
├── proto/                      # Protobuf schema
│   └── security.proto
├── internal/
│   ├── proto/                  # Generated Go protobuf code (do not edit)
│   │   └── security.pb.go
│   └── socket/                 # Shared socket read/write helpers
│       ├── socket.go
│       └── socket_test.go
├── cmd/
│   ├── server/                 # Server binary
│   │   ├── main.go
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
* macOS (for the server to call `security`)
* Protobuf compiler (`protoc`) and `protoc-gen-go` plugin — only required when
  regenerating `internal/proto/security.pb.go`

### Build the server

```bash
go build -o container-server ./cmd/server
```

### Build the client

```bash
go build -o container-client ./cmd/client
```

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
container-client [-socket <path>] [security arguments...]
```

| Flag      | Default                          | Description                     |
|-----------|----------------------------------|---------------------------------|
| `-socket` | `/tmp/container-security.sock`   | Unix domain socket to connect to |

All positional arguments after the flags are forwarded verbatim to the macOS
`security` CLI on the server. The client exits with the same exit code that
`security` returned.

#### Examples

```bash
# List keychains
container-client list-keychains

# Look up a password
container-client find-generic-password -s my-service -w

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
go test ./cmd/server/               # server handlers
go test ./cmd/client/               # client logic
```

## Security considerations

* The server executes the macOS `security` binary with arguments supplied by
  the client. Ensure the Unix domain socket is accessible only to trusted
  processes (e.g. restrict permissions with `chmod 0600`).
* The socket path can be overridden with the `-socket` flag on both binaries.
