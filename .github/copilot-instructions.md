# Copilot Instructions

## Build and test commands

- `make all` builds both binaries for the current platform.
- `make server` builds `./cmd/server` as `container-server`.
- `make client` builds `./cmd/client` as `container-client`.
- `make test` runs the full Go test suite (`go test ./...`).
- Run a single package with `go test ./cmd/client`, `go test ./cmd/server`, `go test ./internal/socket`, or `go test ./internal/command`.
- Run a single test with `go test ./cmd/client -run TestRunSuccess`, `go test ./cmd/server -run TestHandleConnRoundTrip`, or the same `-run` pattern in any package.
- `make proto` regenerates `internal/proto/security.pb.go` from `proto/security.proto`.
- CI runs on `macos-latest` and executes `make test` followed by `make all`.

## High-level architecture

- This repository is a two-binary bridge for macOS Keychain access from environments like Docker containers. The client connects over a Unix domain socket, the server runs on the macOS host, and the server returns stdout, stderr, and exit code data that mirrors the underlying keychain operation.
- `proto/security.proto` defines the only wire contract: `SecurityRequest` carries argv-style arguments and `SecurityResponse` carries stdout/stderr/exit code. `internal/proto/security.pb.go` is generated from that schema.
- `internal/socket` owns the transport details for every request and response: protobuf payloads are sent with a 4-byte big-endian length prefix, and reads reject messages larger than 16 MiB.
- `cmd/client` only parses the global `-socket` flag itself. It validates supported subcommands and flags with `internal/command`, then forwards the original command arguments to the server and exits with the response exit code.
- `cmd/server` listens on the Unix socket, reads one request per connection, delegates execution through `keychainExecutor`, and writes back a `SecurityResponse`.
- The real server implementation is build-tagged in `cmd/server/keychain_darwin.go` and uses `github.com/keybase/go-keychain` directly. `cmd/server/keychain_other.go` is only a non-macOS stub, so server behavior and CI expectations are centered on macOS.

## Key conventions

- Treat `internal/command` as the single source of truth for supported operations. Adding or changing a subcommand means updating the flag-set constructors and `Parse*` helpers there so client validation, usage text, and server-side parsing stay aligned.
- For every supported subcommand, keep the client interface aligned with the macOS `security` CLI: preserve command names, flag names, precedence, exit-code expectations, and output shape unless there is a deliberate, documented reason to differ.
- When updating README or other user-facing docs, verify command examples and architecture claims against `internal/command`, `cmd/client`, and the current server implementation. Do not document the project as a generic pass-through for the full macOS `security` CLI.
- Preserve `security` CLI-style behavior when changing responses. The server returns CLI-like stderr text and exit codes for usage errors and common keychain failures, and the client prints stdout/stderr verbatim before exiting with the server-provided code.
- Keep the transport contract stable. Both binaries depend on the same protobuf schema plus the length-prefixed socket framing in `internal/socket`.
- Do not edit `internal/proto/security.pb.go` by hand; change `proto/security.proto` and regenerate it with `make proto`.
- Tests avoid real macOS keychain access whenever possible. Client tests spin up fake Unix socket servers, and server tests inject stub executors through `handleConnWithExecutor` instead of calling the real keychain implementation.
- The supported command surface is intentionally narrow: the client rejects unknown `security` subcommands before making a network call, rather than acting as a generic pass-through for the full macOS `security` CLI.
- macOS-specific build constraints matter for server work. `make build-darwin-arm64` and `make server-darwin-arm64` require a macOS host because the server depends on go-keychain and the macOS Security framework.
