// Package main implements the container-security server.
//
// The server listens on a Unix domain socket and handles incoming connections
// from the client. For each connection it reads a SecurityRequest protobuf
// message, executes the macOS `security` CLI with the provided arguments, and
// writes a SecurityResponse protobuf message with the output back to the
// client.
//
// Usage:
//
//	server [-socket <path>]
//
// Flags:
//
//	-socket  Path of the Unix domain socket to listen on.
//	         Defaults to /tmp/container-security.sock.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	pb "github.com/cprimera/container-security/internal/proto"
	"github.com/cprimera/container-security/internal/socket"
)

func main() {
	socketPath := flag.String("socket", socket.DefaultSocketPath, "Unix domain socket path")
	flag.Parse()

	if err := run(*socketPath); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// run starts the server and blocks until the process is interrupted.
func run(socketPath string) error {
	// Remove any leftover socket file from a previous run.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	defer os.Remove(socketPath)

	log.Printf("listening on %s", socketPath)

	// Shut down gracefully on SIGINT / SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		log.Println("shutting down")
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// Listener was closed – normal shutdown.
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}
		go handleConn(conn)
	}
}

// executor is a function that runs the security CLI and returns a response.
type executor func(args []string) *pb.SecurityResponse

// handleConn processes a single client connection using execSecurity.
func handleConn(conn net.Conn) {
	handleConnWithExecutor(conn, execSecurity)
}

// handleConnWithExecutor processes a single client connection using the
// provided executor function.  It is separated from handleConn to allow tests
// to inject a stub executor without requiring the macOS `security` binary.
func handleConnWithExecutor(conn net.Conn, exec executor) {
	defer conn.Close()

	req := &pb.SecurityRequest{}
	if err := socket.ReadMessage(conn, req); err != nil {
		log.Printf("read request: %v", err)
		return
	}

	resp := exec(req.Args)

	if err := socket.WriteMessage(conn, resp); err != nil {
		log.Printf("write response: %v", err)
	}
}

// execSecurity runs `security <args>` and returns the captured output.
func execSecurity(args []string) *pb.SecurityResponse {
	cmd := exec.Command("security", args...) //nolint:gosec
	stdout, err := cmd.Output()

	resp := &pb.SecurityResponse{
		Stdout: string(stdout),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			resp.Stderr = string(exitErr.Stderr)
			resp.ExitCode = int32(exitErr.ExitCode())
		} else {
			resp.Stderr = err.Error()
			resp.ExitCode = 1
		}
	}

	return resp
}
