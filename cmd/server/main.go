// Package main implements the container-security server.
//
// The server listens on a Unix domain socket and handles incoming connections
// from the client. For each connection it reads a SecurityRequest protobuf
// message, calls the macOS Keychain APIs directly via go-keychain, and writes
// a SecurityResponse protobuf message with the output back to the client.
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
	"os/signal"
	"path/filepath"
	"syscall"

	pb "github.com/cprimera/container-security/internal/proto"
	"github.com/cprimera/container-security/internal/socket"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	progName := filepath.Base(os.Args[0])
	fs := flag.NewFlagSet(progName, flag.ContinueOnError)
	socketPath := fs.String("socket", socket.DefaultSocketPath, "Unix domain socket path")
	showVersion := fs.Bool("version", false, "Print version information and exit")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n\n", progName)
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintf(os.Stdout, "%s version %s (commit %s)\n", progName, version, commit)
		return 0
	}

	if err := serve(*socketPath); err != nil {
		log.Printf("server: %v", err)
		return 1
	}

	return 0
}

// serve starts the server and blocks until the process is interrupted.
func serve(socketPath string) error {
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

// executor is a function that performs a Keychain operation and returns a response.
type executor func(args []string) *pb.SecurityResponse

// handleConn processes a single client connection using keychainExecutor.
func handleConn(conn net.Conn) {
	handleConnWithExecutor(conn, keychainExecutor)
}

// handleConnWithExecutor processes a single client connection using the
// provided executor function.  It is separated from handleConn to allow tests
// to inject a stub executor without requiring a macOS Keychain.
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
