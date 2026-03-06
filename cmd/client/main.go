// Package main implements the container-security client.
//
// The client accepts the same arguments as the macOS `security` CLI, sends
// them over a Unix domain socket to the server, and prints the server's
// response to stdout/stderr, exiting with the same exit code returned by the
// server.
//
// Usage:
//
//	client [-socket <path>] [security arguments...]
//
// Flags:
//
//	-socket  Path of the Unix domain socket to connect to.
//	         Defaults to /tmp/container-security.sock.
//
// Examples:
//
//	client list-keychains
//	client find-generic-password -s my-service -w
//	client -socket /var/run/cs.sock find-internet-password -s example.com
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	pb "github.com/cprimera/container-security/internal/proto"
	"github.com/cprimera/container-security/internal/socket"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run sends the provided args to the server and returns the exit code.
// Separating this from main allows tests to exercise run without os.Exit.
func run(args []string) int {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	socketPath := fs.String("socket", socket.DefaultSocketPath, "Unix domain socket path")

	if err := fs.Parse(args); err != nil {
		// flag already printed the error.
		return 2
	}

	code, err := sendRequest(*socketPath, fs.Args())
	if err != nil {
		log.Printf("client error: %v", err)
		return 1
	}
	return code
}

// sendRequest connects to the server, sends a SecurityRequest with the
// provided args, and prints the response to stdout/stderr.
func sendRequest(socketPath string, args []string) (int, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return 1, fmt.Errorf("connect to %s: %w", socketPath, err)
	}
	defer conn.Close()

	req := &pb.SecurityRequest{Args: args}
	if err := socket.WriteMessage(conn, req); err != nil {
		return 1, fmt.Errorf("send request: %w", err)
	}

	resp := &pb.SecurityResponse{}
	if err := socket.ReadMessage(conn, resp); err != nil {
		return 1, fmt.Errorf("read response: %w", err)
	}

	if resp.Stdout != "" {
		fmt.Fprint(os.Stdout, resp.Stdout)
	}
	if resp.Stderr != "" {
		fmt.Fprint(os.Stderr, resp.Stderr)
	}

	return int(resp.ExitCode), nil
}
