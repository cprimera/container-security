package main

import (
	"net"
	"os"
	"testing"

	pb "github.com/cprimera/container-security/internal/proto"
	"github.com/cprimera/container-security/internal/socket"
)

// startFakeServer starts a Unix domain socket server at socketPath that
// responds to a single request with resp, then stops.  It returns a cleanup
// function that the caller should defer.
func startFakeServer(t *testing.T, socketPath string, resp *pb.SecurityResponse) func() {
	t.Helper()

	os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req := &pb.SecurityRequest{}
		if err := socket.ReadMessage(conn, req); err != nil {
			return
		}
		socket.WriteMessage(conn, resp) //nolint:errcheck
	}()

	return func() {
		ln.Close()
		os.Remove(socketPath)
	}
}

func TestRunSuccess(t *testing.T) {
	socketPath := "/tmp/cs-client-test-success.sock"
	want := &pb.SecurityResponse{Stdout: "login.keychain\n", ExitCode: 0}
	cleanup := startFakeServer(t, socketPath, want)
	defer cleanup()

	code := run([]string{"-socket", socketPath, "list-keychains"})
	if code != 0 {
		t.Errorf("run returned exit code %d, want 0", code)
	}
}

func TestRunNonZeroExitCode(t *testing.T) {
	socketPath := "/tmp/cs-client-test-exit.sock"
	want := &pb.SecurityResponse{
		Stdout:   "",
		Stderr:   "SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n",
		ExitCode: 44,
	}
	cleanup := startFakeServer(t, socketPath, want)
	defer cleanup()

	code := run([]string{"-socket", socketPath, "find-generic-password", "-s", "missing"})
	if code != 44 {
		t.Errorf("run returned exit code %d, want 44", code)
	}
}

func TestRunNoServer(t *testing.T) {
	// No server is listening; run should return a non-zero exit code.
	code := run([]string{"-socket", "/tmp/cs-nonexistent.sock", "list-keychains"})
	if code == 0 {
		t.Error("expected non-zero exit code when server is unreachable, got 0")
	}
}

func TestRunBadFlag(t *testing.T) {
	// An unknown flag should cause run to return exit code 2.
	code := run([]string{"--unknown-flag"})
	if code == 0 {
		t.Error("expected non-zero exit code for unknown flag, got 0")
	}
}

func TestSendRequest(t *testing.T) {
	socketPath := "/tmp/cs-client-test-send.sock"
	want := &pb.SecurityResponse{Stdout: "hello\n", ExitCode: 0}
	cleanup := startFakeServer(t, socketPath, want)
	defer cleanup()

	code, err := sendRequest(socketPath, []string{"list-keychains"})
	if err != nil {
		t.Fatalf("sendRequest: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
}
