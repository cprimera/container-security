package main

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	pb "github.com/cprimera/container-security/internal/proto"
	"github.com/cprimera/container-security/internal/socket"
)

// TestHandleConn verifies that handleConn reads a request and writes a
// response over an in-memory pipe without requiring the `security` binary.
// It uses a stub execSecurity via the handleConnWithExecutor helper so that
// the test is portable (macOS `security` is not available in CI).
func TestHandleConnRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	req := &pb.SecurityRequest{Args: []string{"list-keychains"}}
	wantResp := &pb.SecurityResponse{Stdout: "login.keychain\n", ExitCode: 0}

	// Simulate the server side in a goroutine.
	go func() {
		handleConnWithExecutor(c2, func(_ []string) *pb.SecurityResponse {
			return wantResp
		})
	}()

	// Client side: write request, read response.
	if err := socket.WriteMessage(c1, req); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	got := &pb.SecurityResponse{}
	if err := socket.ReadMessage(c1, got); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	if got.Stdout != wantResp.Stdout {
		t.Errorf("stdout: got %q, want %q", got.Stdout, wantResp.Stdout)
	}
	if got.ExitCode != wantResp.ExitCode {
		t.Errorf("exit_code: got %d, want %d", got.ExitCode, wantResp.ExitCode)
	}
}

func TestHandleConnBadRequest(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	// Close c1 immediately – the server should handle a truncated read without
	// panicking.
	c1.Close()

	// handleConnWithExecutor should return without writing anything.
	called := false
	handleConnWithExecutor(c2, func(_ []string) *pb.SecurityResponse {
		called = true
		return &pb.SecurityResponse{}
	})

	if called {
		t.Error("executor should not have been called on a bad request")
	}
}

func TestExecSecurityNotAvailable(t *testing.T) {
	// On non-macOS systems `security` is not present; we expect a non-zero
	// exit code rather than a panic.
	resp := execSecurity([]string{"list-keychains"})
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// On Linux the binary won't exist, so ExitCode should be non-zero.
	// On macOS it may succeed; either outcome is acceptable for this test.
	// We only assert that the function returns a well-formed response.
	_ = resp.ExitCode
	_ = resp.Stdout
	_ = resp.Stderr
}

// TestRunGracefulShutdown starts the server, sends a SIGTERM, and verifies it
// stops listening without error.
func TestRunGracefulShutdown(t *testing.T) {
	socketPath := "/tmp/cs-server-test-shutdown.sock"
	os.Remove(socketPath)

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(socketPath)
	}()

	// Wait for the socket to appear.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send SIGTERM to ourselves to trigger graceful shutdown.
	syscall.Kill(os.Getpid(), syscall.SIGTERM) //nolint:errcheck

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("server did not shut down within 3 seconds")
	}
}
