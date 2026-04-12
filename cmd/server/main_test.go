package main

import (
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	pb "github.com/cprimera/container-security/internal/proto"
	"github.com/cprimera/container-security/internal/socket"
)

// TestHandleConn verifies that handleConn reads a request and writes a
// response over an in-memory pipe. It uses a stub executor via the
// handleConnWithExecutor helper so the test runs on any platform without
// a macOS Keychain.
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

func TestKeychainExecutorNoArgs(t *testing.T) {
	// keychainExecutor with no args should return a well-formed usage response.
	resp := keychainExecutor([]string{})
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.ExitCode == 0 {
		t.Error("expected non-zero exit code when no args are provided")
	}
	if resp.Stderr == "" {
		t.Error("expected non-empty stderr for usage error")
	}
}

func TestKeychainExecutorUnknownCommand(t *testing.T) {
	// keychainExecutor with an unsupported command should return a well-formed
	// error response rather than panicking.
	resp := keychainExecutor([]string{"list-keychains"})
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.ExitCode == 0 {
		t.Error("expected non-zero exit code for unsupported command")
	}
}

func TestRunVersion(t *testing.T) {
	oldVersion := version
	oldCommit := commit
	t.Cleanup(func() {
		version = oldVersion
		commit = oldCommit
	})
	version = "v1.2.3"
	commit = "abc1234"

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = oldStdout
	})

	code := run([]string{"-version"})
	w.Close()
	if code != 0 {
		t.Errorf("run returned exit code %d, want 0", code)
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	want := filepathBase(os.Args[0]) + " version v1.2.3 (commit abc1234)\n"
	if string(got) != want {
		t.Fatalf("version output = %q, want %q", string(got), want)
	}
}

// TestServeGracefulShutdown starts the server, sends a SIGTERM, and verifies it
// stops listening without error.
func TestServeGracefulShutdown(t *testing.T) {
	socketPath := "/tmp/cs-server-test-shutdown.sock"
	os.Remove(socketPath)

	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(socketPath)
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
			t.Errorf("serve returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("server did not shut down within 3 seconds")
	}
}

func filepathBase(path string) string {
	parts := strings.Split(path, string(os.PathSeparator))
	return parts[len(parts)-1]
}
