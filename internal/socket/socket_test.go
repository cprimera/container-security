package socket_test

import (
	"net"
	"testing"

	pb "github.com/cprimera/container-security/internal/proto"
	"github.com/cprimera/container-security/internal/socket"
)

// newPipe returns a connected pair of net.Conn backed by an in-memory pipe.
func newPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() {
		c1.Close()
		c2.Close()
	})
	return c1, c2
}

func TestWriteReadRequest(t *testing.T) {
	c1, c2 := newPipe(t)

	want := &pb.SecurityRequest{Args: []string{"find-generic-password", "-s", "my-service"}}

	errCh := make(chan error, 1)
	go func() {
		errCh <- socket.WriteMessage(c1, want)
		c1.Close()
	}()

	got := &pb.SecurityRequest{}
	if err := socket.ReadMessage(c2, got); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	if len(got.Args) != len(want.Args) {
		t.Fatalf("args length mismatch: got %d, want %d", len(got.Args), len(want.Args))
	}
	for i, a := range want.Args {
		if got.Args[i] != a {
			t.Errorf("args[%d]: got %q, want %q", i, got.Args[i], a)
		}
	}
}

func TestWriteReadResponse(t *testing.T) {
	c1, c2 := newPipe(t)

	want := &pb.SecurityResponse{
		Stdout:   "password: secret\n",
		Stderr:   "",
		ExitCode: 0,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- socket.WriteMessage(c1, want)
		c1.Close()
	}()

	got := &pb.SecurityResponse{}
	if err := socket.ReadMessage(c2, got); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	if got.Stdout != want.Stdout {
		t.Errorf("stdout: got %q, want %q", got.Stdout, want.Stdout)
	}
	if got.Stderr != want.Stderr {
		t.Errorf("stderr: got %q, want %q", got.Stderr, want.Stderr)
	}
	if got.ExitCode != want.ExitCode {
		t.Errorf("exit_code: got %d, want %d", got.ExitCode, want.ExitCode)
	}
}

func TestReadMessageTooLarge(t *testing.T) {
	c1, c2 := newPipe(t)

	// Write a manually crafted length prefix that exceeds maxMessageSize.
	go func() {
		// 17 MiB – larger than the 16 MiB limit
		tooLarge := uint32(17 * 1024 * 1024)
		buf := []byte{
			byte(tooLarge >> 24),
			byte(tooLarge >> 16),
			byte(tooLarge >> 8),
			byte(tooLarge),
		}
		c1.Write(buf) //nolint:errcheck
		c1.Close()
	}()

	got := &pb.SecurityRequest{}
	err := socket.ReadMessage(c2, got)
	if err == nil {
		t.Fatal("expected error for oversized message, got nil")
	}
}

func TestRoundTrip(t *testing.T) {
	c1, c2 := newPipe(t)

	req := &pb.SecurityRequest{Args: []string{"list-keychains"}}
	resp := &pb.SecurityResponse{Stdout: "login.keychain\n", ExitCode: 0}

	// Write request from c1, read from c2.
	errCh := make(chan error, 2)
	go func() {
		errCh <- socket.WriteMessage(c1, req)
	}()
	gotReq := &pb.SecurityRequest{}
	if err := socket.ReadMessage(c2, gotReq); err != nil {
		t.Fatalf("ReadMessage(req): %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("WriteMessage(req): %v", err)
	}

	// Write response from c2, read from c1.
	go func() {
		errCh <- socket.WriteMessage(c2, resp)
	}()
	gotResp := &pb.SecurityResponse{}
	if err := socket.ReadMessage(c1, gotResp); err != nil {
		t.Fatalf("ReadMessage(resp): %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("WriteMessage(resp): %v", err)
	}

	if gotResp.Stdout != resp.Stdout {
		t.Errorf("stdout mismatch: got %q, want %q", gotResp.Stdout, resp.Stdout)
	}
}
