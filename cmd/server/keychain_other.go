//go:build !darwin

package main

import (
	"fmt"

	pb "github.com/cprimera/container-security/internal/proto"
)

// keychainExecutor is a stub for non-Darwin platforms. Direct Keychain
// integration is only available on macOS; the server is intended to run there.
func keychainExecutor(args []string) *pb.SecurityResponse {
	return &pb.SecurityResponse{
		Stderr:   fmt.Sprintf("security: Keychain access is only supported on macOS (got %d arg(s))\n", len(args)),
		ExitCode: 1,
	}
}
