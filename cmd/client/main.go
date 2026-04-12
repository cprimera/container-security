// Package main implements the container-security client.
//
// The client sends Keychain requests over a Unix domain socket to the server,
// printing the response to stdout/stderr and exiting with the same exit code.
//
// Usage:
//
//	container-client [-socket <path>] <command> [flags]
//
// Global flags:
//
//	-socket  Path of the Unix domain socket to connect to.
//	         Defaults to /tmp/container-security.sock.
//
// Commands:
//
//	find-generic-password    Find a generic keychain password item.
//	  -a <account>  Match account name
//	  -s <service>  Match service name
//	  -l <label>    Match label
//	  -g            Display the password in the results
//	  -w            Output password only (to stdout)
//
//	find-internet-password   Find an internet keychain password item.
//	  -a <account>  Match account name
//	  -s <server>   Match server name
//	  -l <label>    Match label
//	  -g            Display the password in the results
//	  -w            Output password only (to stdout)
//
//	add-generic-password     Add a generic keychain password item.
//	  -a <account>  Account name
//	  -s <service>  Service name
//	  -l <label>    Label
//	  -w <password> Password data
//	  -U            Update item if it already exists
//
//	add-internet-password    Add an internet keychain password item.
//	  -a <account>  Account name
//	  -s <server>   Server name
//	  -l <label>    Label
//	  -w <password> Password data
//	  -U            Update item if it already exists
//
//	delete-generic-password  Delete a generic keychain password item.
//	  -a <account>  Match account name
//	  -s <service>  Match service name
//
//	delete-internet-password Delete an internet keychain password item.
//	  -a <account>  Match account name
//	  -s <server>   Match server name
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/cprimera/container-security/internal/command"
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

// run sends the provided args to the server and returns the exit code.
// Separating this from main allows tests to exercise run without os.Exit.
func run(args []string) int {
	progName := filepath.Base(os.Args[0])
	fs := flag.NewFlagSet(progName, flag.ContinueOnError)
	socketPath := fs.String("socket", socket.DefaultSocketPath, "Unix domain socket path")
	showVersion := fs.Bool("version", false, "Print version information and exit")
	fs.Usage = func() { printUsage(fs, progName) }

	if err := fs.Parse(args); err != nil {
		// flag already printed the error.
		return 2
	}

	if *showVersion {
		fmt.Fprintf(os.Stdout, "%s version %s (commit %s)\n", progName, version, commit)
		return 0
	}

	subcmdArgs := fs.Args()
	if len(subcmdArgs) == 0 {
		printUsage(fs, progName)
		return 2
	}

	subcmd := subcmdArgs[0]
	subFlags := subcmdArgs[1:]

	// Validate the subcommand and its flags before making a network call.
	if err := parseSubcommand(subcmd, subFlags); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	code, err := sendRequest(*socketPath, subcmdArgs)
	if err != nil {
		log.Printf("client error: %v", err)
		return 1
	}
	return code
}

// printUsage prints full usage information to stderr.
func printUsage(fs *flag.FlagSet, progName string) {
	fmt.Fprintf(os.Stderr, "Usage: %s [-socket <path>] <command> [flags]\n\n", progName)
	fmt.Fprintf(os.Stderr, "Global flags:\n")
	fs.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nCommands:\n")
	for _, sub := range command.Subcommands() {
		fmt.Fprintf(os.Stderr, "\n  %s\n", sub.Name())
		sub.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(os.Stderr, "    -%s\t%s\n", f.Name, f.Usage)
		})
	}
}

// parseSubcommand validates the subcommand name and its flags.
// It returns an error if the subcommand is unknown or its flags are invalid.
// The FlagSet output is redirected to io.Discard so the flag package does not
// write to stderr; run() emits a single error message from the returned error.
func parseSubcommand(subcmd string, args []string) error {
	fs := command.FlagSet(subcmd)
	if fs == nil {
		return fmt.Errorf("security: unknown command '%s'", subcmd)
	}
	fs.SetOutput(io.Discard)
	return fs.Parse(args)
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
