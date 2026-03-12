// Package main implements the container-security client.
//
// The client sends Keychain requests over a Unix domain socket to the server,
// printing the response to stdout/stderr and exiting with the same exit code.
//
// Usage:
//
//	client [-socket <path>] <command> [flags]
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
//	  -w            Output password only (to stdout)
//
//	find-internet-password   Find an internet keychain password item.
//	  -a <account>  Match account name
//	  -s <server>   Match server name
//	  -l <label>    Match label
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
	fs.Usage = func() { printUsage(fs) }

	if err := fs.Parse(args); err != nil {
		// flag already printed the error.
		return 2
	}

	subcmdArgs := fs.Args()
	if len(subcmdArgs) == 0 {
		printUsage(fs)
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
func printUsage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, "Usage: client [-socket <path>] <command> [flags]\n\n")
	fmt.Fprintf(os.Stderr, "Global flags:\n")
	fs.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nCommands:\n")
	for _, sub := range subcommandFlagSets() {
		fmt.Fprintf(os.Stderr, "\n  %s\n", sub.Name())
		sub.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(os.Stderr, "    -%s\t%s\n", f.Name, f.Usage)
		})
	}
}

// parseSubcommand validates the subcommand name and its flags.
// It returns an error if the subcommand is unknown or its flags are invalid.
func parseSubcommand(subcmd string, args []string) error {
	fs := subcommandFlags(subcmd)
	if fs == nil {
		return fmt.Errorf("security: unknown command '%s'", subcmd)
	}
	return fs.Parse(args)
}

// subcommandFlags returns a configured FlagSet for the given subcommand, or
// nil if the subcommand is not recognised.
func subcommandFlags(subcmd string) *flag.FlagSet {
	for _, fs := range subcommandFlagSets() {
		if fs.Name() == subcmd {
			return fs
		}
	}
	return nil
}

// subcommandFlagSets returns flag sets for every supported subcommand.
func subcommandFlagSets() []*flag.FlagSet {
	findGeneric := flag.NewFlagSet("find-generic-password", flag.ContinueOnError)
	findGeneric.String("a", "", "Match `account` name")
	findGeneric.String("s", "", "Match `service` name")
	findGeneric.String("l", "", "Match `label`")
	findGeneric.Bool("w", false, "Output password only (to stdout)")

	findInternet := flag.NewFlagSet("find-internet-password", flag.ContinueOnError)
	findInternet.String("a", "", "Match `account` name")
	findInternet.String("s", "", "Match `server` name")
	findInternet.String("l", "", "Match `label`")
	findInternet.Bool("w", false, "Output password only (to stdout)")

	addGeneric := flag.NewFlagSet("add-generic-password", flag.ContinueOnError)
	addGeneric.String("a", "", "`Account` name")
	addGeneric.String("s", "", "`Service` name")
	addGeneric.String("l", "", "`Label`")
	addGeneric.String("w", "", "`Password` data")
	addGeneric.Bool("U", false, "Update item if it already exists")

	addInternet := flag.NewFlagSet("add-internet-password", flag.ContinueOnError)
	addInternet.String("a", "", "`Account` name")
	addInternet.String("s", "", "`Server` name")
	addInternet.String("l", "", "`Label`")
	addInternet.String("w", "", "`Password` data")
	addInternet.Bool("U", false, "Update item if it already exists")

	deleteGeneric := flag.NewFlagSet("delete-generic-password", flag.ContinueOnError)
	deleteGeneric.String("a", "", "Match `account` name")
	deleteGeneric.String("s", "", "Match `service` name")

	deleteInternet := flag.NewFlagSet("delete-internet-password", flag.ContinueOnError)
	deleteInternet.String("a", "", "Match `account` name")
	deleteInternet.String("s", "", "Match `server` name")

	return []*flag.FlagSet{
		findGeneric,
		findInternet,
		addGeneric,
		addInternet,
		deleteGeneric,
		deleteInternet,
	}
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
