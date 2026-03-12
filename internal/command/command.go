// Package command defines the supported keychain subcommands, their flags, and
// typed arg structs used by both the client (for validation) and the server
// (for execution). Both sides import this package so flag names and
// descriptions remain in sync.
package command

import (
	"errors"
	"flag"
	"strings"
)

// Subcommand name constants.
const (
	FindGenericPassword    = "find-generic-password"
	FindInternetPassword   = "find-internet-password"
	AddGenericPassword     = "add-generic-password"
	AddInternetPassword    = "add-internet-password"
	DeleteGenericPassword  = "delete-generic-password"
	DeleteInternetPassword = "delete-internet-password"
)

// FindGenericPasswordArgs holds the parsed flags for find-generic-password.
type FindGenericPasswordArgs struct {
	Account      string
	Service      string
	Label        string
	ShowPassword bool // -g: include password in verbose output; ignored when PasswordOnly is true
	PasswordOnly bool // -w: output password only (takes precedence over ShowPassword)
}

// FindInternetPasswordArgs holds the parsed flags for find-internet-password.
type FindInternetPasswordArgs struct {
	Account      string
	Server       string
	Label        string
	ShowPassword bool // -g: include password in verbose output; ignored when PasswordOnly is true
	PasswordOnly bool // -w: output password only (takes precedence over ShowPassword)
}

// AddGenericPasswordArgs holds the parsed flags for add-generic-password.
type AddGenericPasswordArgs struct {
	Account  string
	Service  string
	Label    string
	Password string
	Update   bool // -U: update if exists
}

// AddInternetPasswordArgs holds the parsed flags for add-internet-password.
type AddInternetPasswordArgs struct {
	Account  string
	Server   string
	Label    string
	Password string
	Update   bool // -U: update if exists
}

// DeleteGenericPasswordArgs holds the parsed flags for delete-generic-password.
type DeleteGenericPasswordArgs struct {
	Account string
	Service string
}

// DeleteInternetPasswordArgs holds the parsed flags for delete-internet-password.
type DeleteInternetPasswordArgs struct {
	Account string
	Server  string
}

// Subcommands returns a fresh [flag.FlagSet] for each supported subcommand.
// These are suitable for client-side flag validation and usage display.
func Subcommands() []*flag.FlagSet {
	return []*flag.FlagSet{
		newFindGenericPasswordFlagSet(),
		newFindInternetPasswordFlagSet(),
		newAddGenericPasswordFlagSet(),
		newAddInternetPasswordFlagSet(),
		newDeleteGenericPasswordFlagSet(),
		newDeleteInternetPasswordFlagSet(),
	}
}

// FlagSet returns a configured [flag.FlagSet] for the named subcommand, or
// nil if the name is not recognised.
func FlagSet(name string) *flag.FlagSet {
	for _, fs := range Subcommands() {
		if fs.Name() == name {
			return fs
		}
	}
	return nil
}

// ParseFindGenericPassword parses args and returns the typed flag values.
func ParseFindGenericPassword(args []string) (FindGenericPasswordArgs, error) {
	fs := newFindGenericPasswordFlagSet()
	if err := parseFS(fs, args); err != nil {
		return FindGenericPasswordArgs{}, err
	}
	return FindGenericPasswordArgs{
		Account:      strFlag(fs, "a"),
		Service:      strFlag(fs, "s"),
		Label:        strFlag(fs, "l"),
		ShowPassword: boolFlag(fs, "g"),
		PasswordOnly: boolFlag(fs, "w"),
	}, nil
}

// ParseFindInternetPassword parses args and returns the typed flag values.
func ParseFindInternetPassword(args []string) (FindInternetPasswordArgs, error) {
	fs := newFindInternetPasswordFlagSet()
	if err := parseFS(fs, args); err != nil {
		return FindInternetPasswordArgs{}, err
	}
	return FindInternetPasswordArgs{
		Account:      strFlag(fs, "a"),
		Server:       strFlag(fs, "s"),
		Label:        strFlag(fs, "l"),
		ShowPassword: boolFlag(fs, "g"),
		PasswordOnly: boolFlag(fs, "w"),
	}, nil
}

// ParseAddGenericPassword parses args and returns the typed flag values.
func ParseAddGenericPassword(args []string) (AddGenericPasswordArgs, error) {
	fs := newAddGenericPasswordFlagSet()
	if err := parseFS(fs, args); err != nil {
		return AddGenericPasswordArgs{}, err
	}
	return AddGenericPasswordArgs{
		Account:  strFlag(fs, "a"),
		Service:  strFlag(fs, "s"),
		Label:    strFlag(fs, "l"),
		Password: strFlag(fs, "w"),
		Update:   boolFlag(fs, "U"),
	}, nil
}

// ParseAddInternetPassword parses args and returns the typed flag values.
func ParseAddInternetPassword(args []string) (AddInternetPasswordArgs, error) {
	fs := newAddInternetPasswordFlagSet()
	if err := parseFS(fs, args); err != nil {
		return AddInternetPasswordArgs{}, err
	}
	return AddInternetPasswordArgs{
		Account:  strFlag(fs, "a"),
		Server:   strFlag(fs, "s"),
		Label:    strFlag(fs, "l"),
		Password: strFlag(fs, "w"),
		Update:   boolFlag(fs, "U"),
	}, nil
}

// ParseDeleteGenericPassword parses args and returns the typed flag values.
func ParseDeleteGenericPassword(args []string) (DeleteGenericPasswordArgs, error) {
	fs := newDeleteGenericPasswordFlagSet()
	if err := parseFS(fs, args); err != nil {
		return DeleteGenericPasswordArgs{}, err
	}
	return DeleteGenericPasswordArgs{
		Account: strFlag(fs, "a"),
		Service: strFlag(fs, "s"),
	}, nil
}

// ParseDeleteInternetPassword parses args and returns the typed flag values.
func ParseDeleteInternetPassword(args []string) (DeleteInternetPasswordArgs, error) {
	fs := newDeleteInternetPasswordFlagSet()
	if err := parseFS(fs, args); err != nil {
		return DeleteInternetPasswordArgs{}, err
	}
	return DeleteInternetPasswordArgs{
		Account: strFlag(fs, "a"),
		Server:  strFlag(fs, "s"),
	}, nil
}

// ── canonical flag set constructors ──────────────────────────────────────────
// Each constructor is the single source of truth for a subcommand's flags.
// Both Subcommands() (client) and Parse*() (server) call these constructors.

func newFindGenericPasswordFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet(FindGenericPassword, flag.ContinueOnError)
	fs.String("a", "", "Match `account` name")
	fs.String("s", "", "Match `service` name")
	fs.String("l", "", "Match `label`")
	fs.Bool("g", false, "Display the password in the results")
	fs.Bool("w", false, "Output password only (to stdout)")
	return fs
}

func newFindInternetPasswordFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet(FindInternetPassword, flag.ContinueOnError)
	fs.String("a", "", "Match `account` name")
	fs.String("s", "", "Match `server` name")
	fs.String("l", "", "Match `label`")
	fs.Bool("g", false, "Display the password in the results")
	fs.Bool("w", false, "Output password only (to stdout)")
	return fs
}

func newAddGenericPasswordFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet(AddGenericPassword, flag.ContinueOnError)
	fs.String("a", "", "`Account` name")
	fs.String("s", "", "`Service` name")
	fs.String("l", "", "`Label`")
	fs.String("w", "", "`Password` data")
	fs.Bool("U", false, "Update item if it already exists")
	return fs
}

func newAddInternetPasswordFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet(AddInternetPassword, flag.ContinueOnError)
	fs.String("a", "", "`Account` name")
	fs.String("s", "", "`Server` name")
	fs.String("l", "", "`Label`")
	fs.String("w", "", "`Password` data")
	fs.Bool("U", false, "Update item if it already exists")
	return fs
}

func newDeleteGenericPasswordFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet(DeleteGenericPassword, flag.ContinueOnError)
	fs.String("a", "", "Match `account` name")
	fs.String("s", "", "Match `service` name")
	return fs
}

func newDeleteInternetPasswordFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet(DeleteInternetPassword, flag.ContinueOnError)
	fs.String("a", "", "Match `account` name")
	fs.String("s", "", "Match `server` name")
	return fs
}

// ── helpers ───────────────────────────────────────────────────────────────────

// parseFS parses args with fs, capturing the error message from fs itself.
func parseFS(fs *flag.FlagSet, args []string) error {
	var buf strings.Builder
	fs.SetOutput(&buf)
	if err := fs.Parse(args); err != nil {
		return errors.New(strings.TrimSpace(buf.String()))
	}
	return nil
}

// strFlag returns the string value of the named flag from a parsed FlagSet.
func strFlag(fs *flag.FlagSet, name string) string {
	return fs.Lookup(name).Value.String()
}

// boolFlag returns the boolean value of the named flag from a parsed FlagSet.
func boolFlag(fs *flag.FlagSet, name string) bool {
	return fs.Lookup(name).Value.String() == "true"
}
