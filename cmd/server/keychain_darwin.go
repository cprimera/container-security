//go:build darwin

package main

import (
	"flag"
	"fmt"
	"strings"

	keychain "github.com/keybase/go-keychain"

	pb "github.com/cprimera/container-security/internal/proto"
)

// keychainExecutor implements the executor interface by calling macOS Keychain
// APIs directly via go-keychain instead of shelling out to the security CLI.
func keychainExecutor(args []string) *pb.SecurityResponse {
	if len(args) == 0 {
		return &pb.SecurityResponse{
			Stderr:   "Usage: security [-hilqvx] [-p prompt] [command] [opt ...]\n",
			ExitCode: 2,
		}
	}

	switch args[0] {
	case "find-generic-password":
		return keychainFindGenericPassword(args[1:])
	case "find-internet-password":
		return keychainFindInternetPassword(args[1:])
	case "add-generic-password":
		return keychainAddGenericPassword(args[1:])
	case "add-internet-password":
		return keychainAddInternetPassword(args[1:])
	case "delete-generic-password":
		return keychainDeleteGenericPassword(args[1:])
	case "delete-internet-password":
		return keychainDeleteInternetPassword(args[1:])
	default:
		return &pb.SecurityResponse{
			Stderr:   fmt.Sprintf("security: unknown command '%s'\n", args[0]),
			ExitCode: 2,
		}
	}
}

// keychainErrResponse converts a go-keychain error into a SecurityResponse
// with exit codes that match those produced by the macOS security CLI.
func keychainErrResponse(op string, err error) *pb.SecurityResponse {
	switch err {
	case keychain.ErrorItemNotFound:
		return &pb.SecurityResponse{
			Stderr:   fmt.Sprintf("security: %s: The specified item could not be found in the keychain.\n", op),
			ExitCode: 44,
		}
	case keychain.ErrorDuplicateItem:
		return &pb.SecurityResponse{
			Stderr:   fmt.Sprintf("security: %s: The specified item already exists in the keychain.\n", op),
			ExitCode: 45,
		}
	case keychain.ErrorInteractionNotAllowed:
		return &pb.SecurityResponse{
			Stderr:   fmt.Sprintf("security: %s: User interaction is not allowed.\n", op),
			ExitCode: 36,
		}
	default:
		return &pb.SecurityResponse{
			Stderr:   fmt.Sprintf("security: %s: %v\n", op, err),
			ExitCode: 1,
		}
	}
}

// keychainFindGenericPassword handles the find-generic-password subcommand.
// Flags supported: -a (account), -s (service), -l (label), -w (password only).
func keychainFindGenericPassword(args []string) *pb.SecurityResponse {
	fs := flag.NewFlagSet("find-generic-password", flag.ContinueOnError)
	account := fs.String("a", "", "account name")
	service := fs.String("s", "", "service name")
	label := fs.String("l", "", "label")
	passwordOnly := fs.Bool("w", false, "output password to stdout only")

	var buf strings.Builder
	fs.SetOutput(&buf)
	if err := fs.Parse(args); err != nil {
		return &pb.SecurityResponse{Stderr: buf.String(), ExitCode: 2}
	}

	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	if *account != "" {
		query.SetAccount(*account)
	}
	if *service != "" {
		query.SetService(*service)
	}
	if *label != "" {
		query.SetLabel(*label)
	}
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)
	query.SetReturnAttributes(true)

	results, err := keychain.QueryItem(query)
	if err != nil {
		return keychainErrResponse("SecKeychainSearchCopyNext", err)
	}
	if len(results) == 0 {
		return &pb.SecurityResponse{
			Stderr:   "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n",
			ExitCode: 44,
		}
	}

	r := results[0]
	if *passwordOnly {
		return &pb.SecurityResponse{Stdout: string(r.Data) + "\n"}
	}

	var sb strings.Builder
	sb.WriteString("class: \"genp\"\n")
	sb.WriteString("attributes:\n")
	if r.Account != "" {
		sb.WriteString(fmt.Sprintf("    \"acct\"<blob>=%q\n", r.Account))
	}
	if r.Service != "" {
		sb.WriteString(fmt.Sprintf("    \"svce\"<blob>=%q\n", r.Service))
	}
	if r.Label != "" {
		sb.WriteString(fmt.Sprintf("    \"labl\"<blob>=%q\n", r.Label))
	}
	sb.WriteString(fmt.Sprintf("password: %q\n", string(r.Data)))
	return &pb.SecurityResponse{Stdout: sb.String()}
}

// keychainFindInternetPassword handles the find-internet-password subcommand.
// Flags supported: -a (account), -s (server), -l (label), -w (password only).
func keychainFindInternetPassword(args []string) *pb.SecurityResponse {
	fs := flag.NewFlagSet("find-internet-password", flag.ContinueOnError)
	account := fs.String("a", "", "account name")
	server := fs.String("s", "", "server name")
	label := fs.String("l", "", "label")
	passwordOnly := fs.Bool("w", false, "output password to stdout only")

	var buf strings.Builder
	fs.SetOutput(&buf)
	if err := fs.Parse(args); err != nil {
		return &pb.SecurityResponse{Stderr: buf.String(), ExitCode: 2}
	}

	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassInternetPassword)
	if *account != "" {
		query.SetAccount(*account)
	}
	if *server != "" {
		query.SetServer(*server)
	}
	if *label != "" {
		query.SetLabel(*label)
	}
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)
	query.SetReturnAttributes(true)

	results, err := keychain.QueryItem(query)
	if err != nil {
		return keychainErrResponse("SecKeychainSearchCopyNext", err)
	}
	if len(results) == 0 {
		return &pb.SecurityResponse{
			Stderr:   "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n",
			ExitCode: 44,
		}
	}

	r := results[0]
	if *passwordOnly {
		return &pb.SecurityResponse{Stdout: string(r.Data) + "\n"}
	}

	var sb strings.Builder
	sb.WriteString("class: \"inet\"\n")
	sb.WriteString("attributes:\n")
	if r.Account != "" {
		sb.WriteString(fmt.Sprintf("    \"acct\"<blob>=%q\n", r.Account))
	}
	if r.Server != "" {
		sb.WriteString(fmt.Sprintf("    \"srvr\"<blob>=%q\n", r.Server))
	}
	if r.Label != "" {
		sb.WriteString(fmt.Sprintf("    \"labl\"<blob>=%q\n", r.Label))
	}
	sb.WriteString(fmt.Sprintf("password: %q\n", string(r.Data)))
	return &pb.SecurityResponse{Stdout: sb.String()}
}

// keychainAddGenericPassword handles the add-generic-password subcommand.
// Flags supported: -a (account), -s (service), -l (label), -w (password), -U (update if exists).
func keychainAddGenericPassword(args []string) *pb.SecurityResponse {
	fs := flag.NewFlagSet("add-generic-password", flag.ContinueOnError)
	account := fs.String("a", "", "account name")
	service := fs.String("s", "", "service name")
	label := fs.String("l", "", "label")
	password := fs.String("w", "", "password data")
	update := fs.Bool("U", false, "update item if it already exists")

	var buf strings.Builder
	fs.SetOutput(&buf)
	if err := fs.Parse(args); err != nil {
		return &pb.SecurityResponse{Stderr: buf.String(), ExitCode: 2}
	}

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	if *account != "" {
		item.SetAccount(*account)
	}
	if *service != "" {
		item.SetService(*service)
	}
	if *label != "" {
		item.SetLabel(*label)
	}
	item.SetData([]byte(*password))
	item.SetAccessible(keychain.AccessibleWhenUnlocked)

	err := keychain.AddItem(item)
	if err == keychain.ErrorDuplicateItem && *update {
		query := keychain.NewItem()
		query.SetSecClass(keychain.SecClassGenericPassword)
		if *account != "" {
			query.SetAccount(*account)
		}
		if *service != "" {
			query.SetService(*service)
		}
		updateItem := keychain.NewItem()
		updateItem.SetData([]byte(*password))
		if *label != "" {
			updateItem.SetLabel(*label)
		}
		err = keychain.UpdateItem(query, updateItem)
	}
	if err != nil {
		return keychainErrResponse("SecKeychainAddGenericPassword", err)
	}
	return &pb.SecurityResponse{}
}

// keychainAddInternetPassword handles the add-internet-password subcommand.
// Flags supported: -a (account), -s (server), -l (label), -w (password), -U (update if exists).
func keychainAddInternetPassword(args []string) *pb.SecurityResponse {
	fs := flag.NewFlagSet("add-internet-password", flag.ContinueOnError)
	account := fs.String("a", "", "account name")
	server := fs.String("s", "", "server name")
	label := fs.String("l", "", "label")
	password := fs.String("w", "", "password data")
	update := fs.Bool("U", false, "update item if it already exists")

	var buf strings.Builder
	fs.SetOutput(&buf)
	if err := fs.Parse(args); err != nil {
		return &pb.SecurityResponse{Stderr: buf.String(), ExitCode: 2}
	}

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassInternetPassword)
	if *account != "" {
		item.SetAccount(*account)
	}
	if *server != "" {
		item.SetServer(*server)
	}
	if *label != "" {
		item.SetLabel(*label)
	}
	item.SetData([]byte(*password))
	item.SetAccessible(keychain.AccessibleWhenUnlocked)

	err := keychain.AddItem(item)
	if err == keychain.ErrorDuplicateItem && *update {
		query := keychain.NewItem()
		query.SetSecClass(keychain.SecClassInternetPassword)
		if *account != "" {
			query.SetAccount(*account)
		}
		if *server != "" {
			query.SetServer(*server)
		}
		updateItem := keychain.NewItem()
		updateItem.SetData([]byte(*password))
		if *label != "" {
			updateItem.SetLabel(*label)
		}
		err = keychain.UpdateItem(query, updateItem)
	}
	if err != nil {
		return keychainErrResponse("SecKeychainAddInternetPassword", err)
	}
	return &pb.SecurityResponse{}
}

// keychainDeleteGenericPassword handles the delete-generic-password subcommand.
// Flags supported: -a (account), -s (service).
func keychainDeleteGenericPassword(args []string) *pb.SecurityResponse {
	fs := flag.NewFlagSet("delete-generic-password", flag.ContinueOnError)
	account := fs.String("a", "", "account name")
	service := fs.String("s", "", "service name")

	var buf strings.Builder
	fs.SetOutput(&buf)
	if err := fs.Parse(args); err != nil {
		return &pb.SecurityResponse{Stderr: buf.String(), ExitCode: 2}
	}

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	if *account != "" {
		item.SetAccount(*account)
	}
	if *service != "" {
		item.SetService(*service)
	}

	if err := keychain.DeleteItem(item); err != nil {
		return keychainErrResponse("SecKeychainSearchCopyNext", err)
	}
	return &pb.SecurityResponse{}
}

// keychainDeleteInternetPassword handles the delete-internet-password subcommand.
// Flags supported: -a (account), -s (server).
func keychainDeleteInternetPassword(args []string) *pb.SecurityResponse {
	fs := flag.NewFlagSet("delete-internet-password", flag.ContinueOnError)
	account := fs.String("a", "", "account name")
	server := fs.String("s", "", "server name")

	var buf strings.Builder
	fs.SetOutput(&buf)
	if err := fs.Parse(args); err != nil {
		return &pb.SecurityResponse{Stderr: buf.String(), ExitCode: 2}
	}

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassInternetPassword)
	if *account != "" {
		item.SetAccount(*account)
	}
	if *server != "" {
		item.SetServer(*server)
	}

	if err := keychain.DeleteItem(item); err != nil {
		return keychainErrResponse("SecKeychainSearchCopyNext", err)
	}
	return &pb.SecurityResponse{}
}
