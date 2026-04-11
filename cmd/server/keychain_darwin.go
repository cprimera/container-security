//go:build darwin

package main

import (
	"fmt"
	"strings"

	keychain "github.com/keybase/go-keychain"

	"github.com/cprimera/container-security/internal/command"
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
	case command.FindGenericPassword:
		return keychainFindGenericPassword(args[1:])
	case command.FindInternetPassword:
		return keychainFindInternetPassword(args[1:])
	case command.AddGenericPassword:
		return keychainAddGenericPassword(args[1:])
	case command.AddInternetPassword:
		return keychainAddInternetPassword(args[1:])
	case command.DeleteGenericPassword:
		return keychainDeleteGenericPassword(args[1:])
	case command.DeleteInternetPassword:
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
// Flags: -a (account), -s (service), -l (label), -g (show password), -w (password only).
func keychainFindGenericPassword(args []string) *pb.SecurityResponse {
	a, err := command.ParseFindGenericPassword(args)
	if err != nil {
		return &pb.SecurityResponse{Stderr: err.Error() + "\n", ExitCode: 2}
	}

	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	if a.Account != "" {
		query.SetAccount(a.Account)
	}
	if a.Service != "" {
		query.SetService(a.Service)
	}
	if a.Label != "" {
		query.SetLabel(a.Label)
	}
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	// Fetch password data only when the caller needs it.
	query.SetReturnData(a.PasswordOnly || a.ShowPassword)

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
	if a.PasswordOnly {
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
	if a.ShowPassword {
		sb.WriteString(fmt.Sprintf("password: %q\n", string(r.Data)))
	}
	return &pb.SecurityResponse{Stdout: sb.String()}
}

// keychainFindInternetPassword handles the find-internet-password subcommand.
// Flags: -a (account), -s (server), -l (label), -g (show password), -w (password only).
func keychainFindInternetPassword(args []string) *pb.SecurityResponse {
	a, err := command.ParseFindInternetPassword(args)
	if err != nil {
		return &pb.SecurityResponse{Stderr: err.Error() + "\n", ExitCode: 2}
	}

	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassInternetPassword)
	if a.Account != "" {
		query.SetAccount(a.Account)
	}
	if a.Server != "" {
		query.SetServer(a.Server)
	}
	if a.Label != "" {
		query.SetLabel(a.Label)
	}
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnAttributes(true)
	// Fetch password data only when the caller needs it.
	query.SetReturnData(a.PasswordOnly || a.ShowPassword)

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
	if a.PasswordOnly {
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
	if a.ShowPassword {
		sb.WriteString(fmt.Sprintf("password: %q\n", string(r.Data)))
	}
	return &pb.SecurityResponse{Stdout: sb.String()}
}

// keychainAddGenericPassword handles the add-generic-password subcommand.
// Flags: -a (account), -s (service), -l (label), -w (password), -U (update if exists).
func keychainAddGenericPassword(args []string) *pb.SecurityResponse {
	a, err := command.ParseAddGenericPassword(args)
	if err != nil {
		return &pb.SecurityResponse{Stderr: err.Error() + "\n", ExitCode: 2}
	}

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	if a.Account != "" {
		item.SetAccount(a.Account)
	}
	if a.Service != "" {
		item.SetService(a.Service)
	}
	if a.Label != "" {
		item.SetLabel(a.Label)
	}
	item.SetData([]byte(a.Password))
	item.SetAccessible(keychain.AccessibleWhenUnlocked)

	addErr := keychain.AddItem(item)
	if addErr == keychain.ErrorDuplicateItem && a.Update {
		query := keychain.NewItem()
		query.SetSecClass(keychain.SecClassGenericPassword)
		if a.Account != "" {
			query.SetAccount(a.Account)
		}
		if a.Service != "" {
			query.SetService(a.Service)
		}
		updateItem := keychain.NewItem()
		updateItem.SetData([]byte(a.Password))
		if a.Label != "" {
			updateItem.SetLabel(a.Label)
		}
		addErr = keychain.UpdateItem(query, updateItem)
	}
	if addErr != nil {
		return keychainErrResponse("SecKeychainAddGenericPassword", addErr)
	}
	return &pb.SecurityResponse{}
}

// keychainAddInternetPassword handles the add-internet-password subcommand.
// Flags: -a (account), -s (server), -l (label), -w (password), -U (update if exists).
func keychainAddInternetPassword(args []string) *pb.SecurityResponse {
	a, err := command.ParseAddInternetPassword(args)
	if err != nil {
		return &pb.SecurityResponse{Stderr: err.Error() + "\n", ExitCode: 2}
	}

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassInternetPassword)
	if a.Account != "" {
		item.SetAccount(a.Account)
	}
	if a.Server != "" {
		item.SetServer(a.Server)
	}
	if a.Label != "" {
		item.SetLabel(a.Label)
	}
	item.SetData([]byte(a.Password))
	item.SetAccessible(keychain.AccessibleWhenUnlocked)

	addErr := keychain.AddItem(item)
	if addErr == keychain.ErrorDuplicateItem && a.Update {
		query := keychain.NewItem()
		query.SetSecClass(keychain.SecClassInternetPassword)
		if a.Account != "" {
			query.SetAccount(a.Account)
		}
		if a.Server != "" {
			query.SetServer(a.Server)
		}
		updateItem := keychain.NewItem()
		updateItem.SetData([]byte(a.Password))
		if a.Label != "" {
			updateItem.SetLabel(a.Label)
		}
		addErr = keychain.UpdateItem(query, updateItem)
	}
	if addErr != nil {
		return keychainErrResponse("SecKeychainAddInternetPassword", addErr)
	}
	return &pb.SecurityResponse{}
}

// keychainDeleteGenericPassword handles the delete-generic-password subcommand.
// Flags: -a (account), -s (service).
func keychainDeleteGenericPassword(args []string) *pb.SecurityResponse {
	a, err := command.ParseDeleteGenericPassword(args)
	if err != nil {
		return &pb.SecurityResponse{Stderr: err.Error() + "\n", ExitCode: 2}
	}

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	if a.Account != "" {
		item.SetAccount(a.Account)
	}
	if a.Service != "" {
		item.SetService(a.Service)
	}

	if err := keychain.DeleteItem(item); err != nil {
		return keychainErrResponse("SecKeychainSearchCopyNext", err)
	}
	return &pb.SecurityResponse{}
}

// keychainDeleteInternetPassword handles the delete-internet-password subcommand.
// Flags: -a (account), -s (server).
func keychainDeleteInternetPassword(args []string) *pb.SecurityResponse {
	a, err := command.ParseDeleteInternetPassword(args)
	if err != nil {
		return &pb.SecurityResponse{Stderr: err.Error() + "\n", ExitCode: 2}
	}

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassInternetPassword)
	if a.Account != "" {
		item.SetAccount(a.Account)
	}
	if a.Server != "" {
		item.SetServer(a.Server)
	}

	if err := keychain.DeleteItem(item); err != nil {
		return keychainErrResponse("SecKeychainSearchCopyNext", err)
	}
	return &pb.SecurityResponse{}
}


