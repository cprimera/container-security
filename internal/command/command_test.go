package command

import (
	"testing"
)

func TestSubcommandsReturnsAllCommands(t *testing.T) {
	want := []string{
		FindGenericPassword,
		FindInternetPassword,
		AddGenericPassword,
		AddInternetPassword,
		DeleteGenericPassword,
		DeleteInternetPassword,
	}
	got := Subcommands()
	if len(got) != len(want) {
		t.Fatalf("Subcommands() returned %d items, want %d", len(got), len(want))
	}
	for i, fs := range got {
		if fs.Name() != want[i] {
			t.Errorf("Subcommands()[%d].Name() = %q, want %q", i, fs.Name(), want[i])
		}
	}
}

func TestFlagSetKnown(t *testing.T) {
	for _, name := range []string{
		FindGenericPassword, FindInternetPassword,
		AddGenericPassword, AddInternetPassword,
		DeleteGenericPassword, DeleteInternetPassword,
	} {
		fs := FlagSet(name)
		if fs == nil {
			t.Errorf("FlagSet(%q) returned nil", name)
		} else if fs.Name() != name {
			t.Errorf("FlagSet(%q).Name() = %q", name, fs.Name())
		}
	}
}

func TestFlagSetUnknown(t *testing.T) {
	if FlagSet("list-keychains") != nil {
		t.Error("FlagSet(\"list-keychains\") should be nil")
	}
}

func TestParseFindGenericPassword(t *testing.T) {
	args, err := ParseFindGenericPassword([]string{"-a", "alice", "-s", "mysvc", "-l", "mylabel", "-g"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if args.Account != "alice" {
		t.Errorf("Account: got %q, want %q", args.Account, "alice")
	}
	if args.Service != "mysvc" {
		t.Errorf("Service: got %q, want %q", args.Service, "mysvc")
	}
	if args.Label != "mylabel" {
		t.Errorf("Label: got %q, want %q", args.Label, "mylabel")
	}
	if !args.ShowPassword {
		t.Error("ShowPassword (-g) should be true")
	}
	if args.PasswordOnly {
		t.Error("PasswordOnly (-w) should be false")
	}
}

func TestParseFindGenericPasswordW(t *testing.T) {
	// -w (password only) takes precedence over -g (show password).
	args, err := ParseFindGenericPassword([]string{"-s", "svc", "-w"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !args.PasswordOnly {
		t.Error("PasswordOnly (-w) should be true")
	}
	if args.ShowPassword {
		t.Error("ShowPassword (-g) should be false")
	}
}

func TestParseFindGenericPasswordBadFlag(t *testing.T) {
	_, err := ParseFindGenericPassword([]string{"--unknown"})
	if err == nil {
		t.Error("expected error for unknown flag")
	}
}

func TestParseFindInternetPassword(t *testing.T) {
	args, err := ParseFindInternetPassword([]string{"-a", "bob", "-s", "example.com", "-g"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if args.Account != "bob" {
		t.Errorf("Account: got %q, want %q", args.Account, "bob")
	}
	if args.Server != "example.com" {
		t.Errorf("Server: got %q, want %q", args.Server, "example.com")
	}
	if !args.ShowPassword {
		t.Error("ShowPassword (-g) should be true")
	}
}

func TestParseAddGenericPassword(t *testing.T) {
	args, err := ParseAddGenericPassword([]string{"-a", "alice", "-s", "svc", "-w", "secret"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if args.Account != "alice" {
		t.Errorf("Account: got %q", args.Account)
	}
	if args.Service != "svc" {
		t.Errorf("Service: got %q", args.Service)
	}
	if args.Password != "secret" {
		t.Errorf("Password: got %q", args.Password)
	}
	if args.Update {
		t.Error("Update should be false")
	}
}

func TestParseAddGenericPasswordUpdate(t *testing.T) {
	args, err := ParseAddGenericPassword([]string{"-s", "svc", "-w", "pw", "-U"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !args.Update {
		t.Error("Update (-U) should be true")
	}
}

func TestParseAddInternetPassword(t *testing.T) {
	args, err := ParseAddInternetPassword([]string{"-a", "user", "-s", "host.com", "-w", "pw", "-U"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if args.Server != "host.com" {
		t.Errorf("Server: got %q", args.Server)
	}
	if !args.Update {
		t.Error("Update should be true")
	}
}

func TestParseDeleteGenericPassword(t *testing.T) {
	args, err := ParseDeleteGenericPassword([]string{"-a", "alice", "-s", "svc"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if args.Account != "alice" {
		t.Errorf("Account: got %q", args.Account)
	}
	if args.Service != "svc" {
		t.Errorf("Service: got %q", args.Service)
	}
}

func TestParseDeleteInternetPassword(t *testing.T) {
	args, err := ParseDeleteInternetPassword([]string{"-s", "host.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if args.Server != "host.com" {
		t.Errorf("Server: got %q", args.Server)
	}
}
