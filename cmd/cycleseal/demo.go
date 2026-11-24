package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/cycleseal/internal/receipt"
)

// cmdDemo records a refusal and an allowed cycle, verifies the chain, then
// edits a sample receipt to demonstrate a verification failure.
func cmdDemo() int {
	dir, err := os.MkdirTemp("", "cycleseal-demo-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
		return exitUsage
	}
	defer os.RemoveAll(dir)

	store := receipt.Store{Dir: dir}
	pub, err := store.Keygen()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
		return exitUsage
	}
	polPath := filepath.Join(dir, "policy.json")
	// The demo uses the system echo in place of an agent engine.
	if err := os.WriteFile(polPath, []byte(`{"engines":["echo"],"permission_modes_allow":["plan"],"permission_modes_deny":["bypassPermissions"],"require_explicit_mode":true}`), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
		return exitUsage
	}

	runArgs := []string{"run", "-state", dir, "-policy", polPath, "-quiet", "--", "echo", "--permission-mode"}
	verifyArgs := []string{"verify", "-state", dir, "-key", hex.EncodeToString(pub)}
	fmt.Printf("cycleseal %s — demo\n", version)
	steps := []struct {
		title string
		args  []string
		want  int
	}{
		{"Refuse a disallowed mode", append(runArgs, "bypassPermissions"), exitRefused},
		{"Run a cycle in plan mode", append(runArgs, "plan", "cycle output"), exitOK},
		{"Show both receipts", []string{"log", "-state", dir}, exitOK},
		{"Verify the original chain", verifyArgs, exitOK},
	}
	for _, step := range steps {
		if !demoStep(step.title, step.args, step.want) {
			return exitFailed
		}
	}
	if err := tamper(filepath.Join(dir, "chain.jsonl")); err != nil {
		fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
		return exitUsage
	}
	if !demoStep("Verify after changing the refused receipt", verifyArgs, exitFailed) {
		return exitFailed
	}
	return exitOK
}

func demoStep(title string, args []string, want int) bool {
	fmt.Printf("\n%s\n", title)
	if code := run(args); code != want {
		fmt.Fprintf(os.Stderr, "cycleseal: %s exited %d, expected %d\n", args[0], code, want)
		return false
	}
	return true
}

func tamper(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out := strings.Replace(string(b), `"policy_decision":"deny"`, `"policy_decision":"allow"`, 1)
	if out == string(b) {
		return errors.New("demo could not find the receipt to tamper with")
	}
	return os.WriteFile(path, []byte(out), 0o644)
}
