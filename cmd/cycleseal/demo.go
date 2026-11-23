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
	dir := ".cycleseal-demo"
	_ = os.RemoveAll(dir)
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

	step := func(n int, title string) { fmt.Printf("\n── %d. %s\n", n, title) }

	fmt.Printf("cycleseal %s — demo in %s/\ntrust root %s\n", version, dir, shortHash(hex.EncodeToString(pub)))

	step(1, "the cycle an ungoverned loop runs today")
	fmt.Println("   $ cycleseal run -- echo --permission-mode bypassPermissions")
	code := cmdRun([]string{"-state", dir, "-policy", polPath, "--", "echo", "--permission-mode", "bypassPermissions"})
	fmt.Printf("   exit %d\n", code)

	step(2, "a cycle policy accepts")
	fmt.Println("   $ cycleseal run -- echo --permission-mode plan")
	code = cmdRun([]string{"-state", dir, "-policy", polPath, "-quiet", "--", "echo", "--permission-mode", "plan", "cycle output"})
	fmt.Printf("   exit %d\n", code)

	step(3, "the chain so far")
	cmdLog([]string{"-state", dir})

	step(4, "verify against the trust root")
	cmdVerify([]string{"-state", dir})

	step(5, "edit a sealed receipt, the way a markdown baton would be edited")
	if err := tamper(filepath.Join(dir, "chain.jsonl")); err != nil {
		fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
		return exitUsage
	}
	fmt.Println("   rewrote receipt #0 to say the permissive cycle was allowed")
	code = cmdVerify([]string{"-state", dir})
	fmt.Printf("\nexit %d — the edit is detectable, which is the whole difference between\na chain and a file the agent can rewrite.\n", code)
	return exitOK
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
