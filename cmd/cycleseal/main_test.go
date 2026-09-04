package main

import (
	"encoding/hex"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Mindburn-Labs/cycleseal/internal/policy"
	"github.com/Mindburn-Labs/cycleseal/internal/receipt"
)

func TestRefusedAstraInvocationsAreSealedAndVerify(t *testing.T) {
	store := receipt.Store{Dir: t.TempDir()}
	pub, err := store.Keygen()
	if err != nil {
		t.Fatal(err)
	}
	// These binaries do not exist: a refusal must never reach the runner.
	bin := t.TempDir()
	invocations := [][]string{
		{filepath.Join(bin, "astra"), "--config", `sandbox_mode="fullAccessV2"`},
		{filepath.Join(bin, "gpt-6-astra"), "-s", "danger-full-access"},
		{filepath.Join(bin, "codex"), "exec", "--model", "gpt-6-astra", "--config=sandbox_mode=fullAccessV2"},
	}
	wantModes := []string{"fullAccessV2", "danger-full-access", "fullAccessV2"}
	for i, argv := range invocations {
		args := append([]string{"run", "-state", store.Dir, "--"}, argv...)
		if code := run(args); code != exitRefused {
			t.Fatalf("invocation %d: exit %d, want %d", i, code, exitRefused)
		}
	}
	chain, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != len(invocations) {
		t.Fatalf("chain length = %d, want %d", len(chain), len(invocations))
	}
	for i, sealed := range chain {
		r := sealed.Receipt
		d := policy.Default().Evaluate(invocations[i])
		if r.PermissionMode != wantModes[i] {
			t.Errorf("receipt %d mode = %q, want %q", i, r.PermissionMode, wantModes[i])
		}
		if r.PolicyDecision != receipt.DecisionDeny || r.ExitCode != -1 || r.OutputBytes != 0 || r.OutputSHA256 != receipt.SHA256Hex(nil) {
			t.Errorf("receipt %d does not record an unexecuted refusal: %+v", i, r)
		}
		if r.Engine != d.Engine || r.PermissionMode != d.PermissionMode || r.PolicyReason != d.Reason || !reflect.DeepEqual(r.Argv, invocations[i]) {
			t.Errorf("receipt %d lost invocation or decision: %+v", i, r)
		}
		if r.PolicySHA256 != receipt.SHA256Hex(policy.Default().Bytes()) {
			t.Errorf("receipt %d lost policy digest", i)
		}
	}
	if code := run([]string{"verify", "-state", store.Dir, "-key", hex.EncodeToString(pub)}); code != exitOK {
		t.Fatalf("verify exit = %d, want %d", code, exitOK)
	}
}
