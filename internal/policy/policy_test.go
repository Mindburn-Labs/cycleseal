package policy

import "testing"

func TestDefaultRefusesThePermissiveModes(t *testing.T) {
	p := Default()
	cases := []struct {
		name string
		argv []string
	}{
		{"claude bypassPermissions", []string{"claude", "-p", "x", "--permission-mode", "bypassPermissions"}},
		{"claude bypassPermissions inline", []string{"claude", "--permission-mode=bypassPermissions"}},
		{"codex danger-full-access", []string{"codex", "exec", "-c", `sandbox_mode="danger-full-access"`, "prompt"}},
		{"absolute path still resolves", []string{"/usr/local/bin/claude", "--permission-mode", "bypassPermissions"}},
	}
	for _, c := range cases {
		if d := p.Evaluate(c.argv); d.Allow {
			t.Errorf("%s: allowed, want refused (%s)", c.name, d.Reason)
		}
	}
}

// An unstated mode is not a safe mode: it inherits the engine default, and the
// loops this exists for default to the most permissive setting available.
func TestUnstatedModeIsRefused(t *testing.T) {
	d := Default().Evaluate([]string{"claude", "-p", "do the thing"})
	if d.Allow {
		t.Fatalf("unstated mode allowed: %s", d.Reason)
	}
	if d.Reason == "" {
		t.Error("refusal carries no reason")
	}
}

func TestAllowedModePasses(t *testing.T) {
	d := Default().Evaluate([]string{"claude", "-p", "x", "--permission-mode", "plan"})
	if !d.Allow {
		t.Fatalf("plan mode refused: %s", d.Reason)
	}
	if d.Engine != "claude" || d.PermissionMode != "plan" {
		t.Errorf("decision = %+v", d)
	}
}

func TestUnknownEngineAndDeniedFlagsAreRefused(t *testing.T) {
	p := Default()
	if d := p.Evaluate([]string{"curl", "--permission-mode", "plan"}); d.Allow {
		t.Error("unknown engine allowed")
	}
	if d := p.Evaluate([]string{"claude", "--dangerously-skip-permissions", "--permission-mode", "plan"}); d.Allow {
		t.Error("denied flag allowed")
	}
}

// Fail closed: nothing reaches allow by running out of checks.
func TestNoInputReachesAllowByExhaustion(t *testing.T) {
	p := Default()
	for _, argv := range [][]string{
		nil,
		{},
		{""},
		{"claude"},
		{"claude", "--permission-mode"},
		{"claude", "--permission-mode", "somethingNew"},
	} {
		if d := p.Evaluate(argv); d.Allow {
			t.Errorf("argv %q allowed: %s", argv, d.Reason)
		}
	}
}

// A mode outside the allow list is refused even when nobody thought to name it
// in the deny list. New permissive modes ship faster than deny lists grow.
func TestUnknownModeIsRefusedNotAssumedSafe(t *testing.T) {
	d := Default().Evaluate([]string{"claude", "--permission-mode", "fullAccessV2"})
	if d.Allow {
		t.Fatal("an unrecognised mode was assumed safe")
	}
}

func TestPermissionModeExtraction(t *testing.T) {
	cases := map[string][]string{
		"plan":               {"claude", "--permission-mode", "plan"},
		"acceptEdits":        {"claude", "--permission-mode=acceptEdits"},
		"workspace-write":    {"codex", "exec", "-c", `sandbox_mode="workspace-write"`},
		"danger-full-access": {"codex", "--sandbox", "danger-full-access"},
		"":                   {"claude", "-p", "hello"},
	}
	for want, argv := range cases {
		if got := PermissionMode(argv); got != want {
			t.Errorf("PermissionMode(%q) = %q, want %q", argv, got, want)
		}
	}
}

// The receipt records which rules produced its decision, so the bytes have to
// be stable across runs.
func TestBytesAreDeterministic(t *testing.T) {
	a, b := Default().Bytes(), Default().Bytes()
	if string(a) != string(b) {
		t.Errorf("policy bytes differ between calls:\n%s\n%s", a, b)
	}
}
