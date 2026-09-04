package policy

import (
	"fmt"
	"strings"
	"testing"
)

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
		{"claude", "--permission-mode", "plan", "--permission-mode", "bypassPermissions"},
		{"claude", "--permission-mode", "plan", "--permission-mode"},
		{"claude", "-s", "read-only"},
	} {
		if d := p.Evaluate(argv); d.Allow {
			t.Errorf("argv %q allowed: %s", argv, d.Reason)
		}
	}
	for _, engine := range []string{"codex", "astra", "gpt-6-astra"} {
		for _, args := range [][]string{
			nil,
			{"--sandbox"}, {"-s"}, {"--config"}, {"-c"},
			{"--sandbox="}, {"-s="}, {"--config=sandbox_mode="},
			{"--sandbox", "somethingNew"},
			{"--config", `model="gpt-6-astra"`},
			{"--ask-for-approval", "on-request"}, {"-a", "never"},
			{"--approve-for-me"},
			{"--permission-mode", "plan"},
			{"--", "--sandbox", "read-only"},
			{"--sandbox", "read-only", "-s", "danger-full-access"},
			{"-s", "danger-full-access", "--sandbox", "read-only"},
			{"--sandbox", "read-only", "--config", `sandbox_mode = "danger-full-access"`},
			{"--sandbox", "read-only", "--sandbox", "read-only"},
			{"--sandbox", "read-only", "-s"},
			{"--sandbox", "read-only", "--config", "sandbox_mode="},
		} {
			argv := append([]string{engine}, args...)
			if d := p.Evaluate(argv); d.Allow {
				t.Errorf("argv %q allowed: %s", argv, d.Reason)
			}
		}
	}
	for _, allowed := range [][]string{nil, {}} {
		p.PermissionModesAllow = allowed
		for _, requireExplicit := range []bool{true, false} {
			p.RequireExplicitMode = requireExplicit
			for _, mode := range []string{"read-only", "somethingNew"} {
				if d := p.Evaluate([]string{"codex", "--sandbox", mode}); d.Allow {
					t.Errorf("empty allow list allowed mode %q (require explicit: %v)", mode, requireExplicit)
				}
			}
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
	want := `permission mode "fullAccessV2" is not in the allowed set [plan acceptEdits read-only workspace-write]`
	if d.PermissionMode != "fullAccessV2" || d.Reason != want {
		t.Fatalf("refusal must name the observed mode and allowed set: %+v", d)
	}
}

func TestAstraSandboxSpellings(t *testing.T) {
	spellings := []struct {
		name string
		args func(string) []string
	}{
		{"sandbox", func(m string) []string { return []string{"--sandbox", m} }},
		{"sandbox equals", func(m string) []string { return []string{"--sandbox=" + m} }},
		{"short sandbox", func(m string) []string { return []string{"-s", m} }},
		{"short sandbox equals", func(m string) []string { return []string{"-s=" + m} }},
		{"short sandbox attached", func(m string) []string { return []string{"-s" + m} }},
		{"config", func(m string) []string { return []string{"--config", `sandbox_mode="` + m + `"`} }},
		{"config equals", func(m string) []string { return []string{`--config=sandbox_mode="` + m + `"`} }},
		{"short config", func(m string) []string { return []string{"-c", `sandbox_mode="` + m + `"`} }},
		{"short config equals", func(m string) []string { return []string{`-c=sandbox_mode="` + m + `"`} }},
		{"short config attached", func(m string) []string { return []string{`-csandbox_mode="` + m + `"`} }},
		{"config whitespace", func(m string) []string { return []string{"--config", " sandbox_mode = '" + m + "' "} }},
	}
	for _, engine := range []string{"codex", "astra", "gpt-6-astra", "/usr/local/bin/astra", `C:\tools\gpt-6-astra.exe`} {
		for _, spelling := range spellings {
			for _, mode := range []string{"read-only", "workspace-write", "danger-full-access", "fullAccessV2"} {
				t.Run(engine+"/"+spelling.name+"/"+mode, func(t *testing.T) {
					argv := append([]string{engine, "exec", "--model", "gpt-6-astra"}, spelling.args(mode)...)
					if got := PermissionMode(argv); got != mode {
						t.Fatalf("PermissionMode(%q) = %q, want %q", argv, got, mode)
					}
					d := Default().Evaluate(argv)
					wantAllow := mode == "read-only" || mode == "workspace-write"
					if d.Allow != wantAllow || d.PermissionMode != mode {
						t.Fatalf("decision = %+v, want allow=%v, mode=%q", d, wantAllow, mode)
					}
					if mode == "fullAccessV2" && d.Reason != fmt.Sprintf("permission mode %q is not in the allowed set [plan acceptEdits read-only workspace-write]", mode) {
						t.Fatalf("refusal lost the observed mode or allowed set: %s", d.Reason)
					}
				})
			}
		}
	}
}

func TestBypassFlagsOverrideSafeModes(t *testing.T) {
	for _, engine := range []string{"codex", "astra", "gpt-6-astra"} {
		for _, flag := range []string{"--yolo", "--dangerously-bypass-approvals-and-sandbox", "--dangerously-bypass-approvals-and-sandbox=true"} {
			for _, args := range [][]string{{flag, "-s", "read-only"}, {"-s", "read-only", flag}} {
				d := Default().Evaluate(append([]string{engine}, args...))
				if d.Allow || !strings.Contains(d.Reason, "flag ") || !strings.Contains(d.Reason, "denied by policy") {
					t.Errorf("%s %q: %+v", engine, args, d)
				}
			}
		}
	}
}

func TestRepeatedModesAreRefusedEvenWhenOptional(t *testing.T) {
	p := Default()
	p.RequireExplicitMode = false
	d := p.Evaluate([]string{"astra", "-s", "read-only", "--sandbox", "danger-full-access"})
	if d.Allow || !strings.Contains(d.Reason, `"read-only"`) || !strings.Contains(d.Reason, `"danger-full-access"`) {
		t.Fatalf("ambiguous modes must be refused with both values: %+v", d)
	}
	for _, argv := range [][]string{
		{"codex", "--permission-mode", "bypassPermissions"},
		{"claude", "--sandbox", "danger-full-access"},
	} {
		if d := p.Evaluate(argv); d.Allow {
			t.Errorf("wrong engine's mode treated as absent: %q: %+v", argv, d)
		}
	}
}

func TestCustomEngineStillRequiresAnAllowedMode(t *testing.T) {
	p := Default()
	p.Engines = []string{"custom"}
	p.RequireExplicitMode = false
	for _, mode := range []string{"read-only", "danger-full-access", "somethingNew"} {
		d := p.Evaluate([]string{"custom", "--sandbox", mode})
		if d.Allow != (mode == "read-only") || d.PermissionMode != mode {
			t.Errorf("custom engine mode %q: %+v", mode, d)
		}
	}
	if d := Default().Evaluate([]string{"claude", "-c", "--permission-mode", "plan"}); !d.Allow {
		t.Errorf("Claude's continue flag was mistaken for Codex config: %+v", d)
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
