// Package policy decides whether a cycle may run, before it runs.
//
// The decision is made from the command line the loop is about to execute.
// That is a narrow seam, and narrowness is the point: it is the one place an
// existing autonomous loop can be governed without rewriting it, because every
// loop of this shape ends up at exactly one engine invocation.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Policy is the rule set. Zero value is not usable; start from Default.
type Policy struct {
	// Engines that may be invoked at all.
	Engines []string `json:"engines"`
	// PermissionModesAllow is the closed set of acceptable modes. A mode
	// outside it is refused even if it is not named in the deny list.
	PermissionModesAllow []string `json:"permission_modes_allow"`
	// PermissionModesDeny is refused first, and exists so a mode can be
	// named as forbidden rather than merely absent — the refusal message is
	// then about the mode rather than about the list.
	PermissionModesDeny []string `json:"permission_modes_deny"`
	// DenyFlags are refused wherever they appear.
	DenyFlags []string `json:"deny_flags"`
	// RequireExplicitMode refuses a command line that names no permission
	// mode. An unstated mode is not a safe mode: it inherits whatever the
	// engine defaults to, and the loops this tool exists for default to the
	// most permissive one there is.
	RequireExplicitMode bool `json:"require_explicit_mode"`
}

// Default is the posture a governed loop starts from: fail closed, refuse the
// permissive modes by name, and refuse silence.
func Default() Policy {
	return Policy{
		Engines:              []string{"claude", "codex"},
		PermissionModesAllow: []string{"plan", "acceptEdits", "read-only", "workspace-write"},
		PermissionModesDeny:  []string{"bypassPermissions", "danger-full-access"},
		DenyFlags:            []string{"--dangerously-skip-permissions", "--yolo"},
		RequireExplicitMode:  true,
	}
}

// Load reads a policy file, or returns Default when path is empty.
func Load(path string) (Policy, error) {
	if path == "" {
		return Default(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	p := Default()
	if err := json.Unmarshal(raw, &p); err != nil {
		return Policy{}, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Bytes returns the policy as canonical JSON, so a receipt can record which
// rules produced its decision rather than merely that some rules did.
func (p Policy) Bytes() []byte {
	b, err := json.Marshal(p)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// Decision is the outcome for one command line.
type Decision struct {
	Allow          bool   `json:"allow"`
	Reason         string `json:"reason"`
	Engine         string `json:"engine"`
	PermissionMode string `json:"permission_mode"`
}

// Evaluate decides whether argv may run. argv[0] is the engine binary.
//
// Every path that is not an explicit allow is a refusal. There is no branch
// here that reaches "allow" by running out of checks.
func (p Policy) Evaluate(argv []string) Decision {
	if len(argv) == 0 {
		return Decision{Reason: "no command supplied"}
	}

	engine := engineName(argv[0])
	if !contains(p.Engines, engine) {
		return Decision{
			Engine: engine,
			Reason: fmt.Sprintf("engine %q is not in the allowed set %v", engine, p.Engines),
		}
	}

	for _, f := range p.DenyFlags {
		for _, a := range argv[1:] {
			if a == f || strings.HasPrefix(a, f+"=") {
				return Decision{
					Engine: engine,
					Reason: fmt.Sprintf("flag %s is denied by policy", f),
				}
			}
		}
	}

	mode := PermissionMode(argv)
	if mode == "" {
		if p.RequireExplicitMode {
			return Decision{
				Engine: engine,
				Reason: "no permission mode stated; an unstated mode inherits the engine default, which policy will not assume is safe",
			}
		}
		return Decision{Allow: true, Engine: engine, Reason: "allowed: no mode stated and policy does not require one"}
	}
	if contains(p.PermissionModesDeny, mode) {
		return Decision{
			Engine:         engine,
			PermissionMode: mode,
			Reason:         fmt.Sprintf("permission mode %q is denied by policy", mode),
		}
	}
	if len(p.PermissionModesAllow) > 0 && !contains(p.PermissionModesAllow, mode) {
		return Decision{
			Engine:         engine,
			PermissionMode: mode,
			Reason:         fmt.Sprintf("permission mode %q is not in the allowed set %v", mode, p.PermissionModesAllow),
		}
	}
	return Decision{
		Allow:          true,
		Engine:         engine,
		PermissionMode: mode,
		Reason:         fmt.Sprintf("allowed: engine %q, permission mode %q", engine, mode),
	}
}

// PermissionMode extracts the mode from a command line, covering the spellings
// the two common engines use.
func PermissionMode(argv []string) string {
	for i, a := range argv {
		switch {
		case a == "--permission-mode" && i+1 < len(argv):
			return unquote(argv[i+1])
		case strings.HasPrefix(a, "--permission-mode="):
			return unquote(strings.TrimPrefix(a, "--permission-mode="))
		case a == "-c" && i+1 < len(argv):
			if v, ok := configAssign(argv[i+1], "sandbox_mode"); ok {
				return v
			}
		case strings.HasPrefix(a, "--sandbox="):
			return unquote(strings.TrimPrefix(a, "--sandbox="))
		case a == "--sandbox" && i+1 < len(argv):
			return unquote(argv[i+1])
		}
	}
	return ""
}

func configAssign(s, key string) (string, bool) {
	if !strings.HasPrefix(s, key+"=") {
		return "", false
	}
	return unquote(strings.TrimPrefix(s, key+"=")), true
}

func engineName(path string) string {
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		path = path[i+1:]
	}
	return strings.TrimSuffix(path, ".exe")
}

func unquote(s string) string { return strings.Trim(s, `"'`) }

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
