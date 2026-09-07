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
		Engines:              []string{"claude", "codex", "astra", "gpt-6-astra"},
		PermissionModesAllow: []string{"plan", "acceptEdits", "read-only", "workspace-write"},
		PermissionModesDeny:  []string{"bypassPermissions", "danger-full-access"},
		DenyFlags:            []string{"--dangerously-skip-permissions", "--yolo", "--dangerously-bypass-approvals-and-sandbox"},
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

	mode, err := permissionMode(argv)
	if err != nil {
		return Decision{Engine: engine, Reason: err.Error()}
	}
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
	if contains(p.PermissionModesAllow, mode) {
		return Decision{
			Allow:          true,
			Engine:         engine,
			PermissionMode: mode,
			Reason:         fmt.Sprintf("allowed: engine %q, permission mode %q", engine, mode),
		}
	}
	return Decision{
		Engine:         engine,
		PermissionMode: mode,
		Reason:         fmt.Sprintf("permission mode %q is not in the allowed set %v", mode, p.PermissionModesAllow),
	}
}

// PermissionMode extracts one explicit mode. Astra aliases use Codex's sandbox
// flags; approval settings alone do not specify a sandbox. Missing, malformed,
// or repeated modes return an empty string.
func PermissionMode(argv []string) string {
	mode, _ := permissionMode(argv)
	return mode
}

func permissionMode(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", nil
	}
	engine := engineName(argv[0])
	codex := engine == "codex" || engine == "astra" || engine == "gpt-6-astra"
	mode := ""
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			break
		}
		flag, value, inline := strings.Cut(a, "=")
		if codex && len(a) > 2 && (strings.HasPrefix(a, "-s") || strings.HasPrefix(a, "-c")) {
			flag, value, inline = a[:2], strings.TrimPrefix(a[2:], "="), true
		}
		switch flag {
		case "--permission-mode":
			if codex {
				return "", fmt.Errorf("flag %s does not specify a sandbox mode for engine %q", flag, engine)
			}
		case "--sandbox", "-s", "--config", "-c":
			if engine == "claude" {
				// Claude's -c means continue, not a configuration override.
				if flag == "-c" && !inline {
					continue
				}
				return "", fmt.Errorf("flag %s does not specify a permission mode for engine %q", flag, engine)
			}
		default:
			continue
		}
		if !inline {
			i++
			if i >= len(argv) || strings.HasPrefix(argv[i], "-") {
				return "", fmt.Errorf("flag %s requires a value", flag)
			}
			value = argv[i]
		}
		if flag == "-c" || flag == "--config" {
			var ok bool
			value, ok = configAssign(value, "sandbox_mode")
			if !ok {
				continue
			}
		} else {
			value = unquote(value)
		}
		if value == "" {
			return "", fmt.Errorf("flag %s states an empty permission mode", flag)
		}
		if mode != "" {
			return "", fmt.Errorf("multiple permission modes stated: %q and %q; policy requires one explicit mode", mode, value)
		}
		mode = value
	}
	return mode, nil
}

func configAssign(s, key string) (string, bool) {
	k, value, ok := strings.Cut(s, "=")
	if !ok || strings.TrimSpace(k) != key {
		return "", false
	}
	return unquote(strings.TrimSpace(value)), true
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
