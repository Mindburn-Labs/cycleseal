// Command cycleseal governs an autonomous loop at its one narrow seam — the
// engine invocation — and leaves a signed, append-only chain of what happened.
//
// Loops of this class carry their state between cycles in a markdown file the
// agent itself rewrites, and run the engine with permissions fully open.
// cycleseal changes two things and nothing else: the permissive cycle is
// refused before it starts, and every cycle, refused or run, is sealed into a
// chain that cannot be quietly edited afterwards.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mindburn-Labs/cycleseal/internal/policy"
	"github.com/Mindburn-Labs/cycleseal/internal/receipt"
	"github.com/Mindburn-Labs/cycleseal/internal/runner"
)

const version = "0.1.0-prototype"

const usage = `cycleseal ` + version + ` — governed mode for an autonomous loop

usage:
  cycleseal keygen  [-state DIR]
  cycleseal run     [-state DIR] [-policy FILE] [-prompt-file FILE] -- <engine> [args...]
  cycleseal verify  [-state DIR] [-key HEX] [-json]
  cycleseal log     [-state DIR]
  cycleseal demo

Wrap the engine call your loop already makes:

  - claude -p "$PROMPT" --permission-mode bypassPermissions
  + cycleseal run -- claude -p "$PROMPT" --permission-mode bypassPermissions
    → refused before anything executes, and the refusal is sealed too

exit codes:
  0  cycle ran, or chain verified
  1  the engine exited non-zero, or the chain failed verification
  2  usage or internal error
  3  policy refused the cycle
`

const (
	exitOK      = 0
	exitFailed  = 1
	exitUsage   = 2
	exitRefused = 3
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Print(usage)
		return exitOK
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Print(usage)
		return exitOK
	case "version", "-v", "--version":
		fmt.Println("cycleseal " + version)
		return exitOK
	case "keygen":
		return cmdKeygen(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "verify":
		return cmdVerify(args[1:])
	case "log":
		return cmdLog(args[1:])
	case "demo":
		return cmdDemo()
	default:
		fmt.Fprintf(os.Stderr, "cycleseal: unknown command %q (try: cycleseal help)\n", args[0])
		return exitUsage
	}
}

func stateFlag(fs *flag.FlagSet) *string {
	return fs.String("state", ".cycleseal", "directory holding the chain and keys")
}

func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	state := stateFlag(fs)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	pub, err := receipt.Store{Dir: *state}.Keygen()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
		return exitUsage
	}
	fmt.Printf("signing key written to %s\n", filepath.Join(*state, "key.ed25519"))
	fmt.Printf("trust root  %s\n", hex.EncodeToString(pub))
	fmt.Println("\nHand that public key to whoever will check the chain. A chain verified\nwith a key taken from inside itself establishes only self-consistency.")
	return exitOK
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	state := stateFlag(fs)
	policyPath := fs.String("policy", "", "policy file (JSON); omitted means the built-in fail-closed default")
	promptFile := fs.String("prompt-file", "", "file holding the cycle prompt, hashed into the receipt")
	quiet := fs.Bool("quiet", false, "do not mirror engine output to this terminal")

	engineArgv := splitAfterDoubleDash(args)
	if err := fs.Parse(argsBeforeDoubleDash(args)); err != nil {
		return exitUsage
	}
	if len(engineArgv) == 0 {
		fmt.Fprintln(os.Stderr, "cycleseal: nothing to run — put the engine command after `--`")
		return exitUsage
	}

	pol, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
		return exitUsage
	}
	store := receipt.Store{Dir: *state}

	promptHash, err := hashPrompt(*promptFile, engineArgv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
		return exitUsage
	}

	decision := pol.Evaluate(engineArgv)
	now := time.Now().UTC().Format(time.RFC3339)
	rec := receipt.Receipt{
		StartedAt:      now,
		EndedAt:        now,
		Engine:         decision.Engine,
		Argv:           engineArgv,
		PermissionMode: decision.PermissionMode,
		PromptSHA256:   promptHash,
		PolicySHA256:   receipt.SHA256Hex(pol.Bytes()),
		PolicyDecision: receipt.DecisionDeny,
		PolicyReason:   decision.Reason,
		ExitCode:       -1,
		OutputSHA256:   receipt.SHA256Hex(nil),
	}

	if !decision.Allow {
		// A refusal is evidence. Sealing it is what makes "the loop was
		// governed" checkable later, rather than a claim about a gap.
		sealed, err := store.Append(rec)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
			return exitUsage
		}
		fmt.Fprintf(os.Stderr, "cycleseal: REFUSED — %s\n", decision.Reason)
		fmt.Fprintf(os.Stderr, "cycleseal: sealed as receipt #%d %s\n", sealed.Receipt.Seq, shortHash(sealed.Hash))
		return exitRefused
	}

	var mirror *os.File
	if !*quiet {
		mirror = os.Stderr
	}
	res, err := runner.Run(engineArgv, mirror)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
		return exitUsage
	}

	rec.PolicyDecision = receipt.DecisionAllow
	rec.StartedAt = res.StartedAt.Format(time.RFC3339)
	rec.EndedAt = res.EndedAt.Format(time.RFC3339)
	rec.ExitCode = res.ExitCode
	rec.OutputSHA256 = receipt.SHA256Hex(res.Output)
	rec.OutputBytes = int64(len(res.Output))

	sealed, err := store.Append(rec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
		return exitUsage
	}
	fmt.Fprintf(os.Stderr, "cycleseal: sealed receipt #%d %s (engine exit %d, %d bytes out)\n",
		sealed.Receipt.Seq, shortHash(sealed.Hash), res.ExitCode, rec.OutputBytes)
	if res.ExitCode != 0 {
		return exitFailed
	}
	return exitOK
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	state := stateFlag(fs)
	keyHex := fs.String("key", "", "trusted Ed25519 public key (hex); omitted reads trusted.pub beside the chain")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	store := receipt.Store{Dir: *state}

	var (
		trusted ed25519.PublicKey
		err     error
		source  string
	)
	if *keyHex != "" {
		trusted, err = receipt.ParsePublicKey(*keyHex)
		source = "supplied on the command line"
	} else {
		trusted, err = store.TrustedKey()
		source = filepath.Join(*state, "trusted.pub")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
		return exitUsage
	}

	chain, err := store.Read()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
		return exitUsage
	}
	rep := receipt.Verify(chain, trusted)

	if *asJSON {
		if err := receipt.WriteJSON(os.Stdout, rep); err != nil {
			return exitUsage
		}
	} else {
		fmt.Printf("chain:  %s\n", filepath.Join(*state, "chain.jsonl"))
		fmt.Printf("key:    %s (%s)\n", shortHash(hex.EncodeToString(trusted)), source)
		fmt.Printf("length: %d receipt(s)\n", rep.Length)
		if rep.Verified {
			fmt.Printf("tip:    %s\nVERIFIED\n", shortHash(rep.TipHash))
		} else {
			fmt.Println("FAILED")
			for _, p := range rep.Problems {
				fmt.Printf("  receipt #%d: %s\n", p.Seq, p.Reason)
			}
		}
	}
	if !rep.Verified {
		return exitFailed
	}
	return exitOK
}

func cmdLog(args []string) int {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	state := stateFlag(fs)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	chain, err := receipt.Store{Dir: *state}.Read()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cycleseal: "+err.Error())
		return exitUsage
	}
	if len(chain) == 0 {
		fmt.Println("chain is empty")
		return exitOK
	}
	for _, s := range chain {
		r := s.Receipt
		mode := r.PermissionMode
		if mode == "" {
			mode = "(unstated)"
		}
		fmt.Printf("#%-3d %s  %-5s  %-9s  mode=%-18s exit=%-3d  %s\n",
			r.Seq, shortHash(s.Hash), r.PolicyDecision, r.Engine, mode, r.ExitCode, r.StartedAt)
		if r.PolicyDecision == receipt.DecisionDeny {
			fmt.Printf("      %s\n", r.PolicyReason)
		}
	}
	return exitOK
}

// hashPrompt records what the cycle was asked to do. Preferring a file keeps
// the prompt inspectable after the fact; falling back to the -p argument keeps
// the receipt honest when the loop passes it inline.
func hashPrompt(path string, argv []string) (string, error) {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return receipt.SHA256Hex(b), nil
	}
	for i, a := range argv {
		if (a == "-p" || a == "--prompt") && i+1 < len(argv) {
			return receipt.SHA256Hex([]byte(argv[i+1])), nil
		}
	}
	return receipt.SHA256Hex(nil), nil
}

func argsBeforeDoubleDash(args []string) []string {
	for i, a := range args {
		if a == "--" {
			return args[:i]
		}
	}
	return args
}

func splitAfterDoubleDash(args []string) []string {
	for i, a := range args {
		if a == "--" {
			return args[i+1:]
		}
	}
	return nil
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}

// cmdDemo runs the whole story end to end in a scratch directory: a permissive
// cycle refused, a governed cycle sealed, the chain verified, the chain
// tampered with, and the tampering caught.
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
	// The demo governs /bin/echo standing in for an engine, so the story runs
	// anywhere without Claude or Codex installed.
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
