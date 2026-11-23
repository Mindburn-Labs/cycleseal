# cycleseal

cycleseal applies a local policy before launching an agent engine. It appends a
signed receipt for a policy refusal or the result of an allowed cycle.
`cycleseal verify` checks receipt contents, sequence, and links against a trusted
Ed25519 public key.

**Status: early prototype (v0.1).** Built by [Mindburn Labs](https://mindburn.org).

## Quickstart

```sh
go install github.com/Mindburn-Labs/cycleseal/cmd/cycleseal@latest

cycleseal keygen                 # writes a signing key and prints the trust root
cycleseal demo                   # run the bundled demonstration
```

Wrap the loop's engine invocation with `cycleseal run`. This example shows a
policy refusal.

```diff
- claude -p "$PROMPT" --permission-mode bypassPermissions
+ cycleseal run --prompt-file PROMPT.md -- claude -p "$PROMPT" --permission-mode bypassPermissions
```

```
cycleseal: REFUSED — permission mode "bypassPermissions" is denied by policy
cycleseal: sealed as receipt #0 34716621a424
```

A policy refusal exits with status `3`. An allowed invocation runs the engine
and records its result in the same chain.

## The demo, end to end

`cycleseal demo` uses the system `echo` command in place of an agent engine.
The abbreviated output below shows the steps and verification results.

```
── 1. the cycle an ungoverned loop runs today
cycleseal: REFUSED — permission mode "bypassPermissions" is denied by policy
cycleseal: sealed as receipt #0 34716621a424

── 2. a cycle policy accepts
cycleseal: sealed receipt #1 0a031a673bb7 (engine exit 0, 36 bytes out)

── 3. the chain so far
#0   34716621a424  deny   echo   mode=bypassPermissions  exit=-1
      permission mode "bypassPermissions" is denied by policy
#1   0a031a673bb7  allow  echo   mode=plan               exit=0

── 4. verify against the trust root
VERIFIED

── 5. edit a sealed receipt, the way a markdown baton would be edited
FAILED
  receipt #0: recorded hash 34716621a424… does not match the receipt body: the body was edited after sealing
  receipt #0: signature does not verify against the trusted key
```

## Commands

```
cycleseal keygen [-state DIR]
cycleseal run    [-state DIR] [-policy FILE] [-prompt-file FILE] -- <engine> [args...]
cycleseal verify [-state DIR] [-key HEX] [-json]
cycleseal log    [-state DIR]
cycleseal demo
```

Exit codes: `0` ran or verified, `1` engine failed or chain failed
verification, `2` usage error, `3` policy refused the cycle.

## Policy

Omit `-policy` and you get the built-in default: engines `claude`, `codex`,
and the Codex-compatible wrapper names `astra` / `gpt-6-astra`,
modes `plan` / `acceptEdits` / `read-only` / `workspace-write`, with
`bypassPermissions` and `danger-full-access` denied by name and an unstated mode
refused outright.

```json
{
  "engines": ["claude", "codex", "astra", "gpt-6-astra"],
  "permission_modes_allow": ["plan", "acceptEdits", "read-only", "workspace-write"],
  "permission_modes_deny": ["bypassPermissions", "danger-full-access"],
  "deny_flags": ["--dangerously-skip-permissions", "--yolo", "--dangerously-bypass-approvals-and-sandbox"],
  "require_explicit_mode": true
}
```

Astra is selected in Codex with `--model gpt-6-astra`; it uses Codex's sandbox
settings. For example:

```sh
cycleseal run -- codex exec --model gpt-6-astra --sandbox read-only "review the diff"
```

Codex and the Astra wrapper names accept `--sandbox` / `-s` and
`--config` / `-c sandbox_mode=...`, including `--flag=value` and attached short
values. `--ask-for-approval` / `-a` alone do not state a sandbox mode. Repeated
mode settings are refused, and arguments after the engine's `--` do not count
as mode flags. A mode outside the allow list reports both the value seen and
the allowed set; an empty allow list refuses every stated mode.

With `require_explicit_mode`, the command line must state a mode. A stated mode
must appear in `permission_modes_allow`. An entry in `permission_modes_deny`
takes precedence if the mode appears in both lists.

## What a receipt records

Each cycle seals its sequence number and the hash of the previous receipt, when
it started and ended, the engine and the full argv, the permission mode, the
hash of the prompt, the hash of the policy that judged it, the decision and its
reason, the engine's exit code, and the hash and size of its output.

The same schema records both allowed and refused cycles.

## Verification

`cycleseal verify` checks hashes, sequence, links, and signatures offline. It
uses the external public key from `trusted.pub` in the state directory or the
hex-encoded key passed with `-key`. Each receipt must record that same key.

The verifier rejects an empty chain. A successful result authenticates the
receipts presented. Establishing completeness requires an independently
recorded final hash or receipt count.

## Dependencies

Cycleseal uses the Go standard library, including Ed25519 and SHA-256 for
verification. `make check` rejects `require` directives in `go.mod`.

## Limits

- **Policy is local and static.** The CLI runs as one binary with no account or
  service dependency.
- **Receipts use a constrained JCS profile.** Version 2 sorts keys and applies
  RFC 8785 string escaping, but accepts integers only because this schema has no
  floating-point fields. Version 1 struct-order receipts remain verifiable.
  The chain is still local rather than anchored, and its schema is not yet a
  HELM Kernel receipt contract.
- **Policy applies at launch.** The engine is responsible for its permission
  enforcement during a cycle.
- **File permissions protect the signing key.** Anyone who can read
  `key.ed25519` can sign a receipt.

## License

Apache-2.0. See [LICENSE](LICENSE).
