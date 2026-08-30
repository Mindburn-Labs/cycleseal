# cycleseal

Governed mode for an autonomous loop.

Loops that run an AI agent around the clock share a shape: a daemon, a prompt,
one engine invocation per cycle, and a markdown file carried between cycles as
state. That shape has two properties nobody chose. The engine runs with
permissions fully open, because that is what keeps the loop from stalling on a
prompt. And the state file is rewritten each cycle by the agent itself, so
nothing downstream can tell what it used to say.

cycleseal changes exactly two things and leaves the rest of your loop alone:

- **The permissive cycle is refused before it starts.** Policy is evaluated
  against the command line, and there is no path through it that reaches
  *allow* by running out of checks.
- **Every cycle is sealed into an append-only signed chain** — the refused ones
  too. A chain can still be edited. It cannot be edited undetectably, and that
  is the whole difference.

**Status: early prototype (v0.1).** Built by [Mindburn Labs](https://mindburn.org).

## Quickstart

```sh
go install github.com/Mindburn-Labs/cycleseal/cmd/cycleseal@latest

cycleseal keygen                 # writes a signing key and prints the trust root
cycleseal demo                   # the whole story in a scratch directory
```

Then wrap the engine call your loop already makes. One line changes:

```diff
- claude -p "$PROMPT" --permission-mode bypassPermissions
+ cycleseal run --prompt-file PROMPT.md -- claude -p "$PROMPT" --permission-mode bypassPermissions
```

```
cycleseal: REFUSED — permission mode "bypassPermissions" is denied by policy
cycleseal: sealed as receipt #0 34716621a424
```

The loop's own retry and backoff handle the non-zero exit. Change the mode to
one policy accepts and the cycle runs, is sealed, and shows up in the chain.

## The demo, end to end

`cycleseal demo` runs against `/bin/echo`, so it works with no engine installed:

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
```

Exit codes: `0` ran or verified, `1` engine failed or chain failed
verification, `2` usage error, `3` policy refused the cycle.

## Policy

Omit `-policy` and you get the built-in default: engines `claude` and `codex`,
modes `plan` / `acceptEdits` / `read-only` / `workspace-write`, with
`bypassPermissions` and `danger-full-access` denied by name and an unstated mode
refused outright.

```json
{
  "engines": ["claude", "codex"],
  "permission_modes_allow": ["plan", "acceptEdits", "read-only", "workspace-write"],
  "permission_modes_deny": ["bypassPermissions", "danger-full-access"],
  "deny_flags": ["--dangerously-skip-permissions", "--yolo"],
  "require_explicit_mode": true
}
```

Two of those defaults are doing more work than they look:

**`require_explicit_mode`.** A command line that names no permission mode is
refused. An unstated mode is not a safe mode — it inherits whatever the engine
defaults to, and the loops this tool exists for default to the most permissive
setting available. Absence must not read as consent.

**The allow list is closed.** A mode nobody thought to put in the deny list is
still refused. New permissive flags ship faster than deny lists grow.

## What a receipt records

Each cycle seals its sequence number and the hash of the previous receipt, when
it started and ended, the engine and the full argv, the permission mode, the
hash of the prompt, the hash of the policy that judged it, the decision and its
reason, the engine's exit code, and the hash and size of its output.

The refusals are in there too. That is what makes "the loop was governed" a
thing someone can check, rather than a claim about a gap in the record.

## Verification

`cycleseal verify` re-derives every hash, walks the links, and checks every
signature — offline, against a public key **supplied from outside the chain**.

The key each receipt carries is checked for agreement but is never the
authority. A chain that vouches for itself with its own key establishes only
that it is internally consistent, which is not the question anyone reading it
is asking. Hand your trust root to whoever will check the chain, or pass it with
`-key`.

The verifier also fails on an empty chain. Nothing to check is not the same as
nothing wrong.

## No dependencies

`go.mod` has no `require` block, and `make check` fails if one appears. The
verifier's trust story rests on the standard library's Ed25519 and SHA-256 and
on nothing else, so an adversarial reader has a short list of things to audit.

## Limits

Being clear about these matters more than the feature list.

- **This is not yet a policy enforcement point.** Policy is local and static,
  evaluated from the command line. Routing the decision through the HELM PEP,
  so refusals answer to an organisation's policy rather than a JSON file beside
  the loop, is the next step and is not done.
- **Receipts are not yet interoperable.** Canonicalisation is struct-order JSON,
  not RFC 8785 JCS, and the chain is local rather than anchored. Sufficient
  while cycleseal both produces and verifies; move onto the kernel's
  canonicalisation and receipt contracts before these travel.
- **The seam is the invocation, not the agent.** cycleseal governs how the
  engine is launched. What the agent then does inside an allowed cycle is
  bounded by the permission mode it was allowed to run under, not by cycleseal.
- **A local key is a local claim.** Anyone who can read `key.ed25519` can sign a
  chain. Custody of that key is the security boundary, and this prototype does
  nothing to protect it beyond file permissions.

## License

Apache-2.0. See [LICENSE](LICENSE).
