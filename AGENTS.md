# Agent Operational Guidelines for cycleseal

cycleseal wraps the engine call of an autonomous agent loop. It refuses a cycle
whose command line fails a local, static policy, and seals every cycle, refused
or run, into an append-only signed receipt chain that `cycleseal verify` checks
offline against a trusted public key. It is an early prototype (v0.1): one Go
binary built on the standard library alone. It is not a remote policy
enforcement point, and it does not govern what an agent does inside an allowed
cycle.

## Dev Commands
* Check: `make check` (what CI runs) builds, vets and tests, then fails on
  unformatted Go files or on any `require` line in go.mod.
* Build: `make build` (`go build ./...`)
* Test: `make test` (`go test ./...`)
* Format: `make fmt` (`gofmt -l -w .`)
* Demo: `make demo` refuses a permissive cycle, seals an allowed one, verifies
  the chain and shows a tampered receipt failing, all against `/bin/echo` in
  `.cycleseal-demo/`. `make clean` removes it.

The Makefile sets `GOWORK=off`, so the module builds standalone.

## Boundaries
* Keep go.mod free of `require` lines. The verifier's trust rests on the
  standard library's Ed25519 and SHA-256, and `make check` enforces it.
* Keep policy fail-closed: the allow list is closed, and by default a command
  line that states no permission mode is refused.
* Never commit a signing key or a live chain (`.cycleseal/`, `*.ed25519`).
