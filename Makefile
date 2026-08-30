# GOWORK=off: this repo must build standalone, not through the workspace go.work.
GO := GOWORK=off go

.PHONY: build test vet fmt check demo clean

build:
	$(GO) build ./...

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

check: build vet test
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed on:" >&2; echo "$$out" >&2; exit 1; fi
	@if grep -q '^require' go.mod; then echo "go.mod grew a dependency; the verifier's trust story depends on it having none" >&2; exit 1; fi

# End-to-end: refuse a permissive cycle, seal a governed one, verify the chain.
demo:
	$(GO) run ./cmd/cycleseal demo

clean:
	rm -rf cycleseal .cycleseal-demo
