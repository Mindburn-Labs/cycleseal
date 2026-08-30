package runner

import (
	"strings"
	"testing"
)

func TestRunCapturesOutput(t *testing.T) {
	res, err := Run([]string{"echo", "hello"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d, want 0", res.ExitCode)
	}
	if !strings.Contains(string(res.Output), "hello") {
		t.Errorf("output = %q", res.Output)
	}
	if !res.EndedAt.After(res.StartedAt) && res.EndedAt.Equal(res.StartedAt) == false {
		t.Error("timestamps not recorded")
	}
}

// A failing engine is a result to be sealed, not an error that loses the record.
func TestNonZeroExitIsAResultNotAnError(t *testing.T) {
	res, err := Run([]string{"sh", "-c", "echo out; echo err >&2; exit 7"}, nil)
	if err != nil {
		t.Fatalf("non-zero exit reported as an error: %v", err)
	}
	if res.ExitCode != 7 {
		t.Errorf("exit = %d, want 7", res.ExitCode)
	}
	out := string(res.Output)
	if !strings.Contains(out, "out") || !strings.Contains(out, "err") {
		t.Errorf("stdout and stderr not both captured: %q", out)
	}
}

func TestMissingBinaryIsAnError(t *testing.T) {
	if _, err := Run([]string{"cycleseal-no-such-binary-xyz"}, nil); err == nil {
		t.Fatal("a missing engine ran successfully")
	}
	if _, err := Run(nil, nil); err == nil {
		t.Fatal("an empty command ran successfully")
	}
}
