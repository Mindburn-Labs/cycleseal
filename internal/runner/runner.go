// Package runner executes the engine and captures what it produced.
package runner

import (
	"errors"
	"os"
	"os/exec"
	"time"
)

// Result is one execution.
type Result struct {
	ExitCode  int
	Output    []byte
	StartedAt time.Time
	EndedAt   time.Time
}

// Run executes argv, streaming combined output to mirror while capturing it.
//
// A non-zero exit is a result, not an error: the receipt has to record what
// happened, and "the engine failed" is exactly the kind of thing a chain of
// receipts exists to preserve. Only a failure to run at all is an error.
func Run(argv []string, mirror *os.File) (Result, error) {
	if len(argv) == 0 {
		return Result{}, errors.New("no command to run")
	}
	var buf capture
	if mirror != nil {
		buf.mirror = mirror
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.Stdin = os.Stdin

	res := Result{StartedAt: time.Now().UTC()}
	err := cmd.Run()
	res.EndedAt = time.Now().UTC()
	res.Output = buf.data

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		res.ExitCode = 0
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitCode()
	default:
		return res, err
	}
	return res, nil
}

type capture struct {
	data   []byte
	mirror *os.File
}

func (c *capture) Write(p []byte) (int, error) {
	c.data = append(c.data, p...)
	if c.mirror != nil {
		_, _ = c.mirror.Write(p)
	}
	return len(p), nil
}
