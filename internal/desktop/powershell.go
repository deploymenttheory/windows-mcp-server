//go:build windows && (amd64 || arm64)

package desktop

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os/exec"
	"syscall"
	"time"
	"unicode/utf16"
)

// PowerShellResult is the outcome of a PowerShell invocation.
type PowerShellResult struct {
	// Output is the combined stdout+stderr text.
	Output string
	// ExitCode is the process exit code (0 on success).
	ExitCode int
	// TimedOut reports whether the command was killed for exceeding its timeout.
	TimedOut bool
}

// encodePowerShellCommand base64-encodes a command as UTF-16LE, the format
// expected by PowerShell's -EncodedCommand. This avoids all shell-quoting and
// escaping concerns for arbitrary command text.
func encodePowerShellCommand(command string) string {
	units := utf16.Encode([]rune(command))
	buf := make([]byte, 0, len(units)*2)
	for _, u := range units {
		// Truncation is the operation: each UTF-16 code unit is emitted as its
		// low then high byte (little-endian), which is what -EncodedCommand wants.
		buf = append(buf, byte(u), byte(u>>8)) //nolint:gosec // deliberate UTF-16LE split
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// RunPowerShell executes a PowerShell command and returns its combined output
// and exit code. The command is passed via -EncodedCommand so no escaping is
// needed. It is bounded by timeout (a non-positive timeout means no limit) and
// also honors ctx cancellation.
//
// The child process runs with an environment reconstructed from the registry
// (see winenv.go), so commands see the full user PATH/vars even when the MCP
// host launched the server with a stripped environment. The interpreter is
// resolved to an absolute path against that reconstructed PATH.
func (d *Desktop) RunPowerShell(ctx context.Context, command string, timeout time.Duration) (PowerShellResult, error) {
	return d.runPowerShell(ctx, resolvePwsh(), command, timeout)
}

// RunWindowsPowerShell runs a command specifically under Windows PowerShell 5.1
// (powershell.exe), required for WinRT APIs such as toast notifications that
// PowerShell 7 (pwsh) does not expose.
func (d *Desktop) RunWindowsPowerShell(
	ctx context.Context,
	command string,
	timeout time.Duration,
) (PowerShellResult, error) {
	return d.runPowerShell(ctx, resolveWindowsPowerShellExe(), command, timeout)
}

func (d *Desktop) runPowerShell(
	ctx context.Context,
	exe, command string,
	timeout time.Duration,
) (PowerShellResult, error) {
	if command == "" {
		return PowerShellResult{}, errors.New("empty command")
	}

	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	encoded := encodePowerShellCommand(command)
	cmd := exec.CommandContext(runCtx, exe,
		"-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand", encoded)
	// Do not open a console window for the child process.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	// Rebuild the environment from the registry so commands see the full user
	// PATH/vars even when the MCP host stripped the server's environment.
	cmd.Env = powerShellEnv()

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	res := PowerShellResult{Output: out.String()}

	if runCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = -1
		return res, nil
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		// Failure to start the process is an infrastructure error.
		return res, err
	}
	res.ExitCode = 0
	return res, nil
}
