package collectors

import (
	"context"
	"os/exec"
	"syscall"
	"time"
)

// RunPowerShellWithTimeout executes a PowerShell script with a strict timeout context and hidden window
func RunPowerShellWithTimeout(psScript string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Output()
}
