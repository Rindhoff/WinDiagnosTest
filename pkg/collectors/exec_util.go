package collectors

import (
	"context"
	"os/exec"
	"syscall"
	"time"
)

// psSemaphore limits concurrent PowerShell processes to avoid CPU and disk thrashing
var psSemaphore = make(chan struct{}, 3)

func hiddenWindowProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true}
}

// RunPowerShellWithTimeout executes a PowerShell script with a strict timeout context and hidden window
func RunPowerShellWithTimeout(psScript string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Acquire semaphore slot with respect to context cancellation
	select {
	case psSemaphore <- struct{}{}:
		defer func() { <-psSemaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	fullScript := "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " + psScript
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", fullScript)
	cmd.SysProcAttr = hiddenWindowProcAttr()
	return cmd.Output()
}

