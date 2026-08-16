package collectors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"winhealth/pkg/models"
)

// CollectIntegrityDiagnostics collects device manager errors, temp folder size and pending reboot
func CollectIntegrityDiagnostics() models.IntegrityReport {
	report := models.IntegrityReport{
		Severity:             models.SeverityOK,
		Score:                100,
		DeviceManagerErrors:  make([]models.DeviceProblem, 0),
		PendingRebootReasons: make([]string, 0),
		SfcLastScanSummary:   "Ingen aktiv korruption rapporterad.",
	}

	// 1. Calculate Temp Folder Sizes in Go
	var totalTempBytes int64
	tempDirs := []string{
		os.TempDir(),
		os.Getenv("LOCALAPPDATA") + `\Temp`,
		`C:\Windows\Temp`,
		`C:\Windows\SoftwareDistribution\Download`,
	}

	for _, dir := range tempDirs {
		if dir == "" {
			continue
		}
		_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err == nil && info != nil && !info.IsDir() {
				totalTempBytes += info.Size()
			}
			return nil
		})
	}
	report.TempFilesSizeBytes = totalTempBytes
	report.TempFilesSizeDisplay = formatBytes(totalTempBytes)

	// 2. Query PnpDevice Errors and Reboot Pending via PowerShell (only connected/present devices)
	psScript := `$pnpErrors = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { 
    $_.Present -eq $true -and ($_.Status -eq 'Error' -or ($_.ConfigManagerErrorCode -gt 0 -and $_.ConfigManagerErrorCode -ne 22 -and $_.ConfigManagerErrorCode -ne 45))
} | Select-Object FriendlyName, InstanceId, ConfigManagerErrorCode, Status

$rebootReasons = @()
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
    $rebootReasons += "Windows Component-Based Servicing kräver omstart"
}
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
    $rebootReasons += "Windows Update kräver omstart för att slutföra installationer"
}
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations") {
    $rebootReasons += "Väntande filersättningar i systemkatalogen"
}

[PSCustomObject]@{
    PnpErrors = $pnpErrors
    RebootReasons = $rebootReasons
} | ConvertTo-Json -Compress`

	out, _ := RunPowerShellWithTimeout(psScript, 15*time.Second)

	type rawInteg struct {
		PnpErrors     interface{} `json:"PnpErrors"`
		RebootReasons []string    `json:"RebootReasons"`
	}

	if len(out) > 0 {
		var integData rawInteg
		if err := json.Unmarshal(out, &integData); err == nil {
			report.PendingRebootReasons = integData.RebootReasons
			if len(report.PendingRebootReasons) > 0 {
				report.PendingReboot = true
			}

			if integData.PnpErrors != nil {
				type rawPnp struct {
					FriendlyName           string `json:"FriendlyName"`
					InstanceId             string `json:"InstanceId"`
					ConfigManagerErrorCode int    `json:"ConfigManagerErrorCode"`
					Status                 string `json:"Status"`
				}
				b, _ := json.Marshal(integData.PnpErrors)
				var pnpList []rawPnp
				if strings.HasPrefix(string(b), "[") {
					_ = json.Unmarshal(b, &pnpList)
				} else if strings.HasPrefix(string(b), "{") {
					var single rawPnp
					if err := json.Unmarshal(b, &single); err == nil {
						pnpList = append(pnpList, single)
					}
				}
				for _, p := range pnpList {
					report.DeviceManagerErrors = append(report.DeviceManagerErrors, models.DeviceProblem{
						DeviceName:   p.FriendlyName,
						DeviceID:     p.InstanceId,
						ProblemCode:  p.ConfigManagerErrorCode,
						StatusString: p.Status,
					})
				}
			}
		}
	}

	// Score Calculation
	score := 100
	if len(report.DeviceManagerErrors) > 0 {
		devDeduct := len(report.DeviceManagerErrors) * 10
		if devDeduct > 30 {
			devDeduct = 30
		}
		score -= devDeduct
		report.Severity = models.SeverityWarning
	}
	if totalTempBytes > 30*1024*1024*1024 { // >30GB
		score -= 5
	}
	if report.PendingReboot {
		score -= 5
	}

	if score < 0 {
		score = 0
	}
	report.Score = score

	return report
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
