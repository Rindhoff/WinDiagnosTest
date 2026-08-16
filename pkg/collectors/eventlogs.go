package collectors

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"winhealth/pkg/models"
)

// CollectEventLogsDiagnostics collects BSOD minidumps and recent critical/error events
func CollectEventLogsDiagnostics() models.EventLogsReport {
	report := models.EventLogsReport{
		Severity:           models.SeverityOK,
		Score:              100,
		BSODCrashDumps:     make([]models.MinidumpInfo, 0),
		RecentSystemErrors: make([]models.EventLogEntry, 0),
		RecentAppCrashes:   make([]models.EventLogEntry, 0),
	}

	// 1. Scan for Minidumps
	minidumpDir := `C:\Windows\Minidump`
	if entries, err := os.ReadDir(minidumpDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".dmp") {
				info, err := e.Info()
				if err == nil {
					report.BSODCrashDumps = append(report.BSODCrashDumps, models.MinidumpInfo{
						FileName:    e.Name(),
						FilePath:    filepath.Join(minidumpDir, e.Name()),
						CreatedTime: info.ModTime(),
						SizeBytes:   info.Size(),
					})
				}
			}
		}
	}

	// Check Memory.dmp
	if fi, err := os.Stat(`C:\Windows\MEMORY.DMP`); err == nil {
		report.BSODCrashDumps = append(report.BSODCrashDumps, models.MinidumpInfo{
			FileName:    "MEMORY.DMP (Full Dump)",
			FilePath:    `C:\Windows\MEMORY.DMP`,
			CreatedTime: fi.ModTime(),
			SizeBytes:   fi.Size(),
		})
	}

	// 2. Query Event Viewer System & Application errors (last 48 hours)
	psScript := `$startTime = (Get-Date).AddDays(-2)
$events = @()

# System Critical/Errors
$sysEvents = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=$startTime} -MaxEvents 30 -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        LogName = "System"
        EventID = $_.Id
        Source = $_.ProviderName
        TimeCreated = $_.TimeCreated.ToString("o")
        Level = if ($_.Level -eq 1) { "Critical" } else { "Error" }
        Message = $_.Message
    }
}
if ($sysEvents) { $events += $sysEvents }

# Application Crashes (EventID 1000, 1002, or Level 1/2)
$appEvents = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2; StartTime=$startTime} -MaxEvents 30 -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        LogName = "Application"
        EventID = $_.Id
        Source = $_.ProviderName
        TimeCreated = $_.TimeCreated.ToString("o")
        Level = if ($_.Level -eq 1) { "Critical" } else { "Error" }
        Message = $_.Message
    }
}
if ($appEvents) { $events += $appEvents }

$events | ConvertTo-Json -Compress`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := cmd.Output()

	type rawEvent struct {
		LogName     string `json:"LogName"`
		EventID     int64  `json:"EventID"`
		Source      string `json:"Source"`
		TimeCreated string `json:"TimeCreated"`
		Level       string `json:"Level"`
		Message     string `json:"Message"`
	}

	if len(out) > 0 {
		var rawList []rawEvent
		trimmed := strings.TrimSpace(string(out))
		if strings.HasPrefix(trimmed, "[") {
			_ = json.Unmarshal([]byte(trimmed), &rawList)
		} else if strings.HasPrefix(trimmed, "{") {
			var single rawEvent
			if err := json.Unmarshal([]byte(trimmed), &single); err == nil {
				rawList = append(rawList, single)
			}
		}

		for _, item := range rawList {
			t, _ := time.Parse(time.RFC3339, item.TimeCreated)
			entry := models.EventLogEntry{
				LogName:     item.LogName,
				EventID:     item.EventID,
				Source:      item.Source,
				TimeCreated: t,
				Level:       item.Level,
				Message:     cleanEventMessage(item.Message),
			}

			if item.LogName == "System" {
				report.RecentSystemErrors = append(report.RecentSystemErrors, entry)
			} else {
				report.RecentAppCrashes = append(report.RecentAppCrashes, entry)
			}

			if item.Level == "Critical" {
				report.CriticalEventCount++
			} else {
				report.ErrorEventCount++
			}
		}
	}

	// Calculate Score
	score := 100

	// Deduct for recent BSOD dumps (within 7 days)
	recentDumps := 0
	for _, d := range report.BSODCrashDumps {
		if time.Since(d.CreatedTime) < 7*24*time.Hour {
			recentDumps++
		}
	}
	if recentDumps > 0 {
		score -= recentDumps * 20
		report.Severity = models.SeverityCritical
	}

	// Deduct for critical system events
	score -= report.CriticalEventCount * 10
	score -= report.ErrorEventCount * 2

	if score < 0 {
		score = 0
	}
	report.Score = score

	if score < 60 {
		report.Severity = models.SeverityCritical
	} else if score < 85 {
		report.Severity = models.SeverityWarning
	} else {
		report.Severity = models.SeverityOK
	}

	return report
}

func cleanEventMessage(msg string) string {
	msg = strings.TrimSpace(msg)
	if len(msg) > 350 {
		return msg[:347] + "..."
	}
	if msg == "" {
		return "Ingen ytterligare feltext tillgänglig."
	}
	return msg
}
