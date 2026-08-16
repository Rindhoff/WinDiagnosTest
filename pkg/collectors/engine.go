package collectors

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"
	"winhealth/pkg/models"
)

// RunFullDiagnostics orchestrates parallel collection of all diagnostic modules
func RunFullDiagnostics() models.HealthReport {
	start := time.Now()

	report := models.HealthReport{
		Timestamp:      start,
		Architecture:   "64-bit",
		SummaryBadges:  map[string]int{"OK": 0, "WARNING": 0, "CRITICAL": 0},
		TopIssues:      make([]models.IssueSummary, 0),
		QuickFixStatus: make(map[string]bool),
	}

	// 1. Gather System Basics
	hostname, _ := os.Hostname()
	report.ComputerName = hostname
	gatherOSBasics(&report)

	// 2. Parallel Diagnostic Collector Execution
	var wg sync.WaitGroup
	wg.Add(8)

	go func() {
		defer wg.Done()
		report.CheckPointVPN = CollectCheckPointDiagnostics()
	}()

	go func() {
		defer wg.Done()
		report.Hardware = CollectHardwareDiagnostics()
	}()

	go func() {
		defer wg.Done()
		report.EventLogs = CollectEventLogsDiagnostics()
	}()

	go func() {
		defer wg.Done()
		report.Network = CollectNetworkDiagnostics()
	}()

	go func() {
		defer wg.Done()
		report.Security = CollectSecurityDiagnostics()
	}()

	go func() {
		defer wg.Done()
		report.Performance = CollectPerformanceDiagnostics()
	}()

	go func() {
		defer wg.Done()
		report.Integrity = CollectIntegrityDiagnostics()
	}()

	go func() {
		defer wg.Done()
		report.BootLogon = CollectBootLogonDiagnostics()
	}()

	wg.Wait()

	// 3. Calculate Overall Health Score & Synthesize Issues
	calculateOverallScoreAndIssues(&report)

	return report
}

func gatherOSBasics(report *models.HealthReport) {
	psScript := `$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object Caption, Version, BuildNumber, LastBootUpTime
if ($os) {
    [PSCustomObject]@{
        Caption = $os.Caption
        Version = $os.Version
        BuildNumber = $os.BuildNumber
        UptimeHours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1)
    } | ConvertTo-Json -Compress
}`

	out, err := RunPowerShellWithTimeout(psScript, 5*time.Second)
	if err == nil && len(out) > 0 {
		type osInfo struct {
			Caption     string  `json:"Caption"`
			Version     string  `json:"Version"`
			BuildNumber string  `json:"BuildNumber"`
			UptimeHours float64 `json:"UptimeHours"`
		}
		var info osInfo
		if err := json.Unmarshal(out, &info); err == nil {
			report.OSVersion = strings.TrimSpace(info.Caption)
			report.OSBuild = fmt.Sprintf("%s (Build %s)", info.Version, info.BuildNumber)
			if info.UptimeHours > 24 {
				days := int(info.UptimeHours / 24)
				hrs := int(info.UptimeHours) % 24
				report.Uptime = fmt.Sprintf("%d dagar, %d timmar", days, hrs)
			} else {
				report.Uptime = fmt.Sprintf("%.1f timmar", info.UptimeHours)
			}
		}
	}

	if report.OSVersion == "" {
		report.OSVersion = "Windows 10/11"
		report.OSBuild = "Latest"
		report.Uptime = "1 dag"
	}
}

func calculateOverallScoreAndIssues(r *models.HealthReport) {
	// Weights including BootLogon
	hwWeight := 0.15
	logWeight := 0.15
	netWeight := 0.15
	secWeight := 0.15
	bootWeight := 0.15
	cpWeight := 0.15
	integWeight := 0.05
	perfWeight := 0.05

	// If Check Point is not installed/detected, redistribute its weight
	if !r.CheckPointVPN.Detected {
		hwWeight = 0.20
		logWeight = 0.20
		netWeight = 0.15
		secWeight = 0.15
		bootWeight = 0.15
		integWeight = 0.10
		perfWeight = 0.05
		cpWeight = 0.0
	}

	weightedScore := float64(r.Hardware.Score)*hwWeight +
		float64(r.EventLogs.Score)*logWeight +
		float64(r.Network.Score)*netWeight +
		float64(r.Security.Score)*secWeight +
		float64(r.BootLogon.Score)*bootWeight +
		float64(r.Integrity.Score)*integWeight +
		float64(r.Performance.Score)*perfWeight +
		float64(r.CheckPointVPN.Score)*cpWeight

	r.TotalScore = int(math.Round(weightedScore))

	// Build Top Issues List
	// 1. Check Point Issues
	if r.CheckPointVPN.Detected {
		for _, s := range r.CheckPointVPN.Services {
			if !s.IsHealthy {
				r.TopIssues = append(r.TopIssues, models.IssueSummary{
					Category:    "Check Point VPN",
					Title:       fmt.Sprintf("VPN-tjänst '%s' har stoppats", s.DisplayName),
					Description: "Check Point Endpoint Security VPN kan inte ansluta när bakgrundstjänsten är stoppad.",
					Severity:    models.SeverityCritical,
					FixActionId: "restart_checkpoint_vpn",
				})
			}
		}
		for _, a := range r.CheckPointVPN.VirtualAdapters {
			if !a.IsHealthy {
				r.TopIssues = append(r.TopIssues, models.IssueSummary{
					Category:    "Check Point VPN",
					Title:       fmt.Sprintf("Virtuellt nätverkskort '%s' är inaktivt", a.Name),
					Description: "Det virtuella VPN-kortet är inaktiverat eller har förlorat nätverksbindningar.",
					Severity:    models.SeverityWarning,
					FixActionId: "restart_checkpoint_vpn",
				})
			}
		}
		for _, gw := range r.CheckPointVPN.GatewayConnectivity {
			if !gw.Reachable {
				r.TopIssues = append(r.TopIssues, models.IssueSummary{
					Category:    "Check Point VPN",
					Title:       fmt.Sprintf("Kan inte nå VPN-gateway '%s'", gw.Gateway),
					Description: fmt.Sprintf("Kunde inte upprätta anslutning mot gateway (%s).", gw.ErrorMessage),
					Severity:    models.SeverityWarning,
					FixActionId: "flush_dns_winsock",
				})
			}
		}
	}

	// 2. Event Logs Issues
	if len(r.EventLogs.BSODCrashDumps) > 0 {
		r.TopIssues = append(r.TopIssues, models.IssueSummary{
			Category:    "Systemkrascher",
			Title:       fmt.Sprintf("%d kraschdumpar (BSOD) hittades", len(r.EventLogs.BSODCrashDumps)),
			Description: "Datorn har drabbats av blåskärm/krascher. Kontrollera nyligen installerade drivrutiner.",
			Severity:    models.SeverityCritical,
			FixActionId: "run_sfc_scan",
		})
	}
	if r.EventLogs.CriticalEventCount > 0 {
		r.TopIssues = append(r.TopIssues, models.IssueSummary{
			Category:    "Eventlogg",
			Title:       fmt.Sprintf("%d kritiska systemfel de senaste 48h", r.EventLogs.CriticalEventCount),
			Description: "Kritiska felrapporter finns registrerade i Windows System- eller Application-loggen.",
			Severity:    models.SeverityWarning,
		})
	}

	// 3. Hardware Issues
	for _, d := range r.Hardware.Disks {
		if !d.SmartHealthy {
			r.TopIssues = append(r.TopIssues, models.IssueSummary{
				Category:    "Hårdvara / Disk",
				Title:       fmt.Sprintf("SMART-varningsstatus på disk %s (%s)", d.DriveLetter, d.Model),
				Description: "Disken rapporterar risk för haveri! Säkerhetskopiera omedelbart alla viktiga filer.",
				Severity:    models.SeverityCritical,
			})
		} else if d.UsagePct > 90 {
			r.TopIssues = append(r.TopIssues, models.IssueSummary{
				Category:    "Lagring",
				Title:       fmt.Sprintf("Lite ledigt utrymme på enhet %s (%.0f%% använt)", d.DriveLetter, d.UsagePct),
				Description: fmt.Sprintf("Endast %.1f GB ledigt av totalt %.1f GB. Rensa temporära filer för att frigöra utrymme.", d.FreeGB, d.TotalGB),
				Severity:    models.SeverityWarning,
				FixActionId: "clean_temp_files",
			})
		}
	}

	// 4. Network Issues
	if !r.Network.InternetOK {
		r.TopIssues = append(r.TopIssues, models.IssueSummary{
			Category:    "Nätverk",
			Title:       "Ingen internetanslutning detekterades",
			Description: "Kunde inte nå externa DNS-servrar eller standardgateway.",
			Severity:    models.SeverityCritical,
			FixActionId: "flush_dns_winsock",
		})
	}

	// 5. Security Issues
	if !r.Security.RealtimeProtection {
		r.TopIssues = append(r.TopIssues, models.IssueSummary{
			Category:    "Säkerhet",
			Title:       "Realtidsskydd i Antivirus är inaktiverat",
			Description: "Datorn saknar aktivt realtidsskydd mot skadlig programvara.",
			Severity:    models.SeverityCritical,
		})
	}
	if !r.Security.FirewallEnabled {
		r.TopIssues = append(r.TopIssues, models.IssueSummary{
			Category:    "Säkerhet",
			Title:       "Windows-brandväggen är avstängd",
			Description: "Inga aktiva brandväggsprofiler hittades. Aktivera brandväggen för att skydda nätverket.",
			Severity:    models.SeverityWarning,
		})
	}
	if !r.Security.WindowsUpdateServiceOK {
		r.TopIssues = append(r.TopIssues, models.IssueSummary{
			Category:    "Windows Update",
			Title:       "Windows Update-tjänsten är inaktiverad",
			Description: "Uppdateringstjänsten (wuauserv) är avstängd eller blockerad i systeminställningarna.",
			Severity:    models.SeverityWarning,
			FixActionId: "reset_windows_update",
		})
	}

	// 6. Integrity Issues
	if r.Integrity.TempFilesSizeBytes > 5*1024*1024*1024 { // >5 GB
		r.TopIssues = append(r.TopIssues, models.IssueSummary{
			Category:    "Systemfiler",
			Title:       fmt.Sprintf("%s temporära filer och cache samlat", r.Integrity.TempFilesSizeDisplay),
			Description: "Stora mängder temporära filer belastar systemdisken och kan rensas säkert.",
			Severity:    models.SeverityInfo,
			FixActionId: "clean_temp_files",
		})
	}
	if len(r.Integrity.DeviceManagerErrors) > 0 {
		r.TopIssues = append(r.TopIssues, models.IssueSummary{
			Category:    "Enhetshanteraren",
			Title:       fmt.Sprintf("%d enheter har felkod i Enhetshanteraren", len(r.Integrity.DeviceManagerErrors)),
			Description: "Drivrutinsfel eller hårdvarukonflikter upptäcktes för anslutna enheter.",
			Severity:    models.SeverityWarning,
		})
	}

	// 7. Boot & Logon Issues
	if len(r.BootLogon.UnreachableResources) > 0 {
		for _, un := range r.BootLogon.UnreachableResources {
			r.TopIssues = append(r.TopIssues, models.IssueSummary{
				Category:    "Nätverksresurser",
				Title:       fmt.Sprintf("Onåbar resurs '%s' (%s)", un.Name, un.TargetUNC),
				Description: un.ImpactDescription,
				Severity:    models.SeverityCritical,
			})
		}
	}
	if r.BootLogon.TotalBootDurationSeconds > 45.0 {
		r.TopIssues = append(r.TopIssues, models.IssueSummary{
			Category:    "Uppstartsprestanda",
			Title:       fmt.Sprintf("Långsam uppstartstid (%.1f sekunder)", r.BootLogon.TotalBootDurationSeconds),
			Description: "Datorn tar lång tid att starta. Inaktivera onödiga autostartprogram för att snabba upp inloggningen.",
			Severity:    models.SeverityWarning,
		})
	}

	// Count issues by severity
	warnCount := 0
	critCount := 0
	for _, issue := range r.TopIssues {
		if issue.Severity == models.SeverityCritical {
			critCount++
		} else if issue.Severity == models.SeverityWarning {
			warnCount++
		}
	}

	// Score Capping for Critical / Severe findings
	if critCount >= 3 && r.TotalScore > 49 {
		r.TotalScore = 49
	} else if critCount > 0 && r.TotalScore > 69 {
		r.TotalScore = 69
	} else if warnCount >= 4 && r.TotalScore > 79 {
		r.TotalScore = 79
	}

	if r.TotalScore > 100 {
		r.TotalScore = 100
	}
	if r.TotalScore < 0 {
		r.TotalScore = 0
	}

	// Score Rating
	if r.TotalScore >= 90 {
		r.ScoreRating = "Utmärkt skick"
	} else if r.TotalScore >= 75 {
		r.ScoreRating = "Gott skick med anmärkningar"
	} else if r.TotalScore >= 50 {
		r.ScoreRating = "Varningar kräver åtgärd"
	} else {
		r.ScoreRating = "Kritiska problem identifierade"
	}

	r.SummaryBadges["OK"] = countPassingChecks(r)
	r.SummaryBadges["WARNING"] = warnCount
	r.SummaryBadges["CRITICAL"] = critCount
}

func countPassingChecks(r *models.HealthReport) int {
	passed := 0

	// 1. Hardware checks
	if r.Hardware.Score >= 80 {
		passed++
	}
	allDisksHealthy := true
	for _, d := range r.Hardware.Disks {
		if !d.SmartHealthy || d.UsagePct > 90 {
			allDisksHealthy = false
			break
		}
	}
	if len(r.Hardware.Disks) > 0 && allDisksHealthy {
		passed++
	}

	// 2. Security checks
	if r.Security.AntivirusEnabled && r.Security.RealtimeProtection {
		passed++
	}
	if r.Security.FirewallEnabled {
		passed++
	}
	if r.Security.WindowsUpdateServiceOK {
		passed++
	}
	if r.Security.BitLockerProtected {
		passed++
	}

	// 3. Network checks
	if r.Network.InternetOK {
		passed++
	}
	if len(r.Network.ActiveAdapters) > 0 {
		passed++
	}
	if r.Network.GatewayPingMs >= 0 {
		passed++
	}

	// 4. Event log checks
	if len(r.EventLogs.BSODCrashDumps) == 0 {
		passed++
	}
	if r.EventLogs.CriticalEventCount == 0 {
		passed++
	}

	// 5. Integrity checks
	if len(r.Integrity.DeviceManagerErrors) == 0 {
		passed++
	}
	if !r.Integrity.PendingReboot {
		passed++
	}

	// 6. Boot & Logon checks
	if len(r.BootLogon.UnreachableResources) == 0 {
		passed++
	}
	if r.BootLogon.TotalBootDurationSeconds > 0 && r.BootLogon.TotalBootDurationSeconds <= 35.0 {
		passed++
	}

	// 7. CheckPoint VPN checks (if present)
	if r.CheckPointVPN.Detected {
		allServicesHealthy := true
		for _, s := range r.CheckPointVPN.Services {
			if !s.IsHealthy {
				allServicesHealthy = false
				break
			}
		}
		if allServicesHealthy {
			passed++
		}
	}

	return passed
}
