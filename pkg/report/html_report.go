package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"winhealth/pkg/models"

	"golang.org/x/sys/windows/registry"
)

// esc is a shorthand for html.EscapeString
func esc(s string) string {
	return html.EscapeString(s)
}

// GetDefaultDesktopDirectory returns the actual resolved desktop folder on Windows (handles OneDrive / Swedish folders)
func GetDefaultDesktopDirectory() string {
	// Try Windows User Shell Folders registry
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		val, _, err := k.GetStringValue("Desktop")
		if err == nil && val != "" {
			expanded := os.ExpandEnv(val)
			if fi, err := os.Stat(expanded); err == nil && fi.IsDir() {
				return expanded
			}
		}
	}

	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" {
		candidates := []string{
			filepath.Join(userProfile, "OneDrive", "Skrivbord"),
			filepath.Join(userProfile, "OneDrive", "Desktop"),
			filepath.Join(userProfile, "Skrivbord"),
			filepath.Join(userProfile, "Desktop"),
			filepath.Join(userProfile, "Documents"),
			filepath.Join(userProfile, "Downloads"),
		}
		for _, c := range candidates {
			if fi, err := os.Stat(c); err == nil && fi.IsDir() {
				return c
			}
		}
		return userProfile
	}

	return os.TempDir()
}

// GenerateHTMLReport creates a standalone HTML diagnostic report and optionally opens it
func GenerateHTMLReport(r *models.HealthReport, savePath string) (string, error) {
	if savePath == "" {
		desktopPath := GetDefaultDesktopDirectory()
		savePath = filepath.Join(desktopPath, fmt.Sprintf("HealthReport_%s_%s.html", r.ComputerName, time.Now().Format("20060102_150405")))
	}

	// Ensure parent directory exists
	dir := filepath.Dir(savePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("kunde inte skapa mappen '%s': %w", dir, err)
	}

	htmlContent := buildHTMLContent(r)
	err := os.WriteFile(savePath, []byte(htmlContent), 0644)
	if err != nil {
		return "", fmt.Errorf("kunde inte skriva till filen '%s': %w", savePath, err)
	}

	return savePath, nil
}

// OpenReportInBrowser opens the generated report in default Windows browser
func OpenReportInBrowser(filePath string) error {
	cmd := exec.Command("cmd", "/c", "start", "", filePath)
	return cmd.Start()
}

func buildHTMLContent(r *models.HealthReport) string {
	scoreColor := "#10b981" // Green
	if r.TotalScore < 50 {
		scoreColor = "#ef4444" // Red
	} else if r.TotalScore < 75 {
		scoreColor = "#f59e0b" // Yellow
	}

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html lang="sv">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hälsorapport - %s (%s)</title>
<style>
  :root {
    --bg-main: #0f172a;
    --bg-card: #1e293b;
    --bg-card-alt: #334155;
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --border-color: #334155;
    --accent-blue: #38bdf8;
    --accent-green: #10b981;
    --accent-yellow: #f59e0b;
    --accent-red: #ef4444;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-main);
    color: var(--text-primary);
    padding: 30px 20px;
    line-height: 1.5;
  }
  .container { max-width: 1100px; margin: 0 auto; }
  .header {
    background: linear-gradient(135deg, #1e293b, #0f172a);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
  }
  .header-info h1 { font-size: 24px; font-weight: 700; margin-bottom: 6px; }
  .header-info p { color: var(--text-secondary); font-size: 14px; }
  .score-box {
    text-align: center;
    background: var(--bg-card);
    border: 2px solid %s;
    border-radius: 12px;
    padding: 16px 24px;
    min-width: 140px;
  }
  .score-num { font-size: 38px; font-weight: 800; color: %s; }
  .score-lbl { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-secondary); }
  
  .grid-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 18px;
    margin-bottom: 24px;
  }
  .card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 20px;
  }
  .card-title {
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 10px;
  }
  .badge {
    font-size: 11px;
    font-weight: 600;
    padding: 3px 8px;
    border-radius: 4px;
    text-transform: uppercase;
  }
  .badge-ok { background: rgba(16, 185, 129, 0.2); color: #34d399; }
  .badge-warning { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
  .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; }
  .badge-info { background: rgba(56, 189, 248, 0.2); color: #38bdf8; }

  .stat-row {
    display: flex;
    justify-content: space-between;
    font-size: 13px;
    padding: 6px 0;
    border-bottom: 1px solid rgba(255,255,255,0.04);
  }
  .stat-row:last-child { border-bottom: none; }
  .stat-label { color: var(--text-secondary); }
  .stat-val { font-weight: 500; }

  .progress-bar {
    height: 8px;
    background: #334155;
    border-radius: 4px;
    margin: 8px 0;
    overflow: hidden;
  }
  .progress-fill {
    height: 100%%;
    border-radius: 4px;
    background: var(--accent-blue);
  }

  .table-container {
    width: 100%%;
    overflow-x: auto;
    margin-top: 10px;
  }
  table {
    width: 100%%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th {
    text-align: left;
    padding: 8px;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border-color);
  }
  td {
    padding: 8px;
    border-bottom: 1px solid rgba(255,255,255,0.04);
  }
  .log-box {
    background: #090d16;
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 12px;
    font-family: monospace;
    font-size: 12px;
    max-height: 250px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
    color: #e2e8f0;
  }
  .issue-item {
    background: rgba(239, 68, 68, 0.08);
    border-left: 4px solid var(--accent-red);
    padding: 12px;
    border-radius: 4px;
    margin-bottom: 10px;
  }
  .issue-item.warning {
    background: rgba(245, 158, 11, 0.08);
    border-left-color: var(--accent-yellow);
  }
  .issue-item.info {
    background: rgba(56, 189, 248, 0.08);
    border-left-color: var(--accent-blue);
  }
  .issue-title { font-weight: 600; font-size: 14px; margin-bottom: 4px; }
  .issue-desc { font-size: 13px; color: var(--text-secondary); }
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="header-info">
      <h1>Hälsorapport: %s</h1>
      <p>%s &bull; %s &bull; Uptime: %s</p>
      <p style="margin-top: 4px; font-size: 12px;">Skannad: %s</p>
    </div>
    <div class="score-box">
      <div class="score-num">%d/100</div>
      <div class="score-lbl">%s</div>
    </div>
  </div>
`, esc(r.ComputerName), esc(r.Timestamp.Format("2006-01-02 15:04")), scoreColor, scoreColor, esc(r.ComputerName), esc(r.OSVersion), esc(r.OSBuild), esc(r.Uptime), esc(r.Timestamp.Format("2006-01-02 15:04:05")), r.TotalScore, esc(r.ScoreRating)))

	// Top Issues Section
	if len(r.TopIssues) > 0 {
		sb.WriteString(`<div class="card" style="margin-bottom: 24px;">
    <div class="card-title">
      <span>⚠️ Identifierade Avvikelser & Rekommendationer</span>
      <span class="badge badge-warning">`)
		sb.WriteString(fmt.Sprintf("%d punkter", len(r.TopIssues)))
		sb.WriteString(`</span>
    </div>`)
		for _, issue := range r.TopIssues {
			cls := "critical"
			if issue.Severity == models.SeverityWarning {
				cls = "warning"
			} else if issue.Severity == models.SeverityInfo {
				cls = "info"
			}
			sb.WriteString(fmt.Sprintf(`
    <div class="issue-item %s">
      <div class="issue-title">[%s] %s</div>
      <div class="issue-desc">%s</div>
    </div>`, cls, esc(issue.Category), esc(issue.Title), esc(issue.Description)))
		}
		sb.WriteString(`</div>`)
	}

	// Check Point VPN Card
	sb.WriteString(`<div class="grid-cards">`)
	sb.WriteString(`<div class="card">
    <div class="card-title">
      <span>🔒 Check Point VPN</span>`)
	if r.CheckPointVPN.Detected {
		sb.WriteString(fmt.Sprintf(`<span class="badge badge-%s">%d/100</span>`, getBadgeClass(r.CheckPointVPN.Severity), r.CheckPointVPN.Score))
	} else {
		sb.WriteString(`<span class="badge badge-info">Ej installerad</span>`)
	}
	sb.WriteString(`</div>`)

	if r.CheckPointVPN.Detected {
		sb.WriteString(fmt.Sprintf(`
    <div class="stat-row"><span class="stat-label">Klientversion:</span><span class="stat-val">%s</span></div>
    <div class="stat-row"><span class="stat-label">Installationskatalog:</span><span class="stat-val" style="font-size:11px;">%s</span></div>
    <div class="stat-row"><span class="stat-label">Rekommendation:</span><span class="stat-val">%s</span></div>`,
			esc(defaultIfEmpty(r.CheckPointVPN.ClientVersion, "Identifierad")),
			esc(defaultIfEmpty(r.CheckPointVPN.InstallPath, "Standard")),
			esc(r.CheckPointVPN.RecommendedAction)))

		if len(r.CheckPointVPN.Services) > 0 {
			sb.WriteString(`<div style="margin-top:12px; font-size:12px; font-weight:600; color:var(--text-secondary);">Tjänster:</div>`)
			for _, s := range r.CheckPointVPN.Services {
				icon := "🟢"
				if !s.IsHealthy {
					icon = "🔴"
				}
				sb.WriteString(fmt.Sprintf(`<div class="stat-row"><span>%s %s</span><span>%s</span></div>`, icon, esc(s.DisplayName), esc(s.Status)))
			}
		}
	} else {
		sb.WriteString(`<div style="padding: 12px 0; color: var(--text-secondary); font-size:13px;">Check Point VPN-klienten är inte installerad på systemet.</div>`)
	}
	sb.WriteString(`</div>`)

	// Hardware Card
	sb.WriteString(fmt.Sprintf(`
  <div class="card">
    <div class="card-title">
      <span>💾 Hårdvara & Resurser</span>
      <span class="badge badge-%s">%d/100</span>
    </div>
    <div class="stat-row"><span class="stat-label">Processor:</span><span class="stat-val">%s (%d kärnor)</span></div>
    <div class="stat-row"><span class="stat-label">Moderkort:</span><span class="stat-val">%s</span></div>
    <div class="stat-row"><span class="stat-label">RAM-användning:</span><span class="stat-val">%.1f GB av %.1f GB (%.0f%%)</span></div>
    <div class="progress-bar"><div class="progress-fill" style="width: %.0f%%;"></div></div>`,
		getBadgeClass(r.Hardware.Severity), r.Hardware.Score, esc(r.Hardware.CPUModel), r.Hardware.CPUCores, esc(r.Hardware.Motherboard),
		r.Hardware.UsedRAMGB, r.Hardware.TotalRAMGB, r.Hardware.RAMUsagePct, r.Hardware.RAMUsagePct))

	for _, d := range r.Hardware.Disks {
		smartIco := "🟢"
		if !d.SmartHealthy {
			smartIco = "🔴 SMART Fel"
		}
		sb.WriteString(fmt.Sprintf(`
    <div class="stat-row" style="margin-top:6px;"><span class="stat-label">Enhet %s (%s):</span><span class="stat-val">%s %.1f GB ledigt av %.1f GB</span></div>
    <div class="progress-bar"><div class="progress-fill" style="width: %.0f%%; background: %s;"></div></div>`,
			esc(d.DriveLetter), esc(d.Model), smartIco, d.FreeGB, d.TotalGB, d.UsagePct, getProgressColor(d.UsagePct)))
	}

	if r.Hardware.Battery != nil && r.Hardware.Battery.Present {
		sb.WriteString(fmt.Sprintf(`
    <div class="stat-row"><span class="stat-label">Batterihälsa:</span><span class="stat-val">%d%% (%s, Hälsa: %.0f%%)</span></div>`,
			r.Hardware.Battery.ChargePercent, esc(r.Hardware.Battery.Status), r.Hardware.Battery.HealthPct))
	}
	sb.WriteString(`</div>`)

	// Network Card
	sb.WriteString(fmt.Sprintf(`
  <div class="card">
    <div class="card-title">
      <span>🌐 Nätverk & Anslutning</span>
      <span class="badge badge-%s">%d/100</span>
    </div>
    <div class="stat-row"><span class="stat-label">Internetanslutning:</span><span class="stat-val">%s</span></div>
    <div class="stat-row"><span class="stat-label">Standardgateway:</span><span class="stat-val">%s (Ping: %d ms)</span></div>`,
		getBadgeClass(r.Network.Severity), r.Network.Score,
		boolToStatus(r.Network.InternetOK, "Ansluten", "Ej ansluten"),
		esc(defaultIfEmpty(r.Network.DefaultGateway, "Ingen")), r.Network.GatewayPingMs))

	for _, dns := range r.Network.DNSServers {
		status := "🟢"
		if !dns.Reachable {
			status = "🔴"
		}
		sb.WriteString(fmt.Sprintf(`<div class="stat-row"><span class="stat-label">%s:</span><span class="stat-val">%s %d ms</span></div>`, esc(dns.Server), status, dns.LatencyMs))
	}
	sb.WriteString(`</div>`)

	// Security Card
	sb.WriteString(fmt.Sprintf(`
  <div class="card">
    <div class="card-title">
      <span>🛡️ Säkerhet & Uppdateringar</span>
      <span class="badge badge-%s">%d/100</span>
    </div>
    <div class="stat-row"><span class="stat-label">Antivirus:</span><span class="stat-val">%s (%s)</span></div>
    <div class="stat-row"><span class="stat-label">Realtidsskydd:</span><span class="stat-val">%s</span></div>
    <div class="stat-row"><span class="stat-label">BitLocker-kryptering:</span><span class="stat-val">%s</span></div>
    <div class="stat-row"><span class="stat-label">Windows Brandvägg:</span><span class="stat-val">%s</span></div>
    <div class="stat-row"><span class="stat-label">Senast uppdaterad:</span><span class="stat-val">%s</span></div>
    <div class="stat-row"><span class="stat-label">Senaste uppdateringssökning:</span><span class="stat-val">%s</span></div>
    <div class="stat-row"><span class="stat-label">Väntande uppdateringar:</span><span class="stat-val">%s</span></div>
    <div class="stat-row"><span class="stat-label">Väntande omstarter:</span><span class="stat-val">%s</span></div>
  </div>`,
		getBadgeClass(r.Security.Severity), r.Security.Score,
		esc(r.Security.AntivirusName), boolToStatus(r.Security.AntivirusEnabled, "Aktiv", "Inaktiv"),
		boolToStatus(r.Security.RealtimeProtection, "Aktivt", "Inaktivt"),
		esc(r.Security.BitLockerStatus),
		boolToStatus(r.Security.FirewallEnabled, "Aktiverad", "Inaktiverad"),
		esc(defaultIfEmpty(r.Security.LastUpdateInstallTime, "Okänt / Nyligen")),
		esc(defaultIfEmpty(r.Security.LastUpdateSearchTime, "Nyligen")),
		esc(fmt.Sprintf("%d st (%s)", r.Security.PendingUpdatesCount, defaultIfEmpty(r.Security.WindowsUpdateOverallStatus, "Aktuell"))),
		boolToStatus(r.Integrity.PendingReboot, "Ja (Krävs)", "Nej")))

	// Event Logs Card
	sb.WriteString(fmt.Sprintf(`
  <div class="card">
    <div class="card-title">
      <span>⚠️ Krascher & Loggar</span>
      <span class="badge badge-%s">%d/100</span>
    </div>
    <div class="stat-row"><span class="stat-label">BSOD Minidump-krascher:</span><span class="stat-val">%d st</span></div>
    <div class="stat-row"><span class="stat-label">Kritiska systemfel (48h):</span><span class="stat-val">%d st</span></div>
    <div class="stat-row"><span class="stat-label">Applikationskrascher (48h):</span><span class="stat-val">%d st</span></div>
    <div class="stat-row"><span class="stat-label">Temporära filer:</span><span class="stat-val">%s</span></div>
  </div>`,
		getBadgeClass(r.EventLogs.Severity), r.EventLogs.Score,
		len(r.EventLogs.BSODCrashDumps), r.EventLogs.CriticalEventCount, len(r.EventLogs.RecentAppCrashes), esc(r.Integrity.TempFilesSizeDisplay)))

	// Boot & Logon Analysis Card
	sb.WriteString(fmt.Sprintf(`
  <div class="card">
    <div class="card-title">
      <span>⏱️ Uppstart & Inloggning</span>
      <span class="badge badge-%s">%d/100</span>
    </div>
    <div class="stat-row"><span class="stat-label">Total uppstartstid:</span><span class="stat-val">%.1f sekunder</span></div>
    <div class="stat-row"><span class="stat-label">Huvudfas (BIOS/Kärna):</span><span class="stat-val">%.1f s</span></div>
    <div class="stat-row"><span class="stat-label">Inloggning & Profil:</span><span class="stat-val">%.1f s</span></div>
    <div class="stat-row"><span class="stat-label">Post-Boot / Autostart:</span><span class="stat-val">%.1f s</span></div>
    <div class="stat-row"><span class="stat-label">Windows Snabbstart:</span><span class="stat-val">%s</span></div>
    <div class="stat-row"><span class="stat-label">Domän:</span><span class="stat-val">%s (%s)</span></div>
    <div class="stat-row"><span class="stat-label">WPR Boot-spårning:</span><span class="stat-val">%s</span></div>`,
		getBadgeClass(r.BootLogon.Severity), r.BootLogon.Score,
		r.BootLogon.TotalBootDurationSeconds,
		r.BootLogon.MainPathBootSeconds,
		r.BootLogon.UserLogonWaitSeconds,
		r.BootLogon.PostBootDelaySeconds,
		boolToStatus(r.BootLogon.FastStartupEnabled, "Aktiverat", "Inaktiverat"),
		boolToStatus(r.BootLogon.IsDomainJoined, "Domänansluten", "Lokal arbetsgrupp"),
		esc(defaultIfEmpty(r.BootLogon.DomainName, "WORKGROUP")),
		esc(defaultIfEmpty(r.BootLogon.BootTrace.StatusMessage, "Redo"))))

	if len(r.BootLogon.UnreachableResources) > 0 {
		sb.WriteString(`<div style="margin-top:10px; color:#ef4444; font-size:12px; font-weight:600;">⚠️ Onåbara nätverksresurser (Timeouter):</div>`)
		for _, un := range r.BootLogon.UnreachableResources {
			sb.WriteString(fmt.Sprintf(`<div class="stat-row"><span class="stat-label" style="color:#f87171;">🔴 %s:</span><span class="stat-val" style="font-size:11px;">%s (Nås ej)</span></div>`, esc(un.Name), esc(un.TargetUNC)))
		}
	}

	sb.WriteString(`</div>`) // end BootLogon card

	sb.WriteString(`</div>`) // end grid-cards

	// Boot Degradations Culprits section
	if len(r.BootLogon.BootDegradations) > 0 {
		sb.WriteString(`<div class="card" style="margin-bottom: 24px;">
    <div class="card-title"><span>⚠️ Identifierade Tidstjuvar vid Boot (Drivrutiner, Tjänster & Appar)</span></div>
    <div class="table-container">
      <table>
        <thead>
          <tr><th>Typ</th><th>Komponent</th><th>Fördröjning</th><th>Beskrivning</th></tr>
        </thead>
        <tbody>`)
		for _, deg := range r.BootLogon.BootDegradations {
			sb.WriteString(fmt.Sprintf(`<tr>
        <td><span class="badge badge-warning">%s</span></td>
        <td><strong>%s</strong></td>
        <td style="color:#f59e0b; font-weight:600;">+%d ms</td>
        <td>%s</td>
      </tr>`, esc(deg.Type), esc(deg.Name), deg.DurationMs, esc(deg.Description)))
		}
		sb.WriteString(`</tbody></table></div></div>`)
	}

	// Deep WPR Boot Trace Details (if trace data exists)
	if r.BootLogon.BootTrace.HasTraceData {
		sb.WriteString(fmt.Sprintf(`<div class="card" style="margin-bottom: 24px;">
    <div class="card-title">
      <span>🔬 Djupgående Boot-Spårning (Windows Performance Recorder)</span>
      <span class="badge badge-ok">Analyserad</span>
    </div>
    <div class="stat-row"><span class="stat-label">Spårningsfil:</span><span class="stat-val" style="font-size:11px;"><code>%s</code></span></div>
    <div class="stat-row"><span class="stat-label">Filstorlek:</span><span class="stat-val">%s</span></div>
    <div class="stat-row"><span class="stat-label">Inspelad:</span><span class="stat-val">%s</span></div>`,
			esc(r.BootLogon.BootTrace.TraceFilePath),
			esc(r.BootLogon.BootTrace.TraceFileSize),
			esc(r.BootLogon.BootTrace.TraceRecordedAt)))

		if len(r.BootLogon.BootTrace.SlowestDrivers) > 0 {
			sb.WriteString(`<div style="margin-top:12px; font-size:12px; font-weight:600; color:var(--text-secondary);">Mätta Drivrutiner:</div>
    <div class="table-container"><table><thead><tr><th>Drivrutin</th><th>Kategori</th><th>Laddningstid</th><th>Sökväg</th></tr></thead><tbody>`)
			for _, d := range r.BootLogon.BootTrace.SlowestDrivers {
				sb.WriteString(fmt.Sprintf(`<tr><td><strong>%s</strong></td><td><span class="badge badge-info">%s</span></td><td style="color:#38bdf8; font-weight:600;">%d ms</td><td style="font-size:10px;"><code>%s</code></td></tr>`, esc(d.Name), esc(d.Category), d.DurationMs, esc(defaultIfEmpty(d.Path, "-"))))
			}
			sb.WriteString(`</tbody></table></div>`)
		}

		if len(r.BootLogon.BootTrace.SlowestServices) > 0 {
			sb.WriteString(`<div style="margin-top:12px; font-size:12px; font-weight:600; color:var(--text-secondary);">Mätta Tjänster:</div>
    <div class="table-container"><table><thead><tr><th>Tjänst</th><th>Kategori</th><th>Starttid</th><th>Sökväg</th></tr></thead><tbody>`)
			for _, s := range r.BootLogon.BootTrace.SlowestServices {
				sb.WriteString(fmt.Sprintf(`<tr><td><strong>%s</strong></td><td><span class="badge badge-info">%s</span></td><td style="color:#38bdf8; font-weight:600;">%d ms</td><td style="font-size:10px;"><code>%s</code></td></tr>`, esc(s.Name), esc(s.Category), s.DurationMs, esc(defaultIfEmpty(s.Path, "-"))))
			}
			sb.WriteString(`</tbody></table></div>`)
		}

		sb.WriteString(`</div>`)
	}

	// Advanced Autoruns 30+ Locations Table (Sysinternals Style)
	if len(r.BootLogon.AdvancedAutoruns) > 0 {
		sb.WriteString(`<div class="card" style="margin-bottom: 24px;">
    <div class="card-title"><span>🔍 Avancerad Autoruns-skanning (30+ Platser, Sysinternals-stil)</span><span class="badge badge-info">`)
		sb.WriteString(fmt.Sprintf(`%d punkter</span></div>
    <div class="table-container">
      <table>
        <thead>
          <tr><th>Kategori</th><th>Namn</th><th>Utgivare</th><th>Sökväg / Registrering</th><th>Verifiering</th></tr>
        </thead>
        <tbody>`, len(r.BootLogon.AdvancedAutoruns)))
		for _, item := range r.BootLogon.AdvancedAutoruns {
			signBadge := `<span class="badge badge-ok">✔ Verifierad</span>`
			if item.SignStatus != "Verified" {
				signBadge = `<span class="badge badge-warning">⚪ 3:e part / Okänd</span>`
			}
			sb.WriteString(fmt.Sprintf(`<tr>
        <td><span class="badge badge-info">%s</span></td>
        <td><strong>%s</strong></td>
        <td>%s</td>
        <td style="font-size:11px; max-width:350px; word-break:break-all;"><code>%s</code></td>
        <td>%s</td>
      </tr>`, esc(item.Category), esc(item.Name), esc(defaultIfEmpty(item.Publisher, "-")), esc(item.Path), signBadge))
		}
		sb.WriteString(`</tbody></table></div></div>`)
	}

	// Recent Logs Dump section
	if len(r.CheckPointVPN.RecentLogErrors) > 0 {
		sb.WriteString(`<div class="card" style="margin-bottom: 24px;">
    <div class="card-title"><span>📝 Senaste Check Point VPN Fel-loggar</span></div>
    <div class="log-box">`)
		for _, l := range r.CheckPointVPN.RecentLogErrors {
			sb.WriteString(esc(l) + "\n")
		}
		sb.WriteString(`</div></div>`)
	}

	sb.WriteString(`
</div>
</body>
</html>`)

	return sb.String()
}

func getBadgeClass(sev models.Severity) string {
	switch sev {
	case models.SeverityCritical:
		return "critical"
	case models.SeverityWarning:
		return "warning"
	case models.SeverityInfo:
		return "info"
	default:
		return "ok"
	}
}

func getProgressColor(pct float64) string {
	if pct > 90 {
		return "#ef4444"
	} else if pct > 75 {
		return "#f59e0b"
	}
	return "#38bdf8"
}

func boolToStatus(b bool, trueStr, falseStr string) string {
	if b {
		return "🟢 " + trueStr
	}
	return "🔴 " + falseStr
}

func defaultIfEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// ExportJSON exports the report data as JSON
func ExportJSON(r *models.HealthReport, savePath string) (string, error) {
	if savePath == "" {
		desktopPath := GetDefaultDesktopDirectory()
		savePath = filepath.Join(desktopPath, fmt.Sprintf("HealthReport_%s_%s.json", r.ComputerName, time.Now().Format("20060102_150405")))
	}

	dir := filepath.Dir(savePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("kunde inte skapa mappen '%s': %w", dir, err)
	}

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	err = os.WriteFile(savePath, data, 0644)
	if err != nil {
		return "", fmt.Errorf("kunde inte skriva till filen '%s': %w", savePath, err)
	}
	return savePath, nil
}
