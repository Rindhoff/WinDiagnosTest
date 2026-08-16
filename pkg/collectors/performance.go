package collectors

import (
	"encoding/json"
	"strings"
	"time"
	"winhealth/pkg/models"
)

// CollectPerformanceDiagnostics collects top CPU/RAM processes and startup items
func CollectPerformanceDiagnostics() models.PerformanceReport {
	report := models.PerformanceReport{
		Severity:            models.SeverityOK,
		Score:               100,
		TopProcessesByCPU:   make([]models.ProcessInfo, 0),
		TopProcessesByRAM:   make([]models.ProcessInfo, 0),
		StartupPrograms:     make([]models.StartupItem, 0),
	}

	psScript := `$procs = Get-Process | Where-Object { $_.Id -ne 0 }
$totalProcs = ($procs | Measure-Object).Count
$totalThreads = ($procs | Measure-Object -Property Threads -Sum).Sum

# Top RAM
$topRAM = $procs | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 6 | ForEach-Object {
    [PSCustomObject]@{
        PID = $_.Id
        Name = $_.ProcessName
        RAMMB = [math]::Round($_.WorkingSet64 / 1MB, 1)
        CPU = [math]::Round($_.CPU, 1)
        Path = try { $_.Path } catch { "" }
    }
}

# Top CPU
$topCPU = $procs | Sort-Object -Property CPU -Descending | Select-Object -First 6 | ForEach-Object {
    [PSCustomObject]@{
        PID = $_.Id
        Name = $_.ProcessName
        RAMMB = [math]::Round($_.WorkingSet64 / 1MB, 1)
        CPU = [math]::Round($_.CPU, 1)
        Path = try { $_.Path } catch { "" }
    }
}

# Startup programs
$startup = @()
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($rp in $regPaths) {
    if (Test-Path $rp) {
        $props = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $startup += [PSCustomObject]@{
                    Name = $_.Name
                    Command = $_.Value.ToString()
                    Location = if ($rp -match 'HKLM') { "System Registry" } else { "User Registry" }
                    Enabled = $true
                    Impact = "Normal"
                }
            }
        }
    }
}

[PSCustomObject]@{
    TotalProcs = $totalProcs
    TotalThreads = $totalThreads
    TopRAM = $topRAM
    TopCPU = $topCPU
    Startup = $startup
} | ConvertTo-Json -Depth 2 -Compress`

	out, _ := RunPowerShellWithTimeout(psScript, 15*time.Second)

	type rawPerf struct {
		TotalProcs   int         `json:"TotalProcs"`
		TotalThreads int         `json:"TotalThreads"`
		TopRAM       interface{} `json:"TopRAM"`
		TopCPU       interface{} `json:"TopCPU"`
		Startup      interface{} `json:"Startup"`
	}

	if len(out) > 0 {
		var perfData rawPerf
		if err := json.Unmarshal(out, &perfData); err == nil {
			report.TotalRunningProcess = perfData.TotalProcs
			report.TotalThreadsCount = perfData.TotalThreads

			// Parse Top RAM
			if perfData.TopRAM != nil {
				type rawP struct {
					PID   int     `json:"PID"`
					Name  string  `json:"Name"`
					RAMMB float64 `json:"RAMMB"`
					CPU   float64 `json:"CPU"`
					Path  string  `json:"Path"`
				}
				b, _ := json.Marshal(perfData.TopRAM)
				var pList []rawP
				if strings.HasPrefix(string(b), "[") {
					_ = json.Unmarshal(b, &pList)
				} else if strings.HasPrefix(string(b), "{") {
					var single rawP
					if err := json.Unmarshal(b, &single); err == nil {
						pList = append(pList, single)
					}
				}
				for _, p := range pList {
					report.TopProcessesByRAM = append(report.TopProcessesByRAM, models.ProcessInfo{
						PID:        p.PID,
						Name:       p.Name,
						RAMMB:      p.RAMMB,
						CPUPercent: p.CPU,
						Path:       p.Path,
					})
				}
			}

			// Parse Top CPU
			if perfData.TopCPU != nil {
				type rawP struct {
					PID   int     `json:"PID"`
					Name  string  `json:"Name"`
					RAMMB float64 `json:"RAMMB"`
					CPU   float64 `json:"CPU"`
					Path  string  `json:"Path"`
				}
				b, _ := json.Marshal(perfData.TopCPU)
				var pList []rawP
				if strings.HasPrefix(string(b), "[") {
					_ = json.Unmarshal(b, &pList)
				} else if strings.HasPrefix(string(b), "{") {
					var single rawP
					if err := json.Unmarshal(b, &single); err == nil {
						pList = append(pList, single)
					}
				}
				for _, p := range pList {
					report.TopProcessesByCPU = append(report.TopProcessesByCPU, models.ProcessInfo{
						PID:        p.PID,
						Name:       p.Name,
						RAMMB:      p.RAMMB,
						CPUPercent: p.CPU,
						Path:       p.Path,
					})
				}
			}

			// Parse Startup
			if perfData.Startup != nil {
				type rawS struct {
					Name     string `json:"Name"`
					Command  string `json:"Command"`
					Location string `json:"Location"`
					Enabled  bool   `json:"Enabled"`
					Impact   string `json:"Impact"`
				}
				b, _ := json.Marshal(perfData.Startup)
				var sList []rawS
				if strings.HasPrefix(string(b), "[") {
					_ = json.Unmarshal(b, &sList)
				} else if strings.HasPrefix(string(b), "{") {
					var single rawS
					if err := json.Unmarshal(b, &single); err == nil {
						sList = append(sList, single)
					}
				}
				for _, s := range sList {
					report.StartupPrograms = append(report.StartupPrograms, models.StartupItem{
						Name:     s.Name,
						Command:  s.Command,
						Location: s.Location,
						Enabled:  s.Enabled,
						Impact:   s.Impact,
					})
				}
			}
		}
	}

	// Score calculation
	score := 100
	if len(report.StartupPrograms) > 15 {
		score -= 10
		report.Severity = models.SeverityWarning
	}
	if report.TotalRunningProcess > 300 {
		score -= 5
	}
	report.Score = score

	return report
}
