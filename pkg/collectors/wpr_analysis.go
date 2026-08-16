package collectors

import (
	"context"
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"winhealth/pkg/models"
)

// CPUUsageByProcess.wpaProfile is derived from Google's UIforETW project
// (Apache-2.0). See THIRD_PARTY_NOTICES.md.
//
//go:embed assets/CPUUsageByProcess.wpaProfile
var cpuUsageByProcessProfile []byte

type wprTraceAnalysis struct {
	ExporterPath    string
	AnalysisSource  string
	AnalysisError   string
	TopProcesses    []models.BootTimingItem
	SlowestDrivers  []models.BootTimingItem
	SlowestServices []models.BootTimingItem
	NetworkFindings []models.BootNetworkFinding
}

func findWPAExporter() string {
	if p, err := exec.LookPath("wpaexporter.exe"); err == nil {
		return p
	}

	programFiles := os.Getenv("ProgramFiles")
	programFilesX86 := os.Getenv("ProgramFiles(x86)")
	candidates := []string{
		filepath.Join(programFilesX86, "Windows Kits", "10", "Windows Performance Toolkit", "wpaexporter.exe"),
		filepath.Join(programFiles, "Windows Kits", "10", "Windows Performance Toolkit", "wpaexporter.exe"),
		filepath.Join(programFilesX86, "Windows Kits", "11", "Windows Performance Toolkit", "wpaexporter.exe"),
		filepath.Join(programFiles, "Windows Kits", "11", "Windows Performance Toolkit", "wpaexporter.exe"),
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate
		}
	}
	return ""
}

func findWPA() string {
	if p, err := exec.LookPath("wpa.exe"); err == nil {
		return p
	}
	programFiles := os.Getenv("ProgramFiles")
	programFilesX86 := os.Getenv("ProgramFiles(x86)")
	for _, candidate := range []string{
		filepath.Join(programFilesX86, "Windows Kits", "10", "Windows Performance Toolkit", "wpa.exe"),
		filepath.Join(programFiles, "Windows Kits", "10", "Windows Performance Toolkit", "wpa.exe"),
		filepath.Join(programFilesX86, "Windows Kits", "11", "Windows Performance Toolkit", "wpa.exe"),
		filepath.Join(programFiles, "Windows Kits", "11", "Windows Performance Toolkit", "wpa.exe"),
	} {
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate
		}
	}
	return ""
}

func analyzeWPRTrace(tracePath string) wprTraceAnalysis {
	analysis := wprTraceAnalysis{
		ExporterPath:    findWPAExporter(),
		TopProcesses:    make([]models.BootTimingItem, 0),
		NetworkFindings: collectBootNetworkFindings(GetSystemBootTime()),
	}
	analysis.SlowestDrivers, analysis.SlowestServices = AnalyzeBootDriversAndServices()

	if analysis.ExporterPath == "" {
		analysis.AnalysisSource = "Windows Event Log (begränsad reservanalys)"
		analysis.AnalysisError = "WPA Exporter saknas. Installera Windows Performance Toolkit för automatisk ETL-analys. ETL-filen har sparats och kan analyseras senare."
		return analysis
	}

	top, err := exportCPUUsageWithWPA(analysis.ExporterPath, tracePath)
	if err != nil {
		analysis.AnalysisSource = "Windows Event Log (WPA Exporter misslyckades)"
		analysis.AnalysisError = err.Error()
		return analysis
	}
	analysis.TopProcesses = top
	analysis.AnalysisSource = "WPA Exporter: CPU Usage (Precise) från ETL; drivrutiner/tjänster/nätverk kompletteras från Windows Event Log"
	return analysis
}

func exportCPUUsageWithWPA(exporterPath, tracePath string) ([]models.BootTimingItem, error) {
	if fi, err := os.Stat(tracePath); err != nil || fi.Size() < 1024 {
		return nil, fmt.Errorf("ETL-filen saknas eller är för liten för analys: %s", tracePath)
	}

	analysisDir := filepath.Join(filepath.Dir(tracePath), "Analysis", strings.TrimSuffix(filepath.Base(tracePath), filepath.Ext(tracePath)))
	if err := os.MkdirAll(analysisDir, 0755); err != nil {
		return nil, fmt.Errorf("kunde inte skapa analysmappen: %w", err)
	}
	profilePath := filepath.Join(analysisDir, "CPUUsageByProcess.wpaProfile")
	if err := os.WriteFile(profilePath, cpuUsageByProcessProfile, 0644); err != nil {
		return nil, fmt.Errorf("kunde inte skriva WPA-analysprofilen: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exporterPath, "-i", tracePath, "-profile", profilePath, "-outputfolder", analysisDir)
	cmd.SysProcAttr = hiddenWindowProcAttr()
	logPath := filepath.Join(analysisDir, "wpaexporter.log")
	logFile, createErr := os.Create(logPath)
	if createErr != nil {
		return nil, fmt.Errorf("kunde inte skapa WPA Exporter-loggen: %w", createErr)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	err := cmd.Run()
	_ = logFile.Close()
	logTail := readFileTail(logPath, 16*1024)
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("WPA Exporter överskred tidsgränsen 20 minuter")
	}
	if err != nil {
		return nil, fmt.Errorf("WPA Exporter misslyckades: %v (%s)", err, strings.TrimSpace(logTail))
	}

	csvFiles, _ := filepath.Glob(filepath.Join(analysisDir, "*.csv"))
	if len(csvFiles) == 0 {
		return nil, fmt.Errorf("WPA Exporter skapade ingen CPU Usage-tabell")
	}
	for _, csvPath := range csvFiles {
		items, parseErr := parseWPAProcessCSV(csvPath)
		if parseErr == nil && len(items) > 0 {
			return items, nil
		}
	}
	return nil, fmt.Errorf("WPA Exporters CPU-tabell kunde inte tolkas")
}

func parseWPAProcessCSV(path string) ([]models.BootTimingItem, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseWPAProcessCSVData(string(data))
}

func parseWPAProcessCSVData(data string) ([]models.BootTimingItem, error) {
	data = strings.TrimPrefix(data, "\ufeff")
	firstLine := data
	if idx := strings.IndexByte(firstLine, '\n'); idx >= 0 {
		firstLine = firstLine[:idx]
	}
	delimiter := ','
	if strings.Count(firstLine, "\t") > strings.Count(firstLine, ",") {
		delimiter = '\t'
	} else if strings.Count(firstLine, ";") > strings.Count(firstLine, ",") {
		delimiter = ';'
	}
	r := csv.NewReader(strings.NewReader(data))
	r.Comma = delimiter
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("ogiltig WPA CSV: %w", err)
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("WPA CSV innehåller inga datarader")
	}

	processCol, countCol, cpuCol := -1, -1, -1
	for i, header := range records[0] {
		h := strings.ToLower(strings.TrimSpace(header))
		switch {
		case strings.Contains(h, "new process") || h == "process":
			processCol = i
		case h == "count" || strings.Contains(h, "context switch"):
			countCol = i
		case strings.Contains(h, "cpu usage") && cpuCol < 0:
			cpuCol = i
		}
	}
	if processCol < 0 || cpuCol < 0 {
		return nil, fmt.Errorf("WPA CSV saknar process- eller CPU-kolumn")
	}

	items := make([]models.BootTimingItem, 0, len(records)-1)
	for _, record := range records[1:] {
		if processCol >= len(record) || cpuCol >= len(record) {
			continue
		}
		name := strings.TrimSpace(record[processCol])
		if name == "" || strings.HasPrefix(strings.ToLower(name), "idle ") {
			continue
		}
		cpuMs, parseErr := parseWPAFloat(record[cpuCol])
		if parseErr != nil || cpuMs <= 0 {
			continue
		}
		count := 0
		if countCol >= 0 && countCol < len(record) {
			countFloat, _ := parseWPAFloat(record[countCol])
			count = int(countFloat)
		}
		items = append(items, models.BootTimingItem{
			Name:        name,
			Category:    "Process (CPU)",
			DurationMs:  int(cpuMs + 0.5),
			DurationSec: cpuMs / 1000,
			Description: fmt.Sprintf("%.1f ms CPU-tid och %d kontextväxlingar under den inspelade uppstarten.", cpuMs, count),
			Source:      "WPA Exporter / CPU Usage (Precise)",
			Count:       count,
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].DurationMs > items[j].DurationMs })
	if len(items) > 15 {
		items = items[:15]
	}
	return items, nil
}

func parseWPAFloat(raw string) (float64, error) {
	s := strings.TrimSpace(strings.ReplaceAll(raw, "\u00a0", ""))
	s = strings.ReplaceAll(s, " ", "")
	if strings.Contains(s, ",") && strings.Contains(s, ".") {
		if strings.LastIndex(s, ",") > strings.LastIndex(s, ".") {
			s = strings.ReplaceAll(s, ".", "")
			s = strings.ReplaceAll(s, ",", ".")
		} else {
			s = strings.ReplaceAll(s, ",", "")
		}
	} else if strings.Contains(s, ",") {
		// WPA Exporter follows the Windows locale. In Swedish output, duration
		// values use a decimal comma and may contain six fractional digits.
		s = strings.ReplaceAll(s, ",", ".")
	}
	return strconv.ParseFloat(s, 64)
}

func readFileTail(path string, maxBytes int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	start := fi.Size() - maxBytes
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, 0); err != nil {
		return ""
	}
	data, _ := io.ReadAll(f)
	return string(data)
}

func collectBootNetworkFindings(since time.Time) []models.BootNetworkFinding {
	start := since.UTC().Format(time.RFC3339)
	psScript := fmt.Sprintf(`$start = [datetime]::Parse('%s')
$events = @()
$logs = @(
  'Microsoft-Windows-GroupPolicy/Operational',
  'Microsoft-Windows-SMBClient/Connectivity',
  'Microsoft-Windows-DNS-Client/Operational',
  'Microsoft-Windows-WLAN-AutoConfig/Operational'
)
foreach ($logName in $logs) {
  if (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue) {
    $events += Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=$start} -MaxEvents 30 -ErrorAction SilentlyContinue |
      Where-Object { $_.Level -le 3 -or $_.Id -in @(4004,4201,8001,8002,1058,1129,30803,30804,30805,30806) }
  }
}
$events += Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$start} -MaxEvents 100 -ErrorAction SilentlyContinue |
  Where-Object { $_.ProviderName -match '(?i)(Netlogon|Tcpip|DNS|LanmanWorkstation|NlaSvc)' -and $_.Level -le 3 }
$events | Sort-Object TimeCreated | Select-Object -First 50 @{N='Provider';E={$_.ProviderName}}, @{N='EventID';E={$_.Id}}, TimeCreated, Message | ConvertTo-Json -Compress`, start)
	out, err := RunPowerShellWithTimeout(psScript, 15*time.Second)
	if err != nil || len(out) == 0 {
		return []models.BootNetworkFinding{}
	}
	type rawFinding struct {
		Provider    string    `json:"Provider"`
		EventID     int64     `json:"EventID"`
		TimeCreated time.Time `json:"TimeCreated"`
		Message     string    `json:"Message"`
	}
	var raw []rawFinding
	if out[0] == '[' {
		_ = json.Unmarshal(out, &raw)
	} else {
		var single rawFinding
		if json.Unmarshal(out, &single) == nil {
			raw = append(raw, single)
		}
	}
	durationRE := regexp.MustCompile(`(?i)(\d[\d,.]*)\s*(?:ms|millisecond)`)
	findings := make([]models.BootNetworkFinding, 0, len(raw))
	for _, item := range raw {
		message := strings.Join(strings.Fields(item.Message), " ")
		duration := 0
		if match := durationRE.FindStringSubmatch(message); len(match) > 1 {
			value, _ := parseWPAFloat(match[1])
			duration = int(value)
		}
		findings = append(findings, models.BootNetworkFinding{
			Provider: item.Provider, EventID: item.EventID, TimeCreated: item.TimeCreated,
			DurationMs: duration, Message: message, Source: "Windows Event Log under uppstart",
		})
	}
	return findings
}
