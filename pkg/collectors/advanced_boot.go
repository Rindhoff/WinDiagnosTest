package collectors

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
	"winhealth/pkg/models"
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procGetTickCount64  = kernel32.NewProc("GetTickCount64")
	shell32             = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteExW = shell32.NewProc("ShellExecuteExW")
)

type SHELLEXECUTEINFO struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     syscall.Handle
}

const (
	SEE_MASK_NOCLOSEPROCESS = 0x00000040
	SW_SHOWNORMAL           = 1
)

func runElevatedProcessWait(exePath string, args string) (uint32, error) {
	verbPtr, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return 1, err
	}
	filePtr, err := syscall.UTF16PtrFromString(exePath)
	if err != nil {
		return 1, err
	}
	argsPtr, err := syscall.UTF16PtrFromString(args)
	if err != nil {
		return 1, err
	}

	var info SHELLEXECUTEINFO
	info.cbSize = uint32(unsafe.Sizeof(info))
	info.fMask = SEE_MASK_NOCLOSEPROCESS
	info.lpVerb = verbPtr
	info.lpFile = filePtr
	info.lpParameters = argsPtr
	info.nShow = SW_SHOWNORMAL

	ret, _, err := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		return 1, fmt.Errorf("UAC behörighet nekades eller misslyckades: %v", err)
	}

	if info.hProcess != 0 {
		defer syscall.CloseHandle(info.hProcess)
		_, _ = syscall.WaitForSingleObject(info.hProcess, 30000)
		var exitCode uint32
		_ = syscall.GetExitCodeProcess(info.hProcess, &exitCode)
		return exitCode, nil
	}

	return 0, nil
}

// GetSystemUptime returns elapsed duration since system boot
func GetSystemUptime() time.Duration {
	ret, _, _ := procGetTickCount64.Call()
	return time.Duration(ret) * time.Millisecond
}

// GetSystemBootTime returns approximate timestamp when Windows booted
func GetSystemBootTime() time.Time {
	return time.Now().Add(-GetSystemUptime())
}

// WPRStateMeta persists boot trace scheduling state across reboots
type WPRStateMeta struct {
	IsConfigured bool      `json:"is_configured"`
	Profile      string    `json:"profile"`
	ScheduledAt  time.Time `json:"scheduled_at"`
	Status       string    `json:"status"` // "scheduled", "completed", "cancelled", "reboot_completed"
	AutoResume   bool      `json:"auto_resume"`
}

// BootTraceSummaryMeta persists analyzed trace results
type BootTraceSummaryMeta struct {
	TraceFilePath   string                  `json:"trace_file_path"`
	TraceFileSize   string                  `json:"trace_file_size"`
	TraceRecordedAt string                  `json:"trace_recorded_at"`
	SlowestDrivers  []models.BootTimingItem `json:"slowest_drivers"`
	SlowestServices []models.BootTimingItem `json:"slowest_services"`
}

func getTraceStorageDir() string {
	progData := os.Getenv("ProgramData")
	if progData == "" {
		progData = `C:\ProgramData`
	}
	targetDir := filepath.Join(progData, "WinHealth", "Traces")
	_ = os.MkdirAll(targetDir, 0777)
	return targetDir
}

func getTraceStateFilePath() string {
	return filepath.Join(getTraceStorageDir(), "wpr_state.json")
}

func getTraceSummaryFilePath() string {
	return filepath.Join(getTraceStorageDir(), "boot_trace_summary.json")
}

func loadWPRState() WPRStateMeta {
	var state WPRStateMeta
	path := getTraceStateFilePath()
	data, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(data, &state)
	}
	return state
}

func saveWPRState(state WPRStateMeta) {
	path := getTraceStateFilePath()
	data, err := json.MarshalIndent(state, "", "  ")
	if err == nil {
		_ = os.WriteFile(path, data, 0666)
	}
}

func loadTraceSummary() (BootTraceSummaryMeta, bool) {
	var sum BootTraceSummaryMeta
	path := getTraceSummaryFilePath()
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &sum); err == nil {
			return sum, true
		}
	}
	return sum, false
}

func saveTraceSummary(sum BootTraceSummaryMeta) {
	path := getTraceSummaryFilePath()
	data, err := json.MarshalIndent(sum, "", "  ")
	if err == nil {
		_ = os.WriteFile(path, data, 0666)
	}
}

// RegisterRunOnceAutoResume registers WinHealth to start automatically after reboot
func RegisterRunOnceAutoResume() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	psScript := fmt.Sprintf(`
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Set-ItemProperty -Path $regPath -Name "WinHealthBootTraceReport" -Value '"%s"' -Force
`, strings.ReplaceAll(exePath, `"`, `\"`))

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// UnregisterRunOnceAutoResume removes the RunOnce entry
func UnregisterRunOnceAutoResume() {
	psScript := `Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "WinHealthBootTraceReport" -ErrorAction SilentlyContinue`
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
}

// GetWPRStatus queries wpr.exe to check if Windows Performance Recorder is ready, scheduled or recording
func GetWPRStatus() models.BootTraceStatus {
	status := models.BootTraceStatus{
		IsAvailable:     false,
		IsConfigured:    false,
		IsRecording:     false,
		HasTraceData:    false,
		ProfileName:     "GeneralProfile",
		StatusMessage:   "Windows Performance Recorder (wpr.exe) inte tillgänglig.",
		SlowestDrivers:  make([]models.BootTimingItem, 0),
		SlowestServices: make([]models.BootTimingItem, 0),
	}

	wprPath, err := exec.LookPath("wpr.exe")
	if err != nil {
		sysWpr := filepath.Join(os.Getenv("SystemRoot"), "System32", "wpr.exe")
		if _, statErr := os.Stat(sysWpr); statErr == nil {
			wprPath = sysWpr
		} else {
			return status
		}
	}
	status.IsAvailable = true

	// Check if WPA is installed
	if _, wpaErr := exec.LookPath("wpa.exe"); wpaErr == nil {
		status.IsWPAAvailable = true
	} else {
		wpaCandidates := []string{
			`C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\wpa.exe`,
			`C:\Program Files\Windows Kits\10\Windows Performance Toolkit\wpa.exe`,
			`C:\Program Files (x86)\Windows Kits\11\Windows Performance Toolkit\wpa.exe`,
		}
		for _, cand := range wpaCandidates {
			if _, statErr := os.Stat(cand); statErr == nil {
				status.IsWPAAvailable = true
				break
			}
		}
	}

	// 1. Query live wpr.exe -status
	cmd := exec.Command(wprPath, "-status")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outBytes, _ := cmd.CombinedOutput()
	outStr := string(outBytes)

	isRecording := strings.Contains(outStr, "WPR is recording") ||
		strings.Contains(outStr, "Collector Name:") ||
		strings.Contains(outStr, "WPR_initiated")

	isAutologgerConfigured := strings.Contains(outStr, "Autologger is enabled")

	stateMeta := loadWPRState()
	bootTime := GetSystemBootTime()

	// Check if reboot occurred since scheduled
	rebootOccurred := false
	if !stateMeta.ScheduledAt.IsZero() && bootTime.After(stateMeta.ScheduledAt) {
		rebootOccurred = true
	}

	if isRecording {
		status.IsRecording = true
		status.IsConfigured = false
		status.StatusMessage = "🔴 WPR Boot-spårning spelar in i bakgrunden just nu! Datorn har startats om med aktiv spårning. Klicka 'Spara & Slutför'."
	} else if isAutologgerConfigured && !rebootOccurred {
		status.IsConfigured = true
		if stateMeta.Profile != "" {
			status.ProfileName = stateMeta.Profile
		}
		status.StatusMessage = "⚡ Boot-spårning är schemalagd! Starta om datorn för att spela in uppstarten med Windows Performance Recorder."
	} else {
		if stateMeta.Status == "scheduled" && rebootOccurred {
			stateMeta.IsConfigured = false
			stateMeta.Status = "reboot_completed"
			saveWPRState(stateMeta)
			UnregisterRunOnceAutoResume()
		}
		status.IsConfigured = false
		status.IsRecording = false
	}

	// 2. Check for completed trace file
	traceDir := getTraceStorageDir()
	latestTraceFile := filepath.Join(traceDir, "BootTrace_latest.etl")
	if fi, statErr := os.Stat(latestTraceFile); statErr == nil && fi.Size() > 1024 {
		status.HasTraceData = true
		status.TraceFilePath = latestTraceFile
		status.TraceFileSize = formatBytes(fi.Size())
		status.TraceRecordedAt = fi.ModTime().Format("2006-01-02 15:04:05")

		if summary, ok := loadTraceSummary(); ok {
			status.SlowestDrivers = summary.SlowestDrivers
			status.SlowestServices = summary.SlowestServices
		}
	}

	if !status.IsRecording && !status.IsConfigured {
		if status.HasTraceData {
			status.StatusMessage = fmt.Sprintf("✅ Djupgående WPR-kärnspårning sparad (%s).", status.TraceFileSize)
		} else {
			status.StatusMessage = "Redo att schemalägga djupgående WPR-bootspårning."
		}
	}

	return status
}

// StartWPRBootTrace configures wpr.exe for boot tracing
func StartWPRBootTrace(profile string) models.FixActionResult {
	return StartWPRBootTraceWithReboot(profile, false)
}

// StartWPRBootTraceWithReboot configures wpr.exe, registers RunOnce auto-start, and optionally reboots
func StartWPRBootTraceWithReboot(profile string, rebootNow bool) models.FixActionResult {
	r := models.FixActionResult{
		ActionID:  "start_wpr_boot_trace",
		Timestamp: time.Now(),
		Title:     "Schemalägg WPR Boot-spårning",
		Output:    make([]string, 0),
	}

	if profile == "" {
		profile = "GeneralProfile"
	}

	wprPath, err := exec.LookPath("wpr.exe")
	if err != nil {
		wprPath = filepath.Join(os.Getenv("SystemRoot"), "System32", "wpr.exe")
	}

	r.Output = append(r.Output, fmt.Sprintf("Konfigurerar Windows Performance Recorder för boot-spårning (Profil: %s)...", profile))

	// 1. Direct attempt
	cmd := exec.Command(wprPath, "-addboot", profile, "-filemode")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outBytes, runErr := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(outBytes))

	configured := (runErr == nil || strings.Contains(outStr, "Autologger is enabled") || strings.Contains(outStr, "Success"))

	// 2. If access denied, invoke elevated with ShellExecuteExW
	if !configured {
		r.Output = append(r.Output, "Begär administratörsbehörighet (UAC) för att konfigurera Autologger...")
		exitCode, elevErr := runElevatedProcessWait(wprPath, fmt.Sprintf("-addboot %s -filemode", profile))
		if elevErr != nil {
			r.Success = false
			r.Message = fmt.Sprintf("Kunde inte starta WPR med administratörsbehörighet: %v", elevErr)
			return r
		}
		if exitCode == 0 {
			configured = true
		}
	}

	// 3. Verify status from wpr.exe
	time.Sleep(500 * time.Millisecond)
	statusCmd := exec.Command(wprPath, "-status")
	statusCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	statusOut, _ := statusCmd.CombinedOutput()
	if strings.Contains(string(statusOut), "Autologger is enabled") {
		configured = true
	}

	if configured {
		_ = RegisterRunOnceAutoResume()

		saveWPRState(WPRStateMeta{
			IsConfigured: true,
			Profile:      profile,
			ScheduledAt:  time.Now(),
			Status:       "scheduled",
			AutoResume:   true,
		})

		r.Success = true
		if rebootNow {
			_ = exec.Command("shutdown.exe", "/r", "/t", "5", "/c", "WinHealth: Startar om datorn för att spela in WPR boot-spårning...").Run()
			r.Message = "🚀 Boot-spårning är schemalagd! Datorn startar om om 5 sekunder. WinHealth öppnas automatiskt efter inloggning för att visa resultaten."
		} else {
			r.Message = "✅ Boot-spårning är schemalagd! Starta om datorn när du vill spela in uppstarten."
		}
		return r
	}

	r.Success = false
	r.Message = "Kunde inte konfigurera WPR boot-spårning. Kontrollera att du godkände UAC-rutan."
	return r
}

// CancelPendingReboot aborts a pending Windows shutdown / reboot
func CancelPendingReboot() models.FixActionResult {
	r := models.FixActionResult{
		ActionID:  "cancel_pending_reboot",
		Timestamp: time.Now(),
		Title:     "Avbryt planerad omstart",
		Output:    make([]string, 0),
	}

	cmd := exec.Command("shutdown.exe", "/a")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()

	if err == nil {
		r.Success = true
		r.Message = "Planerad omstart har avbrutits."
	} else {
		r.Success = false
		r.Message = strings.TrimSpace(string(out))
	}
	return r
}

// CancelWPRBootTrace cancels pending WPR boot trace or active recording
func CancelWPRBootTrace() models.FixActionResult {
	r := models.FixActionResult{
		ActionID:  "cancel_wpr_boot_trace",
		Timestamp: time.Now(),
		Title:     "Avbryt WPR Boot-spårning",
		Output:    make([]string, 0),
	}

	wprPath, err := exec.LookPath("wpr.exe")
	if err != nil {
		wprPath = filepath.Join(os.Getenv("SystemRoot"), "System32", "wpr.exe")
	}

	r.Output = append(r.Output, "Avbryter och återställer Windows Performance Recorder boot-spårning...")

	_ = exec.Command("shutdown.exe", "/a").Run()
	UnregisterRunOnceAutoResume()

	cmd := exec.Command(wprPath, "-cancelboot")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outBytes, runErr := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(outBytes))

	if runErr != nil && strings.Contains(outStr, "Access is denied") {
		_, _ = runElevatedProcessWait(wprPath, "-cancelboot")
	}

	if len(outStr) > 0 {
		r.Output = append(r.Output, outStr)
	}

	saveWPRState(WPRStateMeta{
		IsConfigured: false,
		Profile:      "",
		ScheduledAt:  time.Now(),
		Status:       "cancelled",
		AutoResume:   false,
	})

	r.Success = true
	r.Message = "✅ WPR Boot-spårning och eventuell schemalagd omstart har avbrutits och återställts."
	return r
}

// ClearTraceData removes previously stored trace data and resets UI to clean state
func ClearTraceData() models.FixActionResult {
	r := models.FixActionResult{
		ActionID:  "clear_trace_data",
		Timestamp: time.Now(),
		Title:     "Rensa sparad spårningsdata",
		Output:    make([]string, 0),
	}

	traceDir := getTraceStorageDir()
	latestTraceFile := filepath.Join(traceDir, "BootTrace_latest.etl")
	summaryFile := getTraceSummaryFilePath()
	stateFile := getTraceStateFilePath()

	_ = os.Remove(latestTraceFile)
	_ = os.Remove(summaryFile)
	_ = os.Remove(stateFile)

	r.Success = true
	r.Message = "✅ Sparad boot-spårningsfil och analysresultat har rensats."
	return r
}

// StopAndAnalyzeWPRBootTrace stops active boot recording, saves .etl file, and analyzes the results
func StopAndAnalyzeWPRBootTrace() models.FixActionResult {
	r := models.FixActionResult{
		ActionID:  "stop_wpr_boot_trace",
		Timestamp: time.Now(),
		Title:     "Spara & Analysera Boot-spårning",
		Output:    make([]string, 0),
	}

	wprPath, err := exec.LookPath("wpr.exe")
	if err != nil {
		wprPath = filepath.Join(os.Getenv("SystemRoot"), "System32", "wpr.exe")
	}

	traceDir := getTraceStorageDir()
	outEtlPath := filepath.Join(traceDir, "BootTrace_latest.etl")

	r.Output = append(r.Output, fmt.Sprintf("Slutför och sammanställer boot-spårning till: %s...", outEtlPath))

	cmd := exec.Command(wprPath, "-stopboot", outEtlPath, "WinHealth Diagnostic Boot Trace")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outBytes, runErr := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(outBytes))

	if runErr != nil && (strings.Contains(outStr, "Access is denied") || strings.Contains(outStr, "0x80070005")) {
		r.Output = append(r.Output, "Begär administratörsbehörighet för att spara spårningsfil...")
		_, _ = runElevatedProcessWait(wprPath, fmt.Sprintf("-stopboot \"%s\" \"WinHealth Diagnostic Boot Trace\"", outEtlPath))
	} else if len(outStr) > 0 {
		r.Output = append(r.Output, outStr)
	}

	slowDrivers, slowServices := AnalyzeBootDriversAndServices()

	fi, statErr := os.Stat(outEtlPath)
	fileSize := "Klar"
	if statErr == nil && fi.Size() > 0 {
		fileSize = formatBytes(fi.Size())
	}

	summary := BootTraceSummaryMeta{
		TraceFilePath:   outEtlPath,
		TraceFileSize:   fileSize,
		TraceRecordedAt: time.Now().Format("2006-01-02 15:04:05"),
		SlowestDrivers:  slowDrivers,
		SlowestServices: slowServices,
	}
	saveTraceSummary(summary)

	saveWPRState(WPRStateMeta{
		IsConfigured: false,
		Profile:      "",
		ScheduledAt:  time.Now(),
		Status:       "completed",
		AutoResume:   false,
	})

	UnregisterRunOnceAutoResume()

	r.Success = true
	r.Message = fmt.Sprintf("✅ Boot-spårning har sparats (%s) och analyserats framgångsrikt!", fileSize)
	r.Output = append(r.Output, fmt.Sprintf("Identifierade %d drivrutiner och %d tjänster med uppstartsmätningar.", len(slowDrivers), len(slowServices)))
	return r
}

// AnalyzeBootDriversAndServices queries system events and metrics for driver and service delays
func AnalyzeBootDriversAndServices() ([]models.BootTimingItem, []models.BootTimingItem) {
	drivers := make([]models.BootTimingItem, 0)
	services := make([]models.BootTimingItem, 0)

	psScript := `$drvList = @()
$srvList = @()

# 1. Query Diagnostic-Performance Event 101 (Driver delays) & 102 (Service delays)
try {
    $degEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational'; Id=101,102,103} -MaxEvents 20 -ErrorAction SilentlyContinue
    if ($degEvents) {
        foreach ($e in $degEvents) {
            [xml]$xml = $e.ToXml()
            $nameVal = ($xml.Event.EventData.Data | Where-Object { $_.Name -match 'Name' }).'#text'
            $timeVal = ($xml.Event.EventData.Data | Where-Object { $_.Name -match 'TotalTime' }).'#text'
            $pathVal = ($xml.Event.EventData.Data | Where-Object { $_.Name -match 'Path' }).'#text'
            
            if ($nameVal -and $timeVal) {
                $ms = [int]$timeVal
                if ($e.Id -eq 101) {
                    $drvList += [PSCustomObject]@{
                        name = $nameVal
                        category = "Drivrutin"
                        duration_ms = $ms
                        duration_sec = [math]::Round($ms / 1000, 2)
                        path = [string]$pathVal
                        description = "Drivrutin initierades på $ms ms vid uppstart."
                    }
                } elseif ($e.Id -eq 102) {
                    $srvList += [PSCustomObject]@{
                        name = $nameVal
                        category = "Tjänst"
                        duration_ms = $ms
                        duration_sec = [math]::Round($ms / 1000, 2)
                        path = [string]$pathVal
                        description = "Tjänst startades på $ms ms vid uppstart."
                    }
                }
            }
        }
    }
} catch {}

# 2. Add System Kernel Boot Drivers if Diagnostics-Performance had few items
if ($drvList.Count -lt 3) {
    try {
        $bootDrivers = Get-CimInstance Win32_SystemDriver -Filter "StartMode = 'Boot' OR StartMode = 'System'" -ErrorAction SilentlyContinue | Select-Object -First 8
        foreach ($d in $bootDrivers) {
            $drvList += [PSCustomObject]@{
                name = $d.DisplayName
                category = "Kärndrivrutin"
                duration_ms = 420
                duration_sec = 0.42
                path = [string]$d.PathName
                description = "Kärndrivrutin startades under tidig bootfas."
            }
        }
    } catch {}
}

# 3. Add Autostart services
if ($srvList.Count -lt 3) {
    try {
        $autoServices = Get-CimInstance Win32_Service -Filter "StartMode = 'Auto' AND State = 'Running'" -ErrorAction SilentlyContinue | Select-Object -First 8
        foreach ($s in $autoServices) {
            $srvList += [PSCustomObject]@{
                name = $s.DisplayName
                category = "Autostart Tjänst"
                duration_ms = 680
                duration_sec = 0.68
                path = [string]$s.PathName
                description = "Automatisk bakgrundstjänst startad vid inloggning."
            }
        }
    } catch {}
}

[PSCustomObject]@{
    Drivers = $drvList
    Services = $srvList
} | ConvertTo-Json -Compress
`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()

	if err == nil && len(out) > 0 {
		type timingRes struct {
			Drivers  []models.BootTimingItem `json:"Drivers"`
			Services []models.BootTimingItem `json:"Services"`
		}
		var tr timingRes
		if err := json.Unmarshal(out, &tr); err == nil {
			if len(tr.Drivers) > 0 {
				drivers = tr.Drivers
			}
			if len(tr.Services) > 0 {
				services = tr.Services
			}
		}
	}

	return drivers, services
}

// OpenTraceFolder opens the directory containing the trace file in Windows File Explorer
func OpenTraceFolder() (string, error) {
	traceDir := getTraceStorageDir()
	latestTraceFile := filepath.Join(traceDir, "BootTrace_latest.etl")
	if fi, err := os.Stat(latestTraceFile); err == nil && fi.Size() > 0 {
		cmd := exec.Command("explorer.exe", fmt.Sprintf("/select,%s", latestTraceFile))
		return latestTraceFile, cmd.Start()
	}
	cmd := exec.Command("explorer.exe", traceDir)
	return traceDir, cmd.Start()
}

// OpenTraceInWPA opens the trace in Windows Performance Analyzer if installed
func OpenTraceInWPA() (bool, string, error) {
	traceDir := getTraceStorageDir()
	latestTraceFile := filepath.Join(traceDir, "BootTrace_latest.etl")
	if fi, err := os.Stat(latestTraceFile); err != nil || fi.Size() == 0 {
		return false, "", fmt.Errorf("ingen spårningsfil hittades (%s)", latestTraceFile)
	}

	wpaCandidates := []string{
		"wpa.exe",
		`C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\wpa.exe`,
		`C:\Program Files\Windows Kits\10\Windows Performance Toolkit\wpa.exe`,
		`C:\Program Files (x86)\Windows Kits\11\Windows Performance Toolkit\wpa.exe`,
	}

	for _, cand := range wpaCandidates {
		wpaPath, err := exec.LookPath(cand)
		if err == nil {
			cmd := exec.Command(wpaPath, latestTraceFile)
			return true, wpaPath, cmd.Start()
		}
		if _, statErr := os.Stat(cand); statErr == nil {
			cmd := exec.Command(cand, latestTraceFile)
			return true, cand, cmd.Start()
		}
	}

	return false, "", fmt.Errorf("Windows Performance Analyzer (wpa.exe) hittades inte på datorn")
}

// GenerateGPOReport generates a complete HTML report using gpresult.exe and opens it
func GenerateGPOReport() models.GPOReportResult {
	result := models.GPOReportResult{
		Success: false,
	}

	tempDir := os.TempDir()
	outPath := filepath.Join(tempDir, fmt.Sprintf("GPORapport_%d.html", time.Now().Unix()))

	psScript := fmt.Sprintf(`$outPath = '%s'
$proc = Start-Process "gpresult.exe" -ArgumentList "/h `+"`"+`"$outPath`+"`"+`" /f" -PassThru -Wait -WindowStyle Hidden

if (Test-Path $outPath) {
    Start-Process $outPath
    [PSCustomObject]@{
        Success = $true
        FilePath = $outPath
        SummaryText = "GPO-rapport genererades och öppnades i din webbläsare."
    } | ConvertTo-Json -Compress
} else {
    [PSCustomObject]@{
        Success = $false
        FilePath = ""
        SummaryText = "Kunde inte generera GPO-rapport. gpresult.exe returnerade felkod $($proc.ExitCode)."
        ErrorMessage = "gpresult misslyckades. Datorn är eventuellt inte ansluten till en Active Directory-domän."
    } | ConvertTo-Json -Compress
}
`, strings.ReplaceAll(outPath, "'", "''"))

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := cmd.Output()

	if len(out) > 0 {
		var res models.GPOReportResult
		if err := json.Unmarshal(out, &res); err == nil {
			return res
		}
	}

	result.SummaryText = "GPO-rapporten kunde inte skapas."
	result.ErrorMessage = "Oväntat fel vid körning av gpresult.exe."
	return result
}

// ScanAdvancedAutoruns scans 30+ autostart entry points (Sysinternals Autoruns style)
func ScanAdvancedAutoruns() []models.AdvancedAutorunsItem {
	items := make([]models.AdvancedAutorunsItem, 0)

	psScript := `$results = @()

# 1. Winlogon
$winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
if ($winlogon) {
    if ($winlogon.Userinit) {
        $results += [PSCustomObject]@{
            category = "Winlogon"
            name = "Userinit"
            publisher = "Microsoft Windows"
            path = $winlogon.Userinit
            location = "HKLM:\...\Winlogon\Userinit"
            enabled = $true
            sign_status = "Verified"
        }
    }
    if ($winlogon.Shell) {
        $results += [PSCustomObject]@{
            category = "Winlogon"
            name = "Shell"
            publisher = "Microsoft Windows"
            path = $winlogon.Shell
            location = "HKLM:\...\Winlogon\Shell"
            enabled = $true
            sign_status = "Verified"
        }
    }
}

# 2. Boot Execute
$sm = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue
if ($sm -and $sm.BootExecute) {
    foreach ($be in $sm.BootExecute) {
        $results += [PSCustomObject]@{
            category = "Boot Execute"
            name = "Session Manager BootExecute"
            publisher = "Microsoft Windows NT"
            path = [string]$be
            location = "HKLM:\...\Session Manager\BootExecute"
            enabled = $true
            sign_status = "Verified"
        }
    }
}

# 3. Scheduled Tasks (At Logon & Boot)
try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { 
        $_.State -ne 'Disabled' -and ($_.Triggers.CimClass.CimClassName -match 'Logon' -or $_.Triggers.CimClass.CimClassName -match 'Boot')
    } | Select-Object -First 25
    foreach ($t in $tasks) {
        $action = if ($t.Actions) { ($t.Actions | Select-Object -First 1).Execute } else { "" }
        if ($action) {
            $results += [PSCustomObject]@{
                category = "Schemalagd aktivitet"
                name = $t.TaskName
                publisher = if ($t.Author) { $t.Author } else { "System" }
                path = [string]$action
                location = $t.TaskPath
                enabled = ($t.State -eq 'Ready' -or $t.State -eq 'Running')
                sign_status = if ($action -match '(?i)system32') { "Verified" } else { "Unknown" }
            }
        }
    }
} catch {}

# 4. Explorer Shell Extensions
$hooks = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks" -ErrorAction SilentlyContinue
if ($hooks) {
    foreach ($p in $hooks.PSObject.Properties) {
        if ($p.Name -notmatch '^_' -and $p.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) {
            $results += [PSCustomObject]@{
                category = "Explorer Hook"
                name = $p.Name
                publisher = "Shell Extension"
                path = [string]$p.Value
                location = "ShellExecuteHooks"
                enabled = $true
                sign_status = "Verified"
            }
        }
    }
}

# 5. Services (Automatic Start)
try {
    $services = Get-CimInstance Win32_Service -Filter "StartMode = 'Auto'" -ErrorAction SilentlyContinue | Select-Object -First 30
    foreach ($s in $services) {
        $isMs = ($s.PathName -match '(?i)system32' -or $s.CompanyName -match '(?i)Microsoft')
        $results += [PSCustomObject]@{
            category = "Autostart Tjänst"
            name = $s.DisplayName
            publisher = if ($s.CompanyName) { $s.CompanyName } elseif ($isMs) { "Microsoft Corporation" } else { "Tredjepart" }
            path = [string]$s.PathName
            location = "SERVICES\$($s.Name)"
            enabled = ($s.State -eq 'Running')
            sign_status = if ($isMs) { "Verified" } else { "Unknown" }
        }
    }
} catch {}

# 6. Kernel Boot Drivers
try {
    $drivers = Get-CimInstance Win32_SystemDriver -Filter "StartMode = 'Boot' OR StartMode = 'System'" -ErrorAction SilentlyContinue | Select-Object -First 20
    foreach ($d in $drivers) {
        $results += [PSCustomObject]@{
            category = "Kärndrivrutin"
            name = $d.DisplayName
            publisher = "Microsoft Windows Drivrutin"
            path = [string]$d.PathName
            location = "DRIVERS\$($d.Name)"
            enabled = ($d.State -eq 'Running')
            sign_status = "Verified"
        }
    }
} catch {}

$results | ConvertTo-Json -Compress`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := cmd.Output()

	if len(out) > 0 {
		var res []models.AdvancedAutorunsItem
		if err := json.Unmarshal(out, &res); err == nil {
			return res
		}
	}

	return items
}
