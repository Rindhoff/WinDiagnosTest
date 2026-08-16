package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
	"winhealth/pkg/models"

	"golang.org/x/sys/windows/registry"
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
	SW_HIDE                 = 0
	waitTimeout             = 258
	stillActive             = 259
)

func runElevatedProcessWait(exePath string, args string) (uint32, error) {
	return runElevatedProcessWaitTimeout(exePath, args, 5*time.Minute)
}

func runElevatedProcessWaitTimeout(exePath string, args string, timeout time.Duration) (uint32, error) {
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
	info.nShow = SW_HIDE

	ret, _, err := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		return 1, fmt.Errorf("UAC behörighet nekades eller misslyckades: %v", err)
	}

	if info.hProcess != 0 {
		defer syscall.CloseHandle(info.hProcess)
		waitResult, waitErr := syscall.WaitForSingleObject(info.hProcess, uint32(timeout/time.Millisecond))
		if waitErr != nil {
			return 1, fmt.Errorf("kunde inte vänta på den upphöjda processen: %w", waitErr)
		}
		if waitResult == waitTimeout {
			return 1, fmt.Errorf("den upphöjda processen överskred tidsgränsen %s", timeout.Round(time.Second))
		}
		var exitCode uint32
		if err := syscall.GetExitCodeProcess(info.hProcess, &exitCode); err != nil {
			return 1, fmt.Errorf("kunde inte läsa processens slutkod: %w", err)
		}
		if exitCode == stillActive {
			return 1, fmt.Errorf("den upphöjda processen avslutades inte")
		}
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
	Version        int       `json:"version"`
	AttemptID      string    `json:"attempt_id"`
	IsConfigured   bool      `json:"is_configured"`
	Profile        string    `json:"profile"`
	Profiles       []string  `json:"profiles,omitempty"`
	ScheduledAt    time.Time `json:"scheduled_at"`
	BootTimeBefore time.Time `json:"boot_time_before"`
	TraceFilePath  string    `json:"trace_file_path"`
	Status         string    `json:"status"` // scheduled, recording, merging, captured_unanalyzed, completed, failed, cancelled
	AutoResume     bool      `json:"auto_resume"`
	LastError      string    `json:"last_error,omitempty"`
	CommandOutput  string    `json:"command_output,omitempty"`
}

// BootTraceSummaryMeta persists analyzed trace results
type BootTraceSummaryMeta struct {
	TraceFilePath   string                      `json:"trace_file_path"`
	TraceFileSize   string                      `json:"trace_file_size"`
	TraceRecordedAt string                      `json:"trace_recorded_at"`
	SlowestDrivers  []models.BootTimingItem     `json:"slowest_drivers"`
	SlowestServices []models.BootTimingItem     `json:"slowest_services"`
	TopProcesses    []models.BootTimingItem     `json:"top_processes,omitempty"`
	NetworkFindings []models.BootNetworkFinding `json:"network_findings,omitempty"`
	AnalysisSource  string                      `json:"analysis_source,omitempty"`
	AnalysisError   string                      `json:"analysis_error,omitempty"`
	AttemptID       string                      `json:"attempt_id,omitempty"`
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

func saveWPRState(state WPRStateMeta) error {
	path := getTraceStateFilePath()
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func cleanTimingItemName(name string) string {
	name = strings.TrimSpace(name)
	fields := strings.Fields(name)
	for _, f := range fields {
		lower := strings.ToLower(f)
		if strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".sys") || strings.HasSuffix(lower, ".dll") {
			return f
		}
	}
	if len(fields) > 1 && len(fields[0]) <= 2 {
		return strings.Join(fields[1:], " ")
	}
	return name
}

func cleanTimingDescription(desc string, durationMs int, category string) string {
	if durationMs > 0 {
		cat := category
		if cat == "" {
			cat = "Komponent"
		}
		return fmt.Sprintf("%s initierades på %d ms vid uppstart.", cat, durationMs)
	}
	return desc
}

func loadTraceSummary() (BootTraceSummaryMeta, bool) {
	var sum BootTraceSummaryMeta
	path := getTraceSummaryFilePath()
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		if err := json.Unmarshal(data, &sum); err == nil {
			for i := range sum.SlowestDrivers {
				sum.SlowestDrivers[i].Name = cleanTimingItemName(sum.SlowestDrivers[i].Name)
				sum.SlowestDrivers[i].Description = cleanTimingDescription(sum.SlowestDrivers[i].Description, sum.SlowestDrivers[i].DurationMs, "Drivrutin")
			}
			for i := range sum.SlowestServices {
				sum.SlowestServices[i].Name = cleanTimingItemName(sum.SlowestServices[i].Name)
				sum.SlowestServices[i].Description = cleanTimingDescription(sum.SlowestServices[i].Description, sum.SlowestServices[i].DurationMs, "Tjänst")
			}
			return sum, true
		}
	}
	return sum, false
}

func saveTraceSummary(sum BootTraceSummaryMeta) error {
	path := getTraceSummaryFilePath()
	data, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// RegisterRunOnceAutoResume registers WinHealth to start automatically after reboot
func RegisterRunOnceAutoResume() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue("WinHealthBootTraceReport", fmt.Sprintf(`"%s"`, exePath))
}

// UnregisterRunOnceAutoResume removes the RunOnce entry
func UnregisterRunOnceAutoResume() {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer key.Close()
	_ = key.DeleteValue("WinHealthBootTraceReport")
}

// GetWPRStatus queries wpr.exe to check if Windows Performance Recorder is ready, scheduled or recording
func GetWPRStatus() models.BootTraceStatus {
	status := models.BootTraceStatus{
		IsAvailable:     false,
		IsConfigured:    false,
		IsRecording:     false,
		CanStop:         false,
		HasTraceData:    false,
		State:           "idle",
		ProfileName:     "GeneralProfile",
		StatusMessage:   "Windows Performance Recorder (wpr.exe) inte tillgänglig.",
		SlowestDrivers:  make([]models.BootTimingItem, 0),
		SlowestServices: make([]models.BootTimingItem, 0),
		TopProcesses:    make([]models.BootTimingItem, 0),
		NetworkFindings: make([]models.BootNetworkFinding, 0),
	}

	wprPath := findWPRExecutable()
	if wprPath == "" {
		return status
	}
	status.IsAvailable = true
	status.IsWPAAvailable = findWPA() != ""
	status.WPAExporterPath = findWPAExporter()
	status.IsWPAExporterAvailable = status.WPAExporterPath != ""

	// 1. Query live wpr.exe -status
	cmd := exec.Command(wprPath, "-status")
	cmd.SysProcAttr = hiddenWindowProcAttr()
	outBytes, statusErr := cmd.CombinedOutput()
	outStr := string(outBytes)
	isRecording, explicitlyNotRecording := parseWPRRecordingStatus(outStr)

	stateMeta := loadWPRState()
	rawTraceFiles := findWPRRawTraceFiles(stateMeta.ScheduledAt)
	hasRecoverableRawTrace := len(rawTraceFiles) > 0
	bootTime := GetSystemBootTime()
	status.State = stateMeta.Status
	if status.State == "" {
		status.State = "idle"
	}
	if stateMeta.Profile != "" {
		status.ProfileName = stateMeta.Profile
	}
	status.LastError = stateMeta.LastError

	referenceBoot := stateMeta.BootTimeBefore
	if referenceBoot.IsZero() {
		referenceBoot = stateMeta.ScheduledAt
	}
	rebootOccurred := !referenceBoot.IsZero() && bootTime.After(referenceBoot.Add(5*time.Second))

	switch stateMeta.Status {
	case "scheduled":
		if !rebootOccurred {
			status.IsConfigured = true
			status.StatusMessage = "⚡ Boot-spårning är verifierat schemalagd. Starta om datorn för att påbörja ETW-inspelningen."
		} else if isRecording {
			stateMeta.Status = "recording"
			stateMeta.IsConfigured = false
			_ = saveWPRState(stateMeta)
			status.State = "recording"
			status.IsRecording = true
			status.CanStop = true
			status.StatusMessage = "🔴 WPR spelar in boot-spårningen. Spara och analysera när inloggningen är färdig."
		} else if hasRecoverableRawTrace {
			stateMeta.Status = "recoverable"
			stateMeta.IsConfigured = false
			stateMeta.LastError = ""
			_ = saveWPRState(stateMeta)
			status.State = "recoverable"
			status.CanStop = true
			status.StatusMessage = fmt.Sprintf("🟡 WPR skapade %s rå boot-data. Spara och analysera för att sammanfoga ETL-filerna.", formatBytes(totalFileSize(rawTraceFiles)))
		} else if explicitlyNotRecording {
			stateMeta.Status = "failed"
			stateMeta.IsConfigured = false
			stateMeta.AutoResume = false
			stateMeta.LastError = recentWPRTraceError(bootTime)
			if stateMeta.LastError == "" {
				stateMeta.LastError = "Windows startades om men WPR:s boot-autologger startade inte."
			}
			_ = saveWPRState(stateMeta)
			UnregisterRunOnceAutoResume()
			status.State = "failed"
			status.LastError = stateMeta.LastError
			status.StatusMessage = "❌ Boot-spårningen startade inte efter omstart: " + stateMeta.LastError
		} else {
			status.CanStop = true
			status.StatusMessage = "⚠️ Omstart upptäckt men WPR-status kunde inte verifieras. Försök spara spårningen för diagnostiskt felmeddelande."
		}
	case "recording", "merging":
		if explicitlyNotRecording && hasRecoverableRawTrace {
			stateMeta.Status = "recoverable"
			stateMeta.IsConfigured = false
			stateMeta.LastError = ""
			_ = saveWPRState(stateMeta)
			status.State = "recoverable"
			status.CanStop = true
			status.StatusMessage = fmt.Sprintf("🟡 WPR-sessionen är avslutad men %s rå boot-data kan återställas och analyseras.", formatBytes(totalFileSize(rawTraceFiles)))
		} else if explicitlyNotRecording {
			stateMeta.Status = "failed"
			stateMeta.IsConfigured = false
			stateMeta.AutoResume = false
			stateMeta.LastError = "WPR-inspelningen avslutades utan att en giltig ETL-fil sparades."
			_ = saveWPRState(stateMeta)
			status.State = "failed"
			status.LastError = stateMeta.LastError
			status.StatusMessage = "❌ " + stateMeta.LastError
		} else {
			status.IsRecording = isRecording
			status.CanStop = true
			status.StatusMessage = "🔴 WPR boot-spårning är redo att sparas och analyseras."
		}
	case "recoverable":
		if hasRecoverableRawTrace {
			status.CanStop = true
			status.StatusMessage = fmt.Sprintf("🟡 %s rå WPR-data väntar på sammanfogning och analys.", formatBytes(totalFileSize(rawTraceFiles)))
		} else {
			status.State = "failed"
			status.LastError = "WPR:s återställningsbara råfiler hittades inte längre."
			status.StatusMessage = "❌ " + status.LastError
		}
	case "captured_unanalyzed":
		status.StatusMessage = "⚠️ ETL-spårningen är sparad men väntar på WPA Exporter-analys."
	case "completed":
		status.StatusMessage = "✅ WPR-spårningen är sparad och analyserad med WPA Exporter."
	case "failed":
		if hasRecoverableRawTrace {
			stateMeta.Status = "recoverable"
			stateMeta.LastError = ""
			_ = saveWPRState(stateMeta)
			status.State = "recoverable"
			status.LastError = ""
			status.CanStop = true
			status.StatusMessage = fmt.Sprintf("🟡 Tidigare inspelning hittades: %s rå WPR-data kan sammanfogas och analyseras.", formatBytes(totalFileSize(rawTraceFiles)))
		} else {
			status.StatusMessage = "❌ WPR-spårningen misslyckades: " + stateMeta.LastError
		}
	case "reboot_completed": // migrate legacy state from earlier builds
		status.State = "failed"
		status.LastError = "Äldre WinHealth-version registrerade omstart men skapade ingen verifierad ETL-fil."
		status.StatusMessage = "❌ " + status.LastError
	}
	if statusErr != nil && status.State == "idle" {
		status.LastError = strings.TrimSpace(outStr)
	}

	// 2. Check for completed trace file
	latestTraceFile := stateMeta.TraceFilePath
	summary, summaryLoaded := loadTraceSummary()
	if summaryLoaded {
		if latestTraceFile == "" {
			latestTraceFile = summary.TraceFilePath
		}
		status.SlowestDrivers = summary.SlowestDrivers
		status.SlowestServices = summary.SlowestServices
		status.TopProcesses = summary.TopProcesses
		status.NetworkFindings = summary.NetworkFindings
		status.AnalysisSource = summary.AnalysisSource
		status.AnalysisError = summary.AnalysisError
	}
	if fi, statErr := os.Stat(latestTraceFile); statErr == nil && fi.Size() > 1024 {
		status.HasTraceData = true
		status.TraceFilePath = latestTraceFile
		status.TraceFileSize = formatBytes(fi.Size())
		status.TraceRecordedAt = fi.ModTime().Format("2006-01-02 15:04:05")
	}
	if summaryLoaded && status.HasTraceData && summary.TraceFilePath == latestTraceFile &&
		(summary.AttemptID == "" || stateMeta.AttemptID == "" || summary.AttemptID == stateMeta.AttemptID) &&
		status.State != "scheduled" && status.State != "recording" && status.State != "merging" {
		status.LastError = ""
		stateMeta.LastError = ""
		stateMeta.IsConfigured = false
		stateMeta.AutoResume = false
		if summary.AnalysisError == "" {
			status.State = "completed"
			stateMeta.Status = "completed"
			status.StatusMessage = "✅ WPR-spårningen är sparad och analyserad med WPA Exporter."
		} else {
			status.State = "captured_unanalyzed"
			stateMeta.Status = "captured_unanalyzed"
			status.StatusMessage = "⚠️ ETL-spårningen är sparad men WPA-analysen behöver köras igen."
		}
		_ = saveWPRState(stateMeta)
	}
	if status.State == "idle" && status.HasTraceData {
		status.StatusMessage = fmt.Sprintf("✅ WPR-spårning sparad (%s).", status.TraceFileSize)
	} else if status.State == "idle" {
		status.StatusMessage = "Redo att schemalägga en verifierad WPR-bootspårning."
	}

	return status
}

func findWPRExecutable() string {
	if p, err := exec.LookPath("wpr.exe"); err == nil {
		return p
	}
	p := filepath.Join(os.Getenv("SystemRoot"), "System32", "wpr.exe")
	if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
		return p
	}
	return ""
}

func parseWPRRecordingStatus(output string) (recording, explicitlyNotRecording bool) {
	lower := strings.ToLower(output)
	explicitlyNotRecording = strings.Contains(lower, "not recording") || strings.Contains(lower, "ingen inspelning")
	recording = !explicitlyNotRecording && (strings.Contains(lower, "wpr is recording") ||
		strings.Contains(lower, "collector name:") || strings.Contains(lower, "wpr_initiated"))
	return recording, explicitlyNotRecording
}

func recentWPRTraceError(since time.Time) string {
	start := since.UTC().Format(time.RFC3339)
	ps := fmt.Sprintf(`$e = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Kernel-EventTracing/Admin'; StartTime=[datetime]::Parse('%s')} -ErrorAction SilentlyContinue | Where-Object { $_.Level -le 3 -and $_.Message -match '(?i)(WPR_initiated|NT Kernel Logger)' } | Select-Object -First 1
if ($e) { (($e.Message -replace '\r?\n',' ') -replace '\s+',' ').Trim() }`, start)
	out, err := RunPowerShellWithTimeout(ps, 8*time.Second)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func findWPRRawTraceFiles(scheduledAt time.Time) []string {
	matches, _ := filepath.Glob(filepath.Join(getTraceStorageDir(), "WPR_initiated*.etl"))
	result := make([]string, 0, len(matches))
	for _, match := range matches {
		fi, err := os.Stat(match)
		if err != nil || fi.IsDir() || fi.Size() < 1024 {
			continue
		}
		if !scheduledAt.IsZero() && fi.ModTime().Before(scheduledAt.Add(-time.Minute)) {
			continue
		}
		result = append(result, match)
	}
	sort.Strings(result)
	return result
}

func totalFileSize(paths []string) int64 {
	var total int64
	for _, path := range paths {
		if fi, err := os.Stat(path); err == nil {
			total += fi.Size()
		}
	}
	return total
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

	profiles, err := validatedBootProfiles(profile)
	if err != nil {
		r.Message = err.Error()
		return r
	}
	profile = profiles[0]
	wprPath := findWPRExecutable()
	if wprPath == "" {
		r.Message = "wpr.exe hittades inte på datorn."
		return r
	}

	statusCmd := exec.Command(wprPath, "-status")
	statusCmd.SysProcAttr = hiddenWindowProcAttr()
	statusOut, _ := statusCmd.CombinedOutput()
	if recording, _ := parseWPRRecordingStatus(string(statusOut)); recording {
		r.Message = "En WPR-inspelning kör redan. Stoppa eller avbryt den innan en ny boot-spårning schemaläggs."
		r.Output = append(r.Output, strings.TrimSpace(string(statusOut)))
		return r
	}

	previous := loadWPRState()
	if rawFiles := findWPRRawTraceFiles(previous.ScheduledAt); len(rawFiles) > 0 {
		r.Message = fmt.Sprintf("Det finns %s återställningsbar WPR-rådata från föregående försök. Spara och analysera den, eller rensa spårningen, innan en ny mätning startas.", formatBytes(totalFileSize(rawFiles)))
		return r
	}
	if previous.Status != "" && previous.Status != "completed" && previous.Status != "cancelled" {
		cleanup := exec.Command(wprPath, "-cancelboot")
		cleanup.SysProcAttr = hiddenWindowProcAttr()
		_, _ = cleanup.CombinedOutput()
	}

	attemptID := time.Now().Format("20060102_150405")
	traceDir := getTraceStorageDir()
	tracePath := filepath.Join(traceDir, "BootTrace_"+attemptID+".etl")

	r.Output = append(r.Output, fmt.Sprintf("Konfigurerar WPR boot-spårning (%s)...", strings.Join(profiles, ", ")))

	args := make([]string, 0, len(profiles)*2+4)
	for _, p := range profiles {
		args = append(args, "-addboot", p)
	}
	args = append(args, "-filemode", "-recordtempto", traceDir)
	startCtx, startCancel := context.WithTimeout(context.Background(), time.Minute)
	defer startCancel()
	cmd := exec.CommandContext(startCtx, wprPath, args...)
	cmd.SysProcAttr = hiddenWindowProcAttr()
	outBytes, runErr := cmd.CombinedOutput()
	if startCtx.Err() == context.DeadlineExceeded {
		runErr = fmt.Errorf("wpr -addboot överskred tidsgränsen 1 minut")
	}
	outStr := strings.TrimSpace(string(outBytes))
	configured := runErr == nil

	if !configured {
		r.Output = append(r.Output, "Direkt konfiguration misslyckades; begär administratörsbehörighet...")
		elevatedArgs := strings.Join(args, " ")
		exitCode, elevErr := runElevatedProcessWait(wprPath, elevatedArgs)
		if elevErr == nil && exitCode == 0 {
			configured = true
		} else if elevErr != nil {
			r.Output = append(r.Output, fmt.Sprintf("UAC fel: %v", elevErr))
		}
	}

	if configured {
		if !hasWPRBootAutologger() {
			_ = exec.Command(wprPath, "-cancelboot").Run()
			r.Message = "WPR returnerade utan fel, men någon WPR boot-autologger skapades inte i registret. Spårningen avbröts före omstart."
			r.Output = append(r.Output, "Kontrollerade HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger efter WPR_initiated_Autologger.")
			return r
		}
		if err := RegisterRunOnceAutoResume(); err != nil {
			_ = exec.Command(wprPath, "-cancelboot").Run()
			r.Message = fmt.Sprintf("WPR konfigurerades men automatisk återupptagning kunde inte registreras: %v", err)
			return r
		}

		state := WPRStateMeta{
			Version: 2, AttemptID: attemptID, IsConfigured: true,
			Profile: profile, Profiles: profiles, ScheduledAt: time.Now(),
			BootTimeBefore: GetSystemBootTime(), TraceFilePath: tracePath,
			Status: "scheduled", AutoResume: true, CommandOutput: outStr,
		}
		if err := saveWPRState(state); err != nil {
			_ = exec.Command(wprPath, "-cancelboot").Run()
			UnregisterRunOnceAutoResume()
			r.Message = fmt.Sprintf("WPR konfigurerades men spårningens state kunde inte sparas: %v", err)
			return r
		}

		r.Success = true
		if rebootNow {
			if err := exec.Command("shutdown.exe", "/r", "/t", "10", "/c", "WinHealth: Startar om datorn för verifierad WPR boot-spårning...").Run(); err != nil {
				r.Success = false
				r.Message = fmt.Sprintf("Spårningen schemalades men omstarten kunde inte initieras: %v", err)
				return r
			}
			r.Message = "🚀 WPR-profilerna är schemalagda. Datorn startar om om 10 sekunder och WinHealth återupptar kontrollen efter inloggning."
		} else {
			r.Message = "✅ WPR-profilerna är schemalagda och verifierade. Starta om datorn för att påbörja inspelningen."
		}
		return r
	}

	r.Success = false
	r.Output = append(r.Output, outStr)
	r.Message = fmt.Sprintf("Kunde inte konfigurera WPR boot-spårning: %v", runErr)
	return r
}

func hasWPRBootAutologger() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\WMI\Autologger`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return false
	}
	for _, name := range names {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "wpr_initiated") || strings.Contains(lower, "wpr boot") {
			return true
		}
	}
	return false
}

func validatedBootProfiles(requested string) ([]string, error) {
	if requested == "" {
		requested = "GeneralProfile"
	}
	allowed := map[string]bool{"GeneralProfile": true, "CPU": true, "Network": true, "DiskIO": true, "FileIO": true}
	if !allowed[requested] {
		return nil, fmt.Errorf("WPR-profilen %q stöds inte", requested)
	}
	// Light-varianterna behåller CPU/CSwitch, disk, processer och nätverksdata
	// men undviker de mycket stora stack- och FileIO-flöden som kan fylla en
	// bootspårning till 4 GB innan användaren hunnit logga in.
	profiles := []string{"GeneralProfile.Light", "Network.Light"}
	if requested != "GeneralProfile" && requested != "Network" {
		profiles = append(profiles, requested+".Light")
	}
	profiles = uniqueStrings(profiles)
	return profiles, nil
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
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

	if runErr != nil && (strings.Contains(outStr, "Access is denied") || strings.Contains(outStr, "0x80070005")) {
		exitCode, elevatedErr := runElevatedProcessWait(wprPath, "-cancelboot")
		if elevatedErr == nil && exitCode == 0 {
			runErr = nil
		} else {
			runErr = fmt.Errorf("upphöjd cancelboot misslyckades (exit %d): %v", exitCode, elevatedErr)
		}
	}

	if len(outStr) > 0 {
		r.Output = append(r.Output, outStr)
	}

	state := loadWPRState()
	state.Version = 2
	state.IsConfigured = false
	state.AutoResume = false
	state.Status = "cancelled"
	state.LastError = ""
	state.CommandOutput = outStr
	if runErr != nil {
		state.Status = "failed"
		state.LastError = fmt.Sprintf("WPR kunde inte återställas: %v (%s)", runErr, outStr)
	}
	_ = saveWPRState(state)

	if runErr != nil {
		r.Message = state.LastError
		return r
	}

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
	summaryFile := getTraceSummaryFilePath()
	stateFile := getTraceStateFilePath()

	for _, pattern := range []string{"BootTrace_*.etl", "BootTrace_*.etl.NGENPDB", "WPR_initiated*.etl"} {
		matches, _ := filepath.Glob(filepath.Join(traceDir, pattern))
		for _, match := range matches {
			_ = os.Remove(match)
		}
	}
	_ = os.RemoveAll(filepath.Join(traceDir, "Analysis"))
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

	wprPath := findWPRExecutable()
	if wprPath == "" {
		r.Message = "wpr.exe hittades inte."
		return r
	}

	state := loadWPRState()
	outEtlPath := state.TraceFilePath
	if outEtlPath == "" {
		outEtlPath = filepath.Join(getTraceStorageDir(), "BootTrace_"+time.Now().Format("20060102_150405")+".etl")
		state.TraceFilePath = outEtlPath
	}
	state.Status = "merging"
	state.LastError = ""
	_ = saveWPRState(state)

	r.Output = append(r.Output, fmt.Sprintf("Slutför och sammanställer boot-spårning till: %s...", outEtlPath))

	rawTraceFiles := findWPRRawTraceFiles(state.ScheduledAt)
	statusCmd := exec.Command(wprPath, "-status")
	statusCmd.SysProcAttr = hiddenWindowProcAttr()
	statusBytes, _ := statusCmd.CombinedOutput()
	isRecording, _ := parseWPRRecordingStatus(string(statusBytes))

	var outStr string
	var runErr error
	existingTraceIsValid := false
	if existing, err := os.Stat(outEtlPath); err == nil && existing.Size() >= 1024 {
		existingTraceIsValid = state.ScheduledAt.IsZero() || !existing.ModTime().Before(state.ScheduledAt)
	}
	if existingTraceIsValid {
		r.Output = append(r.Output, "En redan sammanfogad, giltig ETL-fil hittades. Fortsätter direkt med WPA-analysen.")
	} else if !isRecording && len(rawTraceFiles) > 0 {
		r.Output = append(r.Output, fmt.Sprintf("Den aktiva sessionen har stannat; återställer %d WPR-råfiler (%s) med wpr -merge...", len(rawTraceFiles), formatBytes(totalFileSize(rawTraceFiles))))
		outStr, runErr = mergeWPRRawTraces(wprPath, rawTraceFiles, outEtlPath)
	} else {
		outStr, runErr = stopWPRBootTrace(wprPath, outEtlPath)
		if runErr != nil {
			rawTraceFiles = findWPRRawTraceFiles(state.ScheduledAt)
			if len(rawTraceFiles) > 0 {
				r.Output = append(r.Output, "WPR-sessionen kunde inte stoppas normalt; försöker återställa de kvarvarande råfilerna...")
				outStr, runErr = mergeWPRRawTraces(wprPath, rawTraceFiles, outEtlPath)
			}
		}
	}
	if len(outStr) > 0 {
		r.Output = append(r.Output, outStr)
	}
	if runErr != nil {
		state.Status = "failed"
		state.LastError = fmt.Sprintf("WPR kunde inte stoppa eller sammanfoga boot-spårningen: %v (%s)", runErr, outStr)
		state.CommandOutput = outStr
		_ = saveWPRState(state)
		r.Message = state.LastError
		return r
	}

	fi, statErr := os.Stat(outEtlPath)
	if statErr != nil || fi.Size() < 1024 || (!state.ScheduledAt.IsZero() && fi.ModTime().Before(state.ScheduledAt)) {
		state.Status = "failed"
		state.LastError = "WPR rapporterade slutförande men skapade ingen ny, giltig ETL-fil."
		_ = saveWPRState(state)
		r.Success = false
		r.Message = "⚠️ " + state.LastError
		r.Output = append(r.Output, "ETL-filen saknas, är för liten eller kommer från ett äldre försök.")
		return r
	}

	fileSize := formatBytes(fi.Size())
	for _, rawPath := range rawTraceFiles {
		_ = os.Remove(rawPath)
	}
	analysis := analyzeWPRTrace(outEtlPath)
	summary := BootTraceSummaryMeta{
		TraceFilePath:   outEtlPath,
		TraceFileSize:   fileSize,
		TraceRecordedAt: time.Now().Format("2006-01-02 15:04:05"),
		SlowestDrivers:  analysis.SlowestDrivers,
		SlowestServices: analysis.SlowestServices,
		TopProcesses:    analysis.TopProcesses,
		NetworkFindings: analysis.NetworkFindings,
		AnalysisSource:  analysis.AnalysisSource,
		AnalysisError:   analysis.AnalysisError,
		AttemptID:       state.AttemptID,
	}
	if err := saveTraceSummary(summary); err != nil {
		state.Status = "captured_unanalyzed"
		state.LastError = fmt.Sprintf("ETL sparades men analyssammanfattningen kunde inte skrivas: %v", err)
		_ = saveWPRState(state)
		r.Success = false
		r.Message = state.LastError
		return r
	}

	state.IsConfigured = false
	state.AutoResume = false
	state.CommandOutput = outStr
	state.LastError = analysis.AnalysisError
	if analysis.AnalysisError != "" {
		state.Status = "captured_unanalyzed"
	} else {
		state.Status = "completed"
	}
	_ = saveWPRState(state)

	UnregisterRunOnceAutoResume()

	r.Success = true
	if analysis.AnalysisError != "" {
		r.Message = fmt.Sprintf("⚠️ ETL-spårningen sparades (%s), men automatisk WPA-analys väntar: %s", fileSize, analysis.AnalysisError)
	} else {
		r.Message = fmt.Sprintf("✅ Boot-spårningen sparades (%s) och analyserades med WPA Exporter.", fileSize)
	}
	r.Output = append(r.Output, fmt.Sprintf("WPA identifierade %d CPU-intensiva processer; reservkällor gav %d drivrutiner, %d tjänster och %d nätverkshändelser.", len(analysis.TopProcesses), len(analysis.SlowestDrivers), len(analysis.SlowestServices), len(analysis.NetworkFindings)))
	return r
}

func stopWPRBootTrace(wprPath, outEtlPath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, wprPath, "-stopboot", outEtlPath, "WinHealth Diagnostic Boot Trace")
	cmd.SysProcAttr = hiddenWindowProcAttr()
	outBytes, runErr := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(outBytes))
	if ctx.Err() == context.DeadlineExceeded {
		return outStr, fmt.Errorf("wpr -stopboot överskred tidsgränsen 10 minuter")
	}
	if runErr != nil && isAccessDeniedOutput(outStr) {
		exitCode, elevatedErr := runElevatedProcessWaitTimeout(wprPath, fmt.Sprintf("-stopboot \"%s\" \"WinHealth Diagnostic Boot Trace\"", outEtlPath), 10*time.Minute)
		if elevatedErr != nil || exitCode != 0 {
			return outStr, fmt.Errorf("upphöjd stopboot misslyckades (exit %d): %v", exitCode, elevatedErr)
		}
		return outStr, nil
	}
	return outStr, runErr
}

func mergeWPRRawTraces(wprPath string, rawTraceFiles []string, outEtlPath string) (string, error) {
	if len(rawTraceFiles) == 0 {
		return "", fmt.Errorf("inga WPR-råfiler hittades")
	}
	if fi, err := os.Stat(outEtlPath); err == nil && fi.Size() < 1024 {
		_ = os.Remove(outEtlPath)
	}
	args := make([]string, 0, len(rawTraceFiles)+5)
	args = append(args, "-merge")
	args = append(args, rawTraceFiles...)
	args = append(args, outEtlPath, "-compress", "-skipPdbGen")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, wprPath, args...)
	cmd.SysProcAttr = hiddenWindowProcAttr()
	outBytes, runErr := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(outBytes))
	if ctx.Err() == context.DeadlineExceeded {
		return outStr, fmt.Errorf("wpr -merge överskred tidsgränsen 20 minuter")
	}
	if runErr != nil && isAccessDeniedOutput(outStr) {
		quotedArgs := make([]string, 0, len(args))
		for _, arg := range args {
			quotedArgs = append(quotedArgs, fmt.Sprintf("\"%s\"", strings.ReplaceAll(arg, "\"", "\\\"")))
		}
		exitCode, elevatedErr := runElevatedProcessWaitTimeout(wprPath, strings.Join(quotedArgs, " "), 20*time.Minute)
		if elevatedErr != nil || exitCode != 0 {
			return outStr, fmt.Errorf("upphöjd wpr -merge misslyckades (exit %d): %v", exitCode, elevatedErr)
		}
		return outStr, nil
	}
	return outStr, runErr
}

func isAccessDeniedOutput(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "access is denied") || strings.Contains(lower, "0x80070005") || strings.Contains(lower, "åtkomst nekad")
}

// AnalyzeExistingWPRTrace retries WPA Exporter analysis for an already captured ETL.
// This is useful when Windows Performance Toolkit was installed after capture.
func AnalyzeExistingWPRTrace() models.FixActionResult {
	r := models.FixActionResult{
		ActionID: "analyze_wpr_trace", Timestamp: time.Now(), Title: "Analysera befintlig WPR-spårning",
		Output: make([]string, 0),
	}
	state := loadWPRState()
	tracePath := state.TraceFilePath
	if tracePath == "" {
		if summary, ok := loadTraceSummary(); ok {
			tracePath = summary.TraceFilePath
		}
	}
	fi, err := os.Stat(tracePath)
	if err != nil || fi.Size() < 1024 {
		r.Message = "Ingen giltig ETL-fil finns att analysera."
		return r
	}

	analysis := analyzeWPRTrace(tracePath)
	summary := BootTraceSummaryMeta{
		TraceFilePath: tracePath, TraceFileSize: formatBytes(fi.Size()),
		TraceRecordedAt: fi.ModTime().Format("2006-01-02 15:04:05"), AttemptID: state.AttemptID,
		SlowestDrivers: analysis.SlowestDrivers, SlowestServices: analysis.SlowestServices,
		TopProcesses: analysis.TopProcesses, NetworkFindings: analysis.NetworkFindings,
		AnalysisSource: analysis.AnalysisSource, AnalysisError: analysis.AnalysisError,
	}
	if err := saveTraceSummary(summary); err != nil {
		r.Message = fmt.Sprintf("Analysen kunde inte sparas: %v", err)
		return r
	}
	state.LastError = analysis.AnalysisError
	if analysis.AnalysisError != "" {
		state.Status = "captured_unanalyzed"
		r.Message = analysis.AnalysisError
	} else {
		state.Status = "completed"
		r.Success = true
		r.Message = fmt.Sprintf("ETL-filen analyserades med WPA Exporter: %d processer identifierades.", len(analysis.TopProcesses))
	}
	_ = saveWPRState(state)
	return r
}

// AnalyzeBootDriversAndServices queries system events and metrics for driver and service delays
func AnalyzeBootDriversAndServices() ([]models.BootTimingItem, []models.BootTimingItem) {
	drivers := make([]models.BootTimingItem, 0)
	services := make([]models.BootTimingItem, 0)

	psScript := `$drvList = @()
$srvList = @()
$bootStart = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime

# 1. Query Diagnostic-Performance Event 101 (Driver delays) & 102 (Service delays)
try {
    $filter = @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational'; Id=101,102,103}
    if ($bootStart) { $filter.StartTime = $bootStart }
    $degEvents = Get-WinEvent -FilterHashtable $filter -MaxEvents 50 -ErrorAction SilentlyContinue
    if ($degEvents) {
        foreach ($e in $degEvents) {
            [xml]$xml = $e.ToXml()
            $nameItem = $xml.Event.EventData.Data | Where-Object { $_.Name -in @('DriverFriendlyName','DriverName','ServiceName','ServiceFriendlyName','FriendlyName','ProcessName','Name','AppName') -and $_.'#text' } | Select-Object -First 1
            $nameVal = if ($nameItem) { [string]$nameItem.'#text' } else { "" }
            $timeItem = $xml.Event.EventData.Data | Where-Object { $_.Name -in @('TotalTime','DriverTotalTime','ServiceTotalTime') -and $_.'#text' } | Select-Object -First 1
            $timeVal = if ($timeItem) { [string]$timeItem.'#text' } else { "" }
            $pathItem = $xml.Event.EventData.Data | Where-Object { $_.Name -in @('Path','DriverPath','ServicePath','FilePath') -and $_.'#text' } | Select-Object -First 1
            $pathVal = if ($pathItem) { [string]$pathItem.'#text' } else { "" }
            
            if ($nameVal -and $timeVal) {
                $ms = [int]$timeVal
                if ($e.Id -eq 102) {
                    $drvList += [PSCustomObject]@{
                        name = $nameVal
                        category = "Drivrutin"
                        duration_ms = $ms
                        duration_sec = [math]::Round($ms / 1000, 2)
                        path = [string]$pathVal
                        description = "Drivrutin initierades på $ms ms vid uppstart."
                        source = "Diagnostics-Performance Event Log"
                    }
                } elseif ($e.Id -eq 103) {
                    $srvList += [PSCustomObject]@{
                        name = $nameVal
                        category = "Tjänst"
                        duration_ms = $ms
                        duration_sec = [math]::Round($ms / 1000, 2)
                        path = [string]$pathVal
                        description = "Tjänst startades på $ms ms vid uppstart."
                        source = "Diagnostics-Performance Event Log"
                    }
                } elseif ($e.Id -eq 101) {
                    $srvList += [PSCustomObject]@{
                        name = $nameVal
                        category = "Program"
                        duration_ms = $ms
                        duration_sec = [math]::Round($ms / 1000, 2)
                        path = [string]$pathVal
                        description = "Program initierades på $ms ms vid uppstart."
                        source = "Diagnostics-Performance Event Log"
                    }
                }
            }
        }
    }
} catch {}

[PSCustomObject]@{
    Drivers = $drvList
    Services = $srvList
} | ConvertTo-Json -Compress
`

	out, err := RunPowerShellWithTimeout(psScript, 20*time.Second)

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
	latestTraceFile := currentTraceFilePath()
	if fi, err := os.Stat(latestTraceFile); err == nil && fi.Size() > 0 {
		cmd := exec.Command("explorer.exe", fmt.Sprintf("/select,%s", latestTraceFile))
		return latestTraceFile, cmd.Start()
	}
	cmd := exec.Command("explorer.exe", traceDir)
	return traceDir, cmd.Start()
}

// OpenTraceInWPA opens the trace in Windows Performance Analyzer if installed
func OpenTraceInWPA() (bool, string, error) {
	latestTraceFile := currentTraceFilePath()
	if fi, err := os.Stat(latestTraceFile); err != nil || fi.Size() == 0 {
		return false, "", fmt.Errorf("ingen spårningsfil hittades (%s)", latestTraceFile)
	}

	wpaPath := findWPA()
	if wpaPath != "" {
		cmd := exec.Command(wpaPath, latestTraceFile)
		return true, wpaPath, cmd.Start()
	}

	return false, "", fmt.Errorf("Windows Performance Analyzer (wpa.exe) hittades inte på datorn")
}

func currentTraceFilePath() string {
	state := loadWPRState()
	if state.TraceFilePath != "" {
		return state.TraceFilePath
	}
	if summary, ok := loadTraceSummary(); ok {
		return summary.TraceFilePath
	}
	return ""
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
