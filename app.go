package main

import (
	"context"
	"fmt"
	"sync"
	"time"
	"winhealth/pkg/collectors"
	"winhealth/pkg/models"
	"winhealth/pkg/remediation"
	"winhealth/pkg/report"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx        context.Context
	lastReport *models.HealthReport
	mu         sync.Mutex
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// GetHealthReport performs a full system scan and returns the complete health report
func (a *App) GetHealthReport() models.HealthReport {
	a.mu.Lock()
	defer a.mu.Unlock()

	rep := collectors.RunFullDiagnostics()
	a.lastReport = &rep
	return rep
}

// ExecuteQuickFix runs a remediation action like restarting VPN or flushing DNS
func (a *App) ExecuteQuickFix(actionID string) models.FixActionResult {
	return remediation.ExecuteFix(actionID)
}

// ToggleWindowsUpdateHidden hides or unhides a specific Windows Update so it won't be installed
func (a *App) ToggleWindowsUpdateHidden(title string, hide bool) models.FixActionResult {
	return remediation.ToggleWindowsUpdateHidden(title, hide)
}

// ToggleStartupApp enables or disables an autostart program in Windows
func (a *App) ToggleStartupApp(name string, location string, enable bool) models.FixActionResult {
	return remediation.ToggleStartupApp(name, location, enable)
}

// StartWPRBootTrace configures wpr.exe for boot tracing
func (a *App) StartWPRBootTrace(profile string) models.FixActionResult {
	return collectors.StartWPRBootTrace(profile)
}

// StartWPRBootTraceWithReboot configures wpr.exe, registers RunOnce auto-resume, and optionally reboots
func (a *App) StartWPRBootTraceWithReboot(profile string, rebootNow bool) models.FixActionResult {
	return collectors.StartWPRBootTraceWithReboot(profile, rebootNow)
}

// CancelPendingReboot cancels a scheduled shutdown / reboot
func (a *App) CancelPendingReboot() models.FixActionResult {
	return collectors.CancelPendingReboot()
}

// ClearTraceData removes previously stored trace files and summary
func (a *App) ClearTraceData() models.FixActionResult {
	return collectors.ClearTraceData()
}

// CancelWPRBootTrace cancels pending WPR boot tracing
func (a *App) CancelWPRBootTrace() models.FixActionResult {
	return collectors.CancelWPRBootTrace()
}

// StopWPRBootTrace stops active boot recording, saves .etl file, and analyzes results
func (a *App) StopWPRBootTrace() models.FixActionResult {
	return collectors.StopAndAnalyzeWPRBootTrace()
}

// AnalyzeExistingWPRTrace retries analysis of an already captured ETL file.
func (a *App) AnalyzeExistingWPRTrace() models.FixActionResult {
	return collectors.AnalyzeExistingWPRTrace()
}

// OpenWPTInstallGuide opens Microsoft's official ADK/WPT installation guide.
func (a *App) OpenWPTInstallGuide() {
	wailsRuntime.BrowserOpenURL(a.ctx, "https://learn.microsoft.com/windows-hardware/get-started/adk-install")
}

// OpenTraceFolder opens the trace directory or selects latest .etl file in Explorer
func (a *App) OpenTraceFolder() (string, error) {
	return collectors.OpenTraceFolder()
}

// OpenTraceInWPA opens the trace in Windows Performance Analyzer if available
func (a *App) OpenTraceInWPA() (bool, string, error) {
	return collectors.OpenTraceInWPA()
}

// GenerateAndOpenGPOReport generates a complete HTML report using gpresult.exe and opens it
func (a *App) GenerateAndOpenGPOReport() models.GPOReportResult {
	return collectors.GenerateGPOReport()
}

// GetAdvancedAutoruns returns deep autostart items across 30+ categories
func (a *App) GetAdvancedAutoruns() []models.AdvancedAutorunsItem {
	return collectors.ScanAdvancedAutoruns()
}

// ExportAndOpenHTMLReport prompts the user with a native Save File Dialog, generates the HTML report and opens it
func (a *App) ExportAndOpenHTMLReport() (string, error) {
	a.mu.Lock()
	rep := a.lastReport
	a.mu.Unlock()

	if rep == nil {
		fresh := collectors.RunFullDiagnostics()
		rep = &fresh
	}

	defaultDir := report.GetDefaultDesktopDirectory()
	defaultFile := fmt.Sprintf("HealthReport_%s_%s.html", rep.ComputerName, time.Now().Format("20060102_150405"))

	selectedPath, err := wailsRuntime.SaveFileDialog(a.ctx, wailsRuntime.SaveDialogOptions{
		DefaultDirectory: defaultDir,
		DefaultFilename:  defaultFile,
		Title:            "Välj var HTML-hälsorapporten ska sparas",
		Filters: []wailsRuntime.FileFilter{
			{
				DisplayName: "HTML-rapporter (*.html)",
				Pattern:     "*.html",
			},
			{
				DisplayName: "Alla filer (*.*)",
				Pattern:     "*.*",
			},
		},
	})

	if err != nil {
		return "", err
	}
	if selectedPath == "" {
		// User cancelled dialog
		return "", nil
	}

	savedPath, err := report.GenerateHTMLReport(rep, selectedPath)
	if err != nil {
		return "", err
	}

	_ = report.OpenReportInBrowser(savedPath)
	return savedPath, nil
}

// ExportJSONReport prompts the user with a native Save File Dialog and exports the report as JSON
func (a *App) ExportJSONReport() (string, error) {
	a.mu.Lock()
	rep := a.lastReport
	a.mu.Unlock()

	if rep == nil {
		fresh := collectors.RunFullDiagnostics()
		rep = &fresh
	}

	defaultDir := report.GetDefaultDesktopDirectory()
	defaultFile := fmt.Sprintf("HealthReport_%s_%s.json", rep.ComputerName, time.Now().Format("20060102_150405"))

	selectedPath, err := wailsRuntime.SaveFileDialog(a.ctx, wailsRuntime.SaveDialogOptions{
		DefaultDirectory: defaultDir,
		DefaultFilename:  defaultFile,
		Title:            "Välj var JSON-hälsorapporten ska sparas",
		Filters: []wailsRuntime.FileFilter{
			{
				DisplayName: "JSON-filer (*.json)",
				Pattern:     "*.json",
			},
			{
				DisplayName: "Alla filer (*.*)",
				Pattern:     "*.*",
			},
		},
	})

	if err != nil {
		return "", err
	}
	if selectedPath == "" {
		// User cancelled dialog
		return "", nil
	}

	savedPath, err := report.ExportJSON(rep, selectedPath)
	if err != nil {
		return "", err
	}

	return savedPath, nil
}
