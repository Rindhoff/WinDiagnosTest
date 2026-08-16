package main

import (
	"testing"
	"winhealth/pkg/collectors"
	"winhealth/pkg/models"
	"winhealth/pkg/report"
)

func TestFullDiagnostics(t *testing.T) {
	rep := collectors.RunFullDiagnostics()

	if rep.ComputerName == "" {
		t.Errorf("Expected ComputerName to be populated")
	}

	if rep.TotalScore < 0 || rep.TotalScore > 100 {
		t.Errorf("Expected TotalScore between 0 and 100, got %d", rep.TotalScore)
	}

	if rep.ScoreRating == "" {
		t.Errorf("Expected ScoreRating to be non-empty")
	}

	// Verify CheckPoint collector ran
	if rep.CheckPointVPN.Score < 0 || rep.CheckPointVPN.Score > 100 {
		t.Errorf("Expected CheckPointVPN Score between 0 and 100, got %d", rep.CheckPointVPN.Score)
	}

	// Verify Hardware collector ran
	if rep.Hardware.CPUModel == "" {
		t.Errorf("Expected CPUModel to be populated")
	}

	// Verify Report generation
	tmpReportPath := "scratch_test_report.html"
	saved, err := report.GenerateHTMLReport(&rep, tmpReportPath)
	if err != nil {
		t.Errorf("Failed to generate HTML report: %v", err)
	}
	if saved == "" {
		t.Errorf("Expected saved path to be non-empty")
	}
}

func TestCheckPointCollector(t *testing.T) {
	cp := collectors.CollectCheckPointDiagnostics()
	if cp.Severity != models.SeverityOK && cp.Severity != models.SeverityWarning && cp.Severity != models.SeverityCritical && cp.Severity != models.SeverityInfo {
		t.Errorf("Unexpected severity: %v", cp.Severity)
	}
}

func TestBootLogonDiagnostics(t *testing.T) {
	boot := collectors.CollectBootLogonDiagnostics()
	if boot.TotalBootDurationSeconds < 0 {
		t.Errorf("Expected TotalBootDurationSeconds >= 0, got %f", boot.TotalBootDurationSeconds)
	}
	if boot.LastBootTime == "" {
		t.Errorf("Expected LastBootTime to be non-empty")
	}
	if !boot.BootTrace.IsAvailable {
		t.Logf("WPR is not installed or available on this system")
	} else {
		if boot.BootTrace.StatusMessage == "" {
			t.Errorf("Expected StatusMessage to be populated")
		}
	}
}

func TestWPRStatus(t *testing.T) {
	st := collectors.GetWPRStatus()
	t.Logf("WPR Status: IsConfigured=%v, IsRecording=%v, StatusMessage=%s", st.IsConfigured, st.IsRecording, st.StatusMessage)
	if st.StatusMessage == "" {
		t.Errorf("Expected non-empty StatusMessage from GetWPRStatus")
	}
}

