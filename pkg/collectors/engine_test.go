package collectors

import (
	"testing"
	"time"
	"winhealth/pkg/models"
)

func TestCalculateOverallScoreAndIssues_NoCheckPoint(t *testing.T) {
	rep := models.HealthReport{
		SummaryBadges: make(map[string]int),
		TopIssues:     make([]models.IssueSummary, 0),
		Hardware:      models.HardwareReport{Score: 100, Severity: models.SeverityOK},
		EventLogs:     models.EventLogsReport{Score: 100, Severity: models.SeverityOK},
		Network:       models.NetworkReport{Score: 100, Severity: models.SeverityOK, InternetOK: true},
		Security:      models.SecurityReport{Score: 100, Severity: models.SeverityOK, AntivirusEnabled: true, RealtimeProtection: true},
		BootLogon:     models.BootLogonReport{Score: 100, Severity: models.SeverityOK, TotalBootDurationSeconds: 15.0},
		Integrity:     models.IntegrityReport{Score: 100, Severity: models.SeverityOK},
		Performance:   models.PerformanceReport{Score: 100, Severity: models.SeverityOK},
		CheckPointVPN: models.CheckPointReport{Detected: false, Score: 100},
	}

	calculateOverallScoreAndIssues(&rep)

	if rep.TotalScore != 100 {
		t.Errorf("Expected TotalScore 100 on perfect health without CP, got %d", rep.TotalScore)
	}
	if rep.ScoreRating != "Utmärkt skick" {
		t.Errorf("Expected 'Utmärkt skick', got '%s'", rep.ScoreRating)
	}
	if rep.SummaryBadges["CRITICAL"] != 0 {
		t.Errorf("Expected 0 critical badges, got %d", rep.SummaryBadges["CRITICAL"])
	}
	if rep.SummaryBadges["OK"] <= 0 {
		t.Errorf("Expected positive OK checks count, got %d", rep.SummaryBadges["OK"])
	}
}

func TestCalculateOverallScore_BootLogonImpact(t *testing.T) {
	// Perfect report except BootLogon has 0 score
	rep := models.HealthReport{
		SummaryBadges: make(map[string]int),
		TopIssues:     make([]models.IssueSummary, 0),
		Hardware:      models.HardwareReport{Score: 100, Severity: models.SeverityOK},
		EventLogs:     models.EventLogsReport{Score: 100, Severity: models.SeverityOK},
		Network:       models.NetworkReport{Score: 100, Severity: models.SeverityOK, InternetOK: true},
		Security:      models.SecurityReport{Score: 100, Severity: models.SeverityOK, AntivirusEnabled: true, RealtimeProtection: true},
		BootLogon:     models.BootLogonReport{Score: 0, Severity: models.SeverityWarning},
		Integrity:     models.IntegrityReport{Score: 100, Severity: models.SeverityOK},
		Performance:   models.PerformanceReport{Score: 100, Severity: models.SeverityOK},
		CheckPointVPN: models.CheckPointReport{Detected: false, Score: 100},
	}

	calculateOverallScoreAndIssues(&rep)

	// BootLogon has 15% weight, so 100 - 15 = 85
	if rep.TotalScore != 85 {
		t.Errorf("Expected TotalScore 85 when BootLogon is 0, got %d", rep.TotalScore)
	}
}

func TestCalculateOverallScore_CriticalSeverityCapping(t *testing.T) {
	// High module scores but a critical issue is present
	rep := models.HealthReport{
		SummaryBadges: make(map[string]int),
		TopIssues:     make([]models.IssueSummary, 0),
		Hardware: models.HardwareReport{
			Score:    90,
			Severity: models.SeverityCritical,
			Disks: []models.DiskInfo{
				{DriveLetter: "C:", Model: "Test SSD", SmartHealthy: false},
			},
		},
		EventLogs:   models.EventLogsReport{Score: 100, Severity: models.SeverityOK},
		Network:     models.NetworkReport{Score: 100, Severity: models.SeverityOK, InternetOK: true},
		Security:    models.SecurityReport{Score: 100, Severity: models.SeverityOK, AntivirusEnabled: true, RealtimeProtection: true},
		BootLogon:   models.BootLogonReport{Score: 100, Severity: models.SeverityOK, TotalBootDurationSeconds: 12.0},
		Integrity:   models.IntegrityReport{Score: 100, Severity: models.SeverityOK},
		Performance: models.PerformanceReport{Score: 100, Severity: models.SeverityOK},
	}

	calculateOverallScoreAndIssues(&rep)

	// Should cap at 45 due to failing SMART disk
	if rep.TotalScore > 45 {
		t.Errorf("Expected TotalScore capped at <= 45 when failing SMART disk present, got %d", rep.TotalScore)
	}
	if rep.ScoreRating == "Utmärkt skick" || rep.ScoreRating == "Gott skick" {
		t.Errorf("Rating should not be good/excellent when critical disk issue exists, got '%s'", rep.ScoreRating)
	}
	if rep.SummaryBadges["CRITICAL"] != 1 {
		t.Errorf("Expected 1 critical badge, got %d", rep.SummaryBadges["CRITICAL"])
	}
}

func TestCalculateOverallScore_MultipleCriticals(t *testing.T) {
	// Multiple critical issues
	rep := models.HealthReport{
		SummaryBadges: make(map[string]int),
		TopIssues:     make([]models.IssueSummary, 0),
		Hardware: models.HardwareReport{
			Score:    60,
			Severity: models.SeverityCritical,
			Disks: []models.DiskInfo{
				{DriveLetter: "C:", Model: "Failing Disk", SmartHealthy: false},
			},
		},
		EventLogs: models.EventLogsReport{
			Score: 40,
			BSODCrashDumps: []models.MinidumpInfo{
				{FileName: "dump1.dmp", CreatedTime: time.Now()},
			},
		},
		Network: models.NetworkReport{
			Score:      0,
			InternetOK: false,
			Severity:   models.SeverityCritical,
		},
		Security: models.SecurityReport{
			Score:              0,
			RealtimeProtection: false,
			Severity:           models.SeverityCritical,
		},
		BootLogon:   models.BootLogonReport{Score: 100},
		Integrity:   models.IntegrityReport{Score: 100},
		Performance: models.PerformanceReport{Score: 100},
	}

	calculateOverallScoreAndIssues(&rep)

	if rep.TotalScore > 45 {
		t.Errorf("Expected TotalScore capped at <= 45 with critical issues, got %d", rep.TotalScore)
	}
	if rep.ScoreRating != "Åtgärd rekommenderas" {
		t.Errorf("Expected 'Åtgärd rekommenderas', got '%s'", rep.ScoreRating)
	}
}

func TestCalculateOverallScore_HealthyMachineWithBackgroundLogs(t *testing.T) {
	// Realistic machine with minor background noise (e.g. 20 error logs in 48h, 15GB temp files)
	rep := models.HealthReport{
		SummaryBadges: make(map[string]int),
		TopIssues:     make([]models.IssueSummary, 0),
		Hardware: models.HardwareReport{
			Score:    100,
			Severity: models.SeverityOK,
			Disks: []models.DiskInfo{
				{DriveLetter: "C:", Model: "NVMe SSD", SmartHealthy: true, UsagePct: 45.0, TotalGB: 512.0, FreeGB: 280.0},
			},
		},
		EventLogs: models.EventLogsReport{
			Score:          99,
			Severity:       models.SeverityOK,
			ErrorEventCount: 20,
		},
		Network: models.NetworkReport{
			Score:      100,
			Severity:   models.SeverityOK,
			InternetOK: true,
		},
		Security: models.SecurityReport{
			Score:                  95,
			Severity:               models.SeverityOK,
			AntivirusName:          "Windows Defender",
			AntivirusEnabled:       true,
			RealtimeProtection:     true,
			DefinitionsUpToDate:    true,
			FirewallEnabled:        true,
			WindowsUpdateServiceOK: true,
		},
		BootLogon: models.BootLogonReport{
			Score:                    100,
			Severity:                 models.SeverityOK,
			TotalBootDurationSeconds: 14.5,
		},
		Integrity: models.IntegrityReport{
			Score:              100,
			Severity:           models.SeverityOK,
			TempFilesSizeBytes: 15 * 1024 * 1024 * 1024,
		},
		Performance: models.PerformanceReport{
			Score:    100,
			Severity: models.SeverityOK,
		},
		CheckPointVPN: models.CheckPointReport{Detected: false, Score: 100},
	}

	calculateOverallScoreAndIssues(&rep)

	if rep.TotalScore < 90 {
		t.Errorf("Expected healthy machine to score >= 90, got %d", rep.TotalScore)
	}
	if rep.ScoreRating != "Utmärkt skick" {
		t.Errorf("Expected 'Utmärkt skick', got '%s'", rep.ScoreRating)
	}
	if len(rep.TopIssues) > 0 {
		t.Errorf("Expected 0 top issues for healthy machine, got %d", len(rep.TopIssues))
	}
}
