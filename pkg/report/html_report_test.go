package report

import (
	"strings"
	"testing"
	"time"
	"winhealth/pkg/models"
)

func TestBuildHTMLContent_EscapesXSS(t *testing.T) {
	// Craft a report containing various XSS payloads in multiple fields
	rep := models.HealthReport{
		Timestamp:    time.Now(),
		ComputerName: `<script>alert("xss-computer")</script>`,
		OSVersion:    `Windows 11 <img src=x onerror=alert(1)>`,
		OSBuild:      `Build 22631 "onmouseover="alert(2)`,
		Uptime:       `2 dagar & <script>`,
		TotalScore:   85,
		ScoreRating:  `Bra <svg onload=alert(3)>`,
		TopIssues: []models.IssueSummary{
			{
				Category:    `<script>category</script>`,
				Title:       `<img src=x onerror=alert("title")>`,
				Description: `<b>Bold injection</b> <script>steal()</script>`,
				Severity:    models.SeverityWarning,
			},
		},
		Hardware: models.HardwareReport{
			Score:       90,
			CPUModel:    `Intel Core <script>cpu</script>`,
			Motherboard: `ASUS <iframe src="javascript:alert(1)">`,
			Disks: []models.DiskInfo{
				{
					DriveLetter:  `C:" onfocus="alert(1)`,
					Model:        `Samsung SSD <script>disk</script>`,
					SmartHealthy: true,
					TotalGB:      512,
					FreeGB:       256,
					UsagePct:     50,
				},
			},
		},
		Network: models.NetworkReport{
			Score:          95,
			InternetOK:     true,
			DefaultGateway: `192.168.1.1<script>gw</script>`,
			DNSServers: []models.DNSServerResult{
				{Server: `DNS <script>dns</script>`, Reachable: true, LatencyMs: 15},
			},
		},
		Security: models.SecurityReport{
			Score:                      90,
			AntivirusName:              `Defender <script>av</script>`,
			BitLockerStatus:            `BitLocker <script>bl</script>`,
			WindowsUpdateOverallStatus: `Updates <script>wu</script>`,
		},
		BootLogon: models.BootLogonReport{
			Score:      90,
			DomainName: `DOMAIN<script>dom</script>`,
			UnreachableResources: []models.UnreachableResource{
				{Name: `Share <script>share</script>`, TargetUNC: `\\server\share<script>`},
			},
			BootDegradations: []models.BootDegradationItem{
				{Type: `<script>type</script>`, Name: `Driver<script>`, Description: `Delay <script>`},
			},
		},
	}

	htmlOut := buildHTMLContent(&rep)

	// Check that raw script and dangerous tags are NOT present in output
	dangerousTags := []string{
		"<script>",
		"</script>",
		"<img src=x onerror=",
		"<svg onload=",
		"<iframe src=",
		`" onmouseover="`,
		`" onfocus="`,
	}

	for _, tag := range dangerousTags {
		if strings.Contains(htmlOut, tag) {
			t.Errorf("HTML report contains unescaped dangerous tag/attribute: %s", tag)
		}
	}

	// Verify that escaped representations exist
	if !strings.Contains(htmlOut, "&lt;script&gt;alert(&#34;xss-computer&#34;)&lt;/script&gt;") &&
		!strings.Contains(htmlOut, "&lt;script&gt;alert(&quot;xss-computer&quot;)&lt;/script&gt;") &&
		!strings.Contains(htmlOut, "&lt;script&gt;") {
		t.Errorf("Expected HTML entity escaping in report")
	}
}

func TestExportJSON(t *testing.T) {
	rep := models.HealthReport{
		ComputerName: "TEST-PC",
		TotalScore:   92,
	}

	tmpFile := t.TempDir() + "/test_report.json"
	saved, err := ExportJSON(&rep, tmpFile)
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}
	if saved != tmpFile {
		t.Errorf("Expected saved path %s, got %s", tmpFile, saved)
	}
}
