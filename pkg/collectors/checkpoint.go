package collectors

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"winhealth/pkg/models"
)

// CollectCheckPointDiagnostics runs deep, dynamic scanning for Check Point Endpoint / VPN
func CollectCheckPointDiagnostics() models.CheckPointReport {
	report := models.CheckPointReport{
		Detected:            false,
		Score:               100,
		Severity:            models.SeverityOK,
		Services:            make([]models.CheckPointService, 0),
		VirtualAdapters:     make([]models.CheckPointAdapter, 0),
		ActiveRoutes:        make([]string, 0),
		RecentLogErrors:     make([]string, 0),
		LogFilesFound:       make([]string, 0),
		GatewayConnectivity: make([]models.GatewayTestResult, 0),
		ConfigDetails:       make(map[string]string),
		DiagnosticNotes:     make([]string, 0),
	}

	// 1. Detect Services dynamically
	services := detectCheckPointServices()
	report.Services = services
	if len(services) > 0 {
		report.Detected = true
	}

	// 2. Detect Virtual Network Adapters
	adapters := detectCheckPointAdapters()
	report.VirtualAdapters = adapters
	if len(adapters) > 0 {
		report.Detected = true
	}

	// 3. Scan Filesystem for Install Paths & Logs
	installPath, logFiles, logErrors, clientVer := scanCheckPointFiles()
	if installPath != "" {
		report.Detected = true
		report.InstallPath = installPath
	}
	if clientVer != "" {
		report.ClientVersion = clientVer
	}
	report.LogFilesFound = logFiles
	report.RecentLogErrors = logErrors

	// 4. Scan Config & Test Gateways
	gateways, configMap := parseCheckPointConfig(installPath)
	report.ConfigDetails = configMap
	if len(configMap) > 0 {
		report.ConfigurationFound = true
	}
	for _, gw := range gateways {
		gwRes := testGatewayConnectivity(gw, 443)
		report.GatewayConnectivity = append(report.GatewayConnectivity, gwRes)
	}

	// 5. Scan Active Routing Table for VPN entries
	report.ActiveRoutes = detectVPNRoutes()

	// 6. Evaluate Health & Recommendations
	evaluateCheckPointHealth(&report)

	return report
}

// detectCheckPointServices queries Windows services matching CheckPoint patterns
func detectCheckPointServices() []models.CheckPointService {
	services := make([]models.CheckPointService, 0)

	// PowerShell script to query any CP/Trac/Endpoint services safely
	psScript := `Get-Service | Where-Object { 
		$_.Name -match '(?i)(tracsrv|cpnet|check.?point|cpep|endpoint.?connect|vna)' -or 
		$_.DisplayName -match '(?i)(check.?point|trac.?srv|endpoint.?security)' 
	} | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json -Compress`

	out, err := RunPowerShellWithTimeout(psScript, 8*time.Second)
	if err != nil || len(out) == 0 {
		return services
	}

	type psService struct {
		Name        string      `json:"Name"`
		DisplayName string      `json:"DisplayName"`
		Status      interface{} `json:"Status"`
		StartType   interface{} `json:"StartType"`
	}

	trimmed := strings.TrimSpace(string(out))
	var rawList []psService
	if strings.HasPrefix(trimmed, "[") {
		_ = json.Unmarshal([]byte(trimmed), &rawList)
	} else if strings.HasPrefix(trimmed, "{") {
		var single psService
		if err := json.Unmarshal([]byte(trimmed), &single); err == nil {
			rawList = append(rawList, single)
		}
	}

	for _, item := range rawList {
		statusStr := fmt.Sprintf("%v", item.Status)
		// PowerShell status code 4 = Running, 1 = Stopped
		if statusStr == "4" {
			statusStr = "Running"
		} else if statusStr == "1" {
			statusStr = "Stopped"
		}

		startTypeStr := fmt.Sprintf("%v", item.StartType)
		isHealthy := (statusStr == "Running" || statusStr == "4")

		services = append(services, models.CheckPointService{
			Name:        item.Name,
			DisplayName: item.DisplayName,
			Status:      statusStr,
			StartType:   startTypeStr,
			IsHealthy:   isHealthy,
		})
	}

	return services
}

// detectCheckPointAdapters queries network adapters matching CheckPoint virtual adapter names
func detectCheckPointAdapters() []models.CheckPointAdapter {
	adapters := make([]models.CheckPointAdapter, 0)

	psScript := `Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {
		$_.InterfaceDescription -match '(?i)(check.?point|securemote|virtual.?network.?adapter|cpvna)' -or
		$_.Name -match '(?i)(check.?point|securemote|cpvna)'
	} | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | ConvertTo-Json -Compress`

	out, err := RunPowerShellWithTimeout(psScript, 8*time.Second)
	if err != nil || len(out) == 0 {
		return adapters
	}

	type psAdapter struct {
		Name                 string `json:"Name"`
		InterfaceDescription string `json:"InterfaceDescription"`
		Status               string `json:"Status"`
		MacAddress           string `json:"MacAddress"`
		LinkSpeed            string `json:"LinkSpeed"`
	}

	trimmed := strings.TrimSpace(string(out))
	var rawList []psAdapter
	if strings.HasPrefix(trimmed, "[") {
		_ = json.Unmarshal([]byte(trimmed), &rawList)
	} else if strings.HasPrefix(trimmed, "{") {
		var single psAdapter
		if err := json.Unmarshal([]byte(trimmed), &single); err == nil {
			rawList = append(rawList, single)
		}
	}

	for _, item := range rawList {
		status := item.Status
		if status == "" {
			status = "Disabled/NotPresent"
		}
		isHealthy := strings.EqualFold(status, "Up") || strings.EqualFold(status, "Disconnected")

		adapters = append(adapters, models.CheckPointAdapter{
			Name:        item.Name,
			Description: item.InterfaceDescription,
			Status:      status,
			MACAddress:  item.MacAddress,
			IsHealthy:   isHealthy,
		})
	}

	return adapters
}

// scanCheckPointFiles dynamically searches Program Files, ProgramData, AppData for CheckPoint folders and log files
func scanCheckPointFiles() (string, []string, []string, string) {
	var installPath string
	logFiles := make([]string, 0)
	recentErrors := make([]string, 0)
	var clientVer string

	possibleRoots := []string{
		`C:\Program Files (x86)\CheckPoint`,
		`C:\Program Files\CheckPoint`,
		os.Getenv("ProgramData") + `\CheckPoint`,
		os.Getenv("APPDATA") + `\CheckPoint`,
		os.Getenv("LOCALAPPDATA") + `\CheckPoint`,
	}

	for _, root := range possibleRoots {
		if root == "" {
			continue
		}
		if fi, err := os.Stat(root); err == nil && fi.IsDir() {
			if installPath == "" && strings.Contains(root, "Program Files") {
				installPath = root
			}

			// Look for log files
			_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if err != nil || info == nil {
					return nil
				}
				if !info.IsDir() {
					lowerName := strings.ToLower(info.Name())
					if strings.HasSuffix(lowerName, ".log") || strings.HasSuffix(lowerName, ".elg") {
						logFiles = append(logFiles, path)
						// Parse last errors if modified in last 7 days
						if time.Since(info.ModTime()) < 7*24*time.Hour {
							errs := parseRecentErrorsFromLog(path, 15)
							recentErrors = append(recentErrors, errs...)
						}
					}
					if strings.EqualFold(lowerName, "trac.exe") || strings.EqualFold(lowerName, "cp_ep_agent.exe") {
						// Found executable
						if installPath == "" {
							installPath = filepath.Dir(path)
						}
					}
				}
				return nil
			})
		}
	}

	// Try reading version from registry if available
	psVerScript := `(Get-ItemProperty -Path 'HKLM:\SOFTWARE\CheckPoint\Endpoint Connect', 'HKLM:\SOFTWARE\WOW6432Node\CheckPoint\Endpoint Connect' -ErrorAction SilentlyContinue).ProductVersion`
	if out, err := RunPowerShellWithTimeout(psVerScript, 4*time.Second); err == nil {
		v := strings.TrimSpace(string(out))
		if v != "" {
			clientVer = v
		}
	}

	return installPath, logFiles, recentErrors, clientVer
}

// parseRecentErrorsFromLog reads the bottom lines of a log file searching for errors and warnings
func parseRecentErrorsFromLog(filePath string, maxEntries int) []string {
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > 500 {
			lines = lines[100:] // Keep last 400
		}
	}

	var errorsFound []string
	errorPattern := regexp.MustCompile(`(?i)(error|failed|fatal|exception|timeout|handshake fail|disconnect|cannot reach)`)

	for i := len(lines) - 1; i >= 0 && len(errorsFound) < maxEntries; i-- {
		line := strings.TrimSpace(lines[i])
		if errorPattern.MatchString(line) && len(line) > 5 {
			baseName := filepath.Base(filePath)
			errorsFound = append(errorsFound, fmt.Sprintf("[%s] %s", baseName, line))
		}
	}

	return errorsFound
}

// parseCheckPointConfig looks for config files to discover gateways
func parseCheckPointConfig(installPath string) ([]string, map[string]string) {
	gateways := make([]string, 0)
	details := make(map[string]string)

	possibleConfigs := []string{
		os.Getenv("ProgramData") + `\CheckPoint\Endpoint Security\Endpoint Connect\trac.config`,
		os.Getenv("ProgramData") + `\CheckPoint\Endpoint Connect\trac.config`,
		os.Getenv("APPDATA") + `\CheckPoint\Endpoint Connect\trac.config`,
	}

	if installPath != "" {
		possibleConfigs = append(possibleConfigs, filepath.Join(installPath, "trac.config"))
	}

	for _, cfgPath := range possibleConfigs {
		if data, err := os.ReadFile(cfgPath); err == nil {
			details["ConfigPath"] = cfgPath
			// Regex match server/gateway IPs or hostnames
			gwRegex := regexp.MustCompile(`(?i)<server[^>]*name=["']([^"']+)["']`)
			matches := gwRegex.FindAllStringSubmatch(string(data), -1)
			for _, m := range matches {
				if len(m) > 1 && !contains(gateways, m[1]) {
					gateways = append(gateways, m[1])
				}
			}
			ipRegex := regexp.MustCompile(`(?i)<ip[^>]*>([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)</ip>`)
			ipMatches := ipRegex.FindAllStringSubmatch(string(data), -1)
			for _, m := range ipMatches {
				if len(m) > 1 && !contains(gateways, m[1]) {
					gateways = append(gateways, m[1])
				}
			}
		}
	}

	return gateways, details
}

// testGatewayConnectivity tests TCP connectivity to a gateway on port 443
func testGatewayConnectivity(host string, port int) models.GatewayTestResult {
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return models.GatewayTestResult{
			Gateway:      host,
			Port:         port,
			Reachable:    false,
			LatencyMs:    latency,
			ErrorMessage: err.Error(),
		}
	}
	defer conn.Close()

	return models.GatewayTestResult{
		Gateway:   host,
		Port:      port,
		Reachable: true,
		LatencyMs: latency,
	}
}

// detectVPNRoutes inspects the routing table for VPN interfaces
func detectVPNRoutes() []string {
	var routes []string
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "netstat", "-rn")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return routes
	}

	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.Contains(trimmed, "Check Point") || strings.Contains(trimmed, "SecuRemote") {
			routes = append(routes, trimmed)
		}
	}
	return routes
}

// evaluateCheckPointHealth computes health score and action notes
func evaluateCheckPointHealth(r *models.CheckPointReport) {
	if !r.Detected {
		r.Score = 100
		r.Severity = models.SeverityOK
		r.DiagnosticNotes = append(r.DiagnosticNotes, "Check Point VPN är inte installerat eller aktivt på denna dator.")
		return
	}

	score := 100
	hasStoppedService := false

	for _, s := range r.Services {
		if !s.IsHealthy {
			score -= 30
			hasStoppedService = true
			r.DiagnosticNotes = append(r.DiagnosticNotes, fmt.Sprintf("Tjänsten '%s' körs inte (Status: %s).", s.DisplayName, s.Status))
		}
	}

	if len(r.VirtualAdapters) == 0 {
		score -= 15
		r.DiagnosticNotes = append(r.DiagnosticNotes, "Inget virtuellt nätverkskort för Check Point kunde detekteras.")
	} else {
		for _, adp := range r.VirtualAdapters {
			if !adp.IsHealthy {
				score -= 20
				r.DiagnosticNotes = append(r.DiagnosticNotes, fmt.Sprintf("Det virtuella nätverkskortet '%s' är inaktiverat eller har problem.", adp.Name))
			}
		}
	}

	for _, gw := range r.GatewayConnectivity {
		if !gw.Reachable {
			score -= 25
			r.DiagnosticNotes = append(r.DiagnosticNotes, fmt.Sprintf("VPN-gateway '%s' kunde inte nås över port %d (%s).", gw.Gateway, gw.Port, gw.ErrorMessage))
		}
	}

	if len(r.RecentLogErrors) > 0 {
		score -= 10
		r.DiagnosticNotes = append(r.DiagnosticNotes, fmt.Sprintf("%d nyliga fel eller varningar hittades i Check Point-klientloggarna.", len(r.RecentLogErrors)))
	}

	if score < 0 {
		score = 0
	}
	r.Score = score

	if score >= 90 {
		r.Severity = models.SeverityOK
		r.RecommendedAction = "VPN-klienten och dess tjänster är i gott skick."
	} else if score >= 70 {
		r.Severity = models.SeverityWarning
		if hasStoppedService {
			r.RecommendedAction = "Starta om Check Point-tjänsterna via snabbåtgärder."
		} else {
			r.RecommendedAction = "Kontrollera nätverkskontakt och autentiseringscertifikat."
		}
	} else {
		r.Severity = models.SeverityCritical
		r.RecommendedAction = "Kritiska fel i VPN-tjänsten eller adaptern. Kör 'Återställ Check Point VPN' i fliken Åtgärder."
	}
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if strings.EqualFold(item, val) {
			return true
		}
	}
	return false
}
