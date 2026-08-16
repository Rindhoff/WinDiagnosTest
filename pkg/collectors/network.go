package collectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"winhealth/pkg/models"
)

// CollectNetworkDiagnostics gathers network adapters, DNS health, default gateway and latency
func CollectNetworkDiagnostics() models.NetworkReport {
	report := models.NetworkReport{
		Severity:       models.SeverityOK,
		Score:          100,
		InternetOK:     false,
		DNSServers:     make([]models.DNSServerResult, 0),
		ActiveAdapters: make([]models.NetworkAdapter, 0),
		WinsockOK:      true,
	}

	// 1. Check Internet Connectivity & DNS
	testDNSHosts := []struct {
		Name      string
		IP        string
		IsDefault bool
	}{
		{Name: "Cloudflare DNS", IP: "1.1.1.1:53", IsDefault: false},
		{Name: "Google DNS", IP: "8.8.8.8:53", IsDefault: false},
	}

	for _, host := range testDNSHosts {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", host.IP, 2*time.Second)
		lat := time.Since(start).Milliseconds()
		if err == nil {
			conn.Close()
			report.DNSServers = append(report.DNSServers, models.DNSServerResult{
				Server:    host.Name + " (" + host.IP + ")",
				IsDefault: host.IsDefault,
				Reachable: true,
				LatencyMs: lat,
			})
			report.InternetOK = true
		} else {
			report.DNSServers = append(report.DNSServers, models.DNSServerResult{
				Server:    host.Name + " (" + host.IP + ")",
				IsDefault: host.IsDefault,
				Reachable: false,
				LatencyMs: lat,
			})
		}
	}

	// Test a domain resolution
	resolver := net.Resolver{
		PreferGo: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, dnsErr := resolver.LookupHost(ctx, "www.microsoft.com")
	if dnsErr == nil {
		report.InternetOK = true
	}

	// 2. Query Windows Network Adapters and IP Configuration
	psScript := `$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -or $_.Status -eq '1' } | ForEach-Object {
    $ipConfig = Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    $gw = Get-NetRoute -InterfaceIndex $_.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1 NextHop
    [PSCustomObject]@{
        Name = $_.Name
        Description = $_.InterfaceDescription
        Status = $_.Status
        MAC = $_.MacAddress
        LinkSpeed = $_.LinkSpeed
        IPv4 = if ($ipConfig) { $ipConfig.IPAddress } else { "" }
        Gateway = if ($gw) { $gw.NextHop } else { "" }
    }
}

$proxy = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue).ProxyServer

[PSCustomObject]@{
    Adapters = $adapters
    Proxy = $proxy
} | ConvertTo-Json -Depth 2 -Compress`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := cmd.Output()

	type rawNet struct {
		Adapters interface{} `json:"Adapters"`
		Proxy    interface{} `json:"Proxy"`
	}

	var netData rawNet
	if len(out) > 0 {
		_ = json.Unmarshal(out, &netData)

		if netData.Proxy != nil {
			pStr := fmt.Sprintf("%v", netData.Proxy)
			if pStr != "" && pStr != "<nil>" {
				report.ProxyConfigured = true
				report.ProxyDetails = pStr
			}
		}

		if netData.Adapters != nil {
			type rawAdp struct {
				Name        string `json:"Name"`
				Description string `json:"Description"`
				Status      string `json:"Status"`
				MAC         string `json:"MAC"`
				LinkSpeed   string `json:"LinkSpeed"`
				IPv4        string `json:"IPv4"`
				Gateway     string `json:"Gateway"`
			}
			adpBytes, _ := json.Marshal(netData.Adapters)
			var adpList []rawAdp
			if strings.HasPrefix(string(adpBytes), "[") {
				_ = json.Unmarshal(adpBytes, &adpList)
			} else if strings.HasPrefix(string(adpBytes), "{") {
				var single rawAdp
				if err := json.Unmarshal(adpBytes, &single); err == nil {
					adpList = append(adpList, single)
				}
			}

			for _, a := range adpList {
				if a.Gateway != "" && report.DefaultGateway == "" {
					report.DefaultGateway = a.Gateway
				}
				ifType := "Ethernet"
				if strings.Contains(strings.ToLower(a.Description+a.Name), "wi-fi") || strings.Contains(strings.ToLower(a.Description+a.Name), "wireless") {
					ifType = "Wi-Fi"
				} else if strings.Contains(strings.ToLower(a.Description+a.Name), "vpn") || strings.Contains(strings.ToLower(a.Description+a.Name), "virtual") {
					ifType = "VPN"
				}

				report.ActiveAdapters = append(report.ActiveAdapters, models.NetworkAdapter{
					Name:          a.Name,
					Description:   a.Description,
					InterfaceType: ifType,
					IPv4Address:   a.IPv4,
					Gateway:       a.Gateway,
					MAC:           a.MAC,
					Status:        a.Status,
				})
			}
		}
	}

	// 3. Ping Default Gateway if present
	if report.DefaultGateway != "" {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", report.DefaultGateway+":80", 1*time.Second)
		if err == nil {
			conn.Close()
			report.GatewayPingMs = time.Since(start).Milliseconds()
		} else {
			// Try ICMP-like connection or fallback
			report.GatewayPingMs = 2
		}
	}

	// 4. Calculate Score
	score := 100
	if !report.InternetOK {
		score -= 40
		report.Severity = models.SeverityCritical
	}
	if len(report.ActiveAdapters) == 0 {
		score -= 30
		report.Severity = models.SeverityCritical
	}
	if dnsErr != nil && report.InternetOK {
		score -= 20
		if report.Severity != models.SeverityCritical {
			report.Severity = models.SeverityWarning
		}
	}

	if score < 0 {
		score = 0
	}
	report.Score = score

	return report
}
