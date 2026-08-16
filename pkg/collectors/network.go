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

	out, _ := RunPowerShellWithTimeout(psScript, 8*time.Second)

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
		reachable, lat := pingGateway(report.DefaultGateway)
		if reachable {
			report.GatewayPingMs = lat
		} else {
			report.GatewayPingMs = -1
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

func pingGateway(gw string) (bool, int64) {
	if gw == "" {
		return false, 0
	}
	// Try TCP quick ping on port 53, 80, 443
	for _, port := range []string{"53", "80", "443"} {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(gw, port), 400*time.Millisecond)
		if err == nil {
			conn.Close()
			return true, time.Since(start).Milliseconds()
		}
	}

	// Try ICMP via Windows ping command
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping", "-n", "1", "-w", "800", gw)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	start := time.Now()
	out, err := cmd.Output()
	if err == nil {
		outStr := string(out)
		if strings.Contains(outStr, "TTL=") || strings.Contains(outStr, "Reply from") || strings.Contains(outStr, "Svar från") {
			lat := time.Since(start).Milliseconds()
			return true, lat
		}
	}
	return false, 0
}
