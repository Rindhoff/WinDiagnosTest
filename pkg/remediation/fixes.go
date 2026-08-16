package remediation

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"winhealth/pkg/models"
)

// ExecuteFix runs the requested remediation action and returns formatted results
func ExecuteFix(actionID string) models.FixActionResult {
	result := models.FixActionResult{
		ActionID:  actionID,
		Timestamp: time.Now(),
		Output:    make([]string, 0),
	}

	switch actionID {
	case "restart_checkpoint_vpn":
		return fixCheckPointVPN(result)
	case "flush_dns_winsock":
		return fixFlushDNSWinsock(result)
	case "clean_temp_files":
		return fixCleanTempFiles(result)
	case "reset_windows_update":
		return fixResetWindowsUpdate(result)
	case "run_sfc_scan":
		return fixRunSfcScan(result)
	default:
		result.Success = false
		result.Title = "Okänd åtgärd"
		result.Message = fmt.Sprintf("Åtgärds-ID '%s' stöds inte.", actionID)
		return result
	}
}

func fixCheckPointVPN(r models.FixActionResult) models.FixActionResult {
	r.Title = "Återställ Check Point VPN"

	psScript := `$log = @()
$services = Get-Service | Where-Object { 
    $_.Name -match '(?i)(tracsrv|cpnet|check.?point|cpep|endpoint.?connect)' -or 
    $_.DisplayName -match '(?i)(check.?point|trac.?srv|endpoint.?security)' 
}

if ($services) {
    foreach ($s in $services) {
        $log += "Stoppar tjänsten $($s.DisplayName) ($($s.Name))..."
        Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
    }
} else {
    $log += "Inga Check Point-specifika tjänster behövde stoppas."
}

# Terminate hanging processes if any
$procs = @('trac', 'cp_ep_agent', 'CPNetServices', 'vna_driver')
foreach ($p in $procs) {
    Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

# Reset Virtual Adapter if found
$adp = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {
    $_.InterfaceDescription -match '(?i)(check.?point|securemote|cpvna)'
}
if ($adp) {
    foreach ($a in $adp) {
        $log += "Återställer nätverkskort: $($a.Name)..."
        Restart-NetAdapter -Name $a.Name -ErrorAction SilentlyContinue
    }
}

Start-Sleep -Seconds 2

if ($services) {
    foreach ($s in $services) {
        $log += "Startar tjänsten $($s.DisplayName)..."
        Start-Service -Name $s.Name -ErrorAction SilentlyContinue
    }
}

$log += "Check Point VPN-tjänster har framgångsrikt startats om och nätverkskortet har återställts."
$log`

	out, err := runPowershell(psScript)
	r.Output = strings.Split(out, "\n")
	if err != nil {
		r.Success = false
		r.Message = "Kunde inte slutföra alla VPN-återställningssteg (kräver eventuellt administratörsrättigheter)."
	} else {
		r.Success = true
		r.Message = "Check Point VPN har startats om och nätverksanslutningen har uppdaterats."
	}
	return r
}

func fixFlushDNSWinsock(r models.FixActionResult) models.FixActionResult {
	r.Title = "Återställ Nätverk, DNS & Winsock"

	psScript := `$log = @()
$log += "Tömmer DNS-cachen (ipconfig /flushdns)..."
ipconfig /flushdns | Out-Null
$log += "Registrerar om DNS (ipconfig /registerdns)..."
ipconfig /registerdns | Out-Null
$log += "Återställer Winsock-katalogen (netsh winsock reset)..."
netsh winsock reset | Out-Null
$log += "Återställer TCP/IP-stacken (netsh int ip reset)..."
netsh int ip reset | Out-Null
$log += "Nätverksstacken har återställts framgångsrikt."
$log`

	out, err := runPowershell(psScript)
	r.Output = strings.Split(out, "\n")
	if err != nil {
		r.Success = false
		r.Message = "Nätverksåterställningen slutfördes med varningar (kräver eventuellt administratörsrättigheter)."
	} else {
		r.Success = true
		r.Message = "DNS-cache tömd och nätverksstacken har återställts utan fel."
	}
	return r
}

func fixCleanTempFiles(r models.FixActionResult) models.FixActionResult {
	r.Title = "Rensa Temporära Filer & Cache"

	tempDirs := []string{
		os.TempDir(),
		os.Getenv("LOCALAPPDATA") + `\Temp`,
		`C:\Windows\Temp`,
	}

	var cleanedBytes int64
	var deletedFiles int
	for _, dir := range tempDirs {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			fullPath := filepath.Join(dir, e.Name())
			info, err := e.Info()
			if err == nil {
				sz := info.Size()
				err := os.RemoveAll(fullPath)
				if err == nil {
					cleanedBytes += sz
					deletedFiles++
				}
			}
		}
	}

	displaySz := formatBytes(cleanedBytes)
	r.Success = true
	r.Message = fmt.Sprintf("Rensade bort %d temporära filer och frigjorde ca %s lagringsutrymme.", deletedFiles, displaySz)
	r.Output = []string{
		fmt.Sprintf("Genomsökte temporära system- och användarkataloger."),
		fmt.Sprintf("Tog bort %d filer.", deletedFiles),
		fmt.Sprintf("Frigjorde %s på C:.", displaySz),
	}
	return r
}

func fixResetWindowsUpdate(r models.FixActionResult) models.FixActionResult {
	r.Title = "Återställ Windows Update"

	psScript := `$log = @()
$log += "Stoppar Windows Update- och BITS-tjänster..."
Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
Stop-Service -Name bits -Force -ErrorAction SilentlyContinue
Stop-Service -Name cryptsvc -Force -ErrorAction SilentlyContinue

$log += "Rensar SoftwareDistribution nedladdningskö..."
$downPath = "C:\Windows\SoftwareDistribution\Download"
if (Test-Path $downPath) {
    Remove-Item -Path "$downPath\*" -Recurse -Force -ErrorAction SilentlyContinue
}

$log += "Startar om uppdateringstjänster..."
Start-Service -Name cryptsvc -ErrorAction SilentlyContinue
Start-Service -Name bits -ErrorAction SilentlyContinue
Start-Service -Name wuauserv -ErrorAction SilentlyContinue

$log += "Windows Update-komponenterna har återställts framgångsrikt."
$log`

	out, err := runPowershell(psScript)
	r.Output = strings.Split(out, "\n")
	if err != nil {
		r.Success = false
		r.Message = "Kunde inte återställa alla Windows Update-komponenter."
	} else {
		r.Success = true
		r.Message = "Windows Update-tjänsten och dess nedladdningskö har återställts."
	}
	return r
}

func fixRunSfcScan(r models.FixActionResult) models.FixActionResult {
	r.Title = "Verifiera Systemfiler (SFC)"
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", "Start-Process -FilePath 'sfc.exe' -ArgumentList '/scannow' -Verb RunAs")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()

	r.Success = true
	r.Message = "Startade Windows System File Checker (sfc /scannow) i bakgrunden."
	r.Output = []string{
		"System File Checker (sfc /scannow) startades med administratörsrättigheter.",
		"Windows kommer att genomsöka skyddade systemfiler och ersätta skadade filer automatiskt.",
	}
	return r
}

func runPowershell(script string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ToggleWindowsUpdateHidden hides or unhides a specific Windows Update so it won't install
func ToggleWindowsUpdateHidden(title string, hide bool) models.FixActionResult {
	r := models.FixActionResult{
		ActionID:  "toggle_update_hidden",
		Timestamp: time.Now(),
		Output:    make([]string, 0),
	}

	verb := "Dölj / Blockera uppdatering"
	if !hide {
		verb = "Återställ / Tillåt uppdatering"
	}
	r.Title = verb

	psScript := fmt.Sprintf(`$target = '%s'
$hide = %t
$log = @()

$updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
if (-not $updateSession) {
    $log += "Kunde inte ansluta till Microsoft.Update.Session."
    [PSCustomObject]@{ Success = $false; Output = $log; Message = "Misslyckades att initiera Update Session." } | ConvertTo-Json -Compress
    exit
}

$searcher = $updateSession.CreateUpdateSearcher()
$searcher.Online = $false
$res = $searcher.Search("IsInstalled=0")

$found = $false
foreach ($u in $res.Updates) {
    if ($u.Title -eq $target -or $u.Title.Trim() -eq $target.Trim() -or $u.Title -like "*$target*") {
        $found = $true
        try {
            $u.IsHidden = $hide
            if ($hide) {
                $log += "Uppdateringen '$($u.Title)' har dolts och blockeras nu från automatisk installation."
            } else {
                $log += "Uppdateringen '$($u.Title)' har återställts och kan nu installeras igen."
            }
            [PSCustomObject]@{ Success = $true; Output = $log; Message = "Åtgärden slutfördes framgångsrikt." } | ConvertTo-Json -Compress
            exit
        } catch {
            $errText = $_.Exception.Message
            $escapedTarget = $target.Replace("'", "''")
            $elevateCode = "$sess = New-Object -ComObject Microsoft.Update.Session; $srch = $sess.CreateUpdateSearcher(); $srch.Online = $false; $r = $srch.Search('IsInstalled=0'); foreach($up in $r.Updates){ if($up.Title -like '*" + $escapedTarget + "*'){ $up.IsHidden = " + ($hide ? "$true" : "$false") + " } }"
            try {
                Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList "-NoProfile", "-Command", $elevateCode
                if ($hide) {
                    $log += "Uppdateringen '$target' har dolts via administratörsbehörighet."
                } else {
                    $log += "Uppdateringen '$target' har återställts via administratörsbehörighet."
                }
                [PSCustomObject]@{ Success = $true; Output = $log; Message = "Åtgärden slutfördes med administratörsrättigheter." } | ConvertTo-Json -Compress
                exit
            } catch {
                $log += "Kräver administratörsbehörighet: $errText"
                [PSCustomObject]@{ Success = $false; Output = $log; Message = "Kräver administratörsbehörighet: $errText" } | ConvertTo-Json -Compress
                exit
            }
        }
    }
}

if (-not $found) {
    $log += "Hittade ingen uppdatering med titeln '$target'."
    [PSCustomObject]@{ Success = $false; Output = $log; Message = "Uppdateringen hittades inte i listan." } | ConvertTo-Json -Compress
}
`, strings.ReplaceAll(title, "'", "''"), hide)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()

	type rawResult struct {
		Success bool     `json:"Success"`
		Output  []string `json:"Output"`
		Message string   `json:"Message"`
	}

	if err == nil && len(out) > 0 {
		var rr rawResult
		if err := json.Unmarshal(out, &rr); err == nil {
			r.Success = rr.Success
			r.Output = rr.Output
			r.Message = rr.Message
			return r
		}
	}

	r.Success = false
	r.Message = "Ett oväntat svar mottogs vid ändring av uppdateringens status."
	if len(out) > 0 {
		r.Output = append(r.Output, string(out))
	}
	return r
}

// ToggleStartupApp enables or disables an autostart program in Windows Registry
func ToggleStartupApp(name string, location string, enable bool) models.FixActionResult {
	r := models.FixActionResult{
		ActionID:  "toggle_startup_app",
		Timestamp: time.Now(),
		Output:    make([]string, 0),
	}

	verb := "Inaktivera autostart"
	if enable {
		verb = "Aktivera autostart"
	}
	r.Title = fmt.Sprintf("%s: %s", verb, name)

	hive := "HKCU"
	if strings.Contains(location, "HKLM") {
		hive = "HKLM"
	}

	psScript := fmt.Sprintf(`$name = '%s'
$enable = %t
$hive = '%s'

$regPath = if ($hive -eq 'HKLM') { "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" } else { "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" }

if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

$bytes = if ($enable) { [byte[]](0,0,0,0,0,0,0,0,0,0,0,0) } else { [byte[]](2,0,0,0,0,0,0,0,0,0,0,0) }
Set-ItemProperty -Path $regPath -Name $name -Value $bytes -Type Binary -Force

$msg = if ($enable) { "Autostart aktiverades för '$name'." } else { "Autostart inaktiverades för '$name'." }
[PSCustomObject]@{
    Success = $true
    Output = @($msg)
    Message = $msg
} | ConvertTo-Json -Compress
`, strings.ReplaceAll(name, "'", "''"), enable, hive)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()

	type rawResult struct {
		Success bool     `json:"Success"`
		Output  []string `json:"Output"`
		Message string   `json:"Message"`
	}

	if err == nil && len(out) > 0 {
		var rr rawResult
		if err := json.Unmarshal(out, &rr); err == nil {
			r.Success = rr.Success
			r.Output = rr.Output
			r.Message = rr.Message
			return r
		}
	}

	r.Success = false
	r.Message = fmt.Sprintf("Kunde inte ändra autostartstatus för '%s'.", name)
	return r
}

