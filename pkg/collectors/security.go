package collectors

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"syscall"
	"winhealth/pkg/models"
)

// CollectSecurityDiagnostics inspects Defender, BitLocker, Firewall and Windows Update
func CollectSecurityDiagnostics() models.SecurityReport {
	report := models.SecurityReport{
		Severity:                   models.SeverityOK,
		Score:                      100,
		AntivirusName:              "Windows Defender",
		AntivirusEnabled:           true,
		RealtimeProtection:         true,
		DefinitionsUpToDate:        true,
		BitLockerProtected:         false,
		BitLockerStatus:            "Ej skyddad / Inaktiverad",
		FirewallEnabled:            true,
		UACLevel:                   "Normal",
		WindowsUpdateServiceOK:     true,
		WindowsUpdateStatus:        "Aktiv / Standby (Normalt)",
		WindowsUpdateOverallStatus: "Datorn är uppdaterad",
		PendingUpdatesList:         make([]string, 0),
		PendingUpdatesDetails:      make([]models.WindowsUpdateItem, 0),
		HiddenUpdatesList:          make([]models.WindowsUpdateItem, 0),
		RecentUpdatesInstalled:     make([]string, 0),
	}

	psScript := `$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge
$fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }
$wuSvc = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue | Select-Object Status, StartType
$usoSvc = Get-Service -Name 'usosvc' -ErrorAction SilentlyContinue | Select-Object Status, StartType

# 1. BitLocker Detection (Multi-tier: Direct WMI + Driver / TPM events + Service status)
$blProtected = $false
$blStatus = "Ej skyddad / Inaktiverad"

$bl = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue | Select-Object ProtectionStatus, VolumeStatus, EncryptionMethod, KeyProtector
if ($bl -and ($bl.ProtectionStatus -eq 'On' -or $bl.ProtectionStatus -eq 1)) {
    $blProtected = $true
    $protectors = if ($bl.KeyProtector) { ($bl.KeyProtector.KeyProtectorType -join ', ') } else { "TPM/PIN" }
    $blStatus = "Skyddad (Aktiv kryptering på C: - $protectors)"
} else {
    # Fallback when running without full elevation: Check BitLocker Driver & TPM boot events
    $driverEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-BitLocker-Driver'} -MaxEvents 5 -ErrorAction SilentlyContinue
    $bdeSvc = Get-Service -Name 'BDESVC' -ErrorAction SilentlyContinue
    
    if ($driverEvents) {
        $hasTpmProtector = ($driverEvents | Where-Object { $_.Id -eq 24711 -or $_.Id -eq 24709 -or $_.Message -match 'TPM' })
        if ($hasTpmProtector) {
            $blProtected = $true
            $blStatus = "Skyddad (Aktiv BitLocker-kryptering med TPM/PIN)"
        } elseif ($bdeSvc -and $bdeSvc.Status -eq 'Running') {
            $blProtected = $true
            $blStatus = "Skyddad (BitLocker-tjänst aktiv)"
        }
    }
}

# 2. Windows Update Service & Health
$wuOk = $true
$wuStatusDisplay = "Aktiv / Standby (Normalt)"
if ($wuSvc) {
    if ($wuSvc.StartType -eq 'Disabled' -or $wuSvc.StartType -eq 4) {
        $wuOk = $false
        $wuStatusDisplay = "Inaktiverad (Fel)"
    } elseif ($wuSvc.Status -eq 'Running' -or $wuSvc.Status -eq 4) {
        $wuStatusDisplay = "Körs aktivt (Uppdaterar/Söker)"
    } else {
        $wuStatusDisplay = "I beredskap / Standby (Startar vid behov)"
    }
}

# 3. Query Pending & Hidden Updates
$pendingDetails = @()
$hiddenDetails = @()
$pendingTitles = @()
$recentInstalled = @()
$lastSearchDate = ""
$lastInstallDate = ""

$updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
if ($updateSession) {
    try {
        $searcher = $updateSession.CreateUpdateSearcher()
        $searcher.Online = $false
        $res = $searcher.Search("IsInstalled=0")
        foreach ($u in $res.Updates) {
            $cat = if ($u.Categories -and $u.Categories.Count -gt 0) { $u.Categories.Item(0).Name } else { "System" }
            $kb = if ($u.KBArticleIDs -and $u.KBArticleIDs.Count -gt 0) { "KB" + $u.KBArticleIDs.Item(0) } else { "" }
            $item = [PSCustomObject]@{
                title = $u.Title
                kb_article_id = $kb
                category = $cat
                is_hidden = [bool]$u.IsHidden
            }
            if ($u.IsHidden) {
                $hiddenDetails += $item
            } else {
                $pendingDetails += $item
                $pendingTitles += $u.Title
            }
        }
    } catch {}

    try {
        $searcher = $updateSession.CreateUpdateSearcher()
        $hist = $searcher.QueryHistory(0, 5)
        foreach ($h in $hist) {
            $recentInstalled += $h.Title
        }
    } catch {}
}

# AutoUpdate dates (LastSearch, LastInstall)
$autoUpdate = (New-Object -ComObject Microsoft.Update.AutoUpdate -ErrorAction SilentlyContinue).Results
if ($autoUpdate) {
    if ($autoUpdate.LastSearchSuccessDate) {
        $lastSearchDate = ([datetime]$autoUpdate.LastSearchSuccessDate).ToString("yyyy-MM-dd HH:mm")
    }
    if ($autoUpdate.LastInstallationSuccessDate) {
        $lastInstallDate = ([datetime]$autoUpdate.LastInstallationSuccessDate).ToString("yyyy-MM-dd HH:mm")
    }
}

if (-not $lastInstallDate) {
    $qfe = Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($qfe -and $qfe.InstalledOn) {
        $lastInstallDate = ([datetime]$qfe.InstalledOn).ToString("yyyy-MM-dd")
    }
}

# 4. Check pending reboot / update registry keys
$rebootPend = $false
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $rebootPend = $true }
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $rebootPend = $true }

# Determine overall update status string
$overallStatus = "Datorn är uppdaterad"
if ($rebootPend) {
    $overallStatus = "Omstart krävs för att slutföra installation"
} elseif ($pendingDetails.Count -gt 0) {
    $overallStatus = "$($pendingDetails.Count) uppdateringar väntar på installation"
}

[PSCustomObject]@{
    MpAntivirus = if ($mp) { $mp.AntivirusEnabled } else { $true }
    MpRealtime = if ($mp) { $mp.RealTimeProtectionEnabled } else { $true }
    MpSigAge = if ($mp) { $mp.AntivirusSignatureAge } else { 0 }
    BitLockerProtected = $blProtected
    BitLockerStatus = $blStatus
    FirewallActiveCount = if ($fw) { ($fw | Measure-Object).Count } else { 0 }
    WuOk = $wuOk
    WuStatusDisplay = $wuStatusDisplay
    PendingCount = $pendingDetails.Count
    PendingTitles = $pendingTitles
    PendingDetails = $pendingDetails
    HiddenCount = $hiddenDetails.Count
    HiddenDetails = $hiddenDetails
    LastSearchDate = $lastSearchDate
    LastInstallDate = $lastInstallDate
    OverallStatus = $overallStatus
    RecentInstalled = $recentInstalled
    RebootPending = $rebootPend
} | ConvertTo-Json -Compress`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, _ := cmd.Output()

	type rawSec struct {
		MpAntivirus         interface{}                `json:"MpAntivirus"`
		MpRealtime          interface{}                `json:"MpRealtime"`
		MpSigAge            int                        `json:"MpSigAge"`
		BitLockerProtected  bool                       `json:"BitLockerProtected"`
		BitLockerStatus     string                     `json:"BitLockerStatus"`
		FirewallActiveCount int                        `json:"FirewallActiveCount"`
		WuOk                bool                       `json:"WuOk"`
		WuStatusDisplay     string                     `json:"WuStatusDisplay"`
		PendingCount        int                        `json:"PendingCount"`
		PendingTitles       []string                   `json:"PendingTitles"`
		PendingDetails      []models.WindowsUpdateItem `json:"PendingDetails"`
		HiddenCount         int                        `json:"HiddenCount"`
		HiddenDetails       []models.WindowsUpdateItem `json:"HiddenDetails"`
		LastSearchDate      string                     `json:"LastSearchDate"`
		LastInstallDate     string                     `json:"LastInstallDate"`
		OverallStatus       string                     `json:"OverallStatus"`
		RecentInstalled     []string                   `json:"RecentInstalled"`
		RebootPending       bool                       `json:"RebootPending"`
	}

	if len(out) > 0 {
		var secData rawSec
		if err := json.Unmarshal(out, &secData); err == nil {
			if secData.MpAntivirus != nil {
				report.AntivirusEnabled = fmt.Sprintf("%v", secData.MpAntivirus) == "true" || fmt.Sprintf("%v", secData.MpAntivirus) == "1"
			}
			if secData.MpRealtime != nil {
				report.RealtimeProtection = fmt.Sprintf("%v", secData.MpRealtime) == "true" || fmt.Sprintf("%v", secData.MpRealtime) == "1"
			}
			if secData.MpSigAge > 14 {
				report.DefinitionsUpToDate = false
			}

			report.BitLockerProtected = secData.BitLockerProtected
			if secData.BitLockerStatus != "" {
				report.BitLockerStatus = secData.BitLockerStatus
			}

			report.FirewallEnabled = secData.FirewallActiveCount > 0

			report.WindowsUpdateServiceOK = secData.WuOk
			if secData.WuStatusDisplay != "" {
				report.WindowsUpdateStatus = secData.WuStatusDisplay
			}
			if secData.OverallStatus != "" {
				report.WindowsUpdateOverallStatus = secData.OverallStatus
			}
			report.LastUpdateSearchTime = secData.LastSearchDate
			report.LastUpdateInstallTime = secData.LastInstallDate

			report.PendingUpdatesCount = secData.PendingCount
			if len(secData.PendingTitles) > 0 {
				report.PendingUpdatesList = secData.PendingTitles
			}
			if len(secData.PendingDetails) > 0 {
				report.PendingUpdatesDetails = secData.PendingDetails
			}
			report.HiddenUpdatesCount = secData.HiddenCount
			if len(secData.HiddenDetails) > 0 {
				report.HiddenUpdatesList = secData.HiddenDetails
			}
			if len(secData.RecentInstalled) > 0 {
				report.RecentUpdatesInstalled = secData.RecentInstalled
			}

			if secData.RebootPending {
				report.PendingUpdatesList = append(report.PendingUpdatesList, "Väntande omstart krävs för att slutföra installationer.")
			}
		}
	}

	// Calculate Score
	score := 100
	if !report.RealtimeProtection {
		score -= 30
		report.Severity = models.SeverityCritical
	}
	if !report.FirewallEnabled {
		score -= 25
		if report.Severity != models.SeverityCritical {
			report.Severity = models.SeverityWarning
		}
	}
	if !report.DefinitionsUpToDate {
		score -= 15
		if report.Severity == models.SeverityOK {
			report.Severity = models.SeverityWarning
		}
	}
	if !report.BitLockerProtected {
		score -= 10
	}
	if !report.WindowsUpdateServiceOK {
		score -= 20
	}

	if score < 0 {
		score = 0
	}
	report.Score = score

	return report
}
