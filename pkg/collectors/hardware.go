package collectors

import (
	"encoding/json"
	"math"
	"os/exec"
	"strings"
	"syscall"
	"winhealth/pkg/models"
)

// CollectHardwareDiagnostics collects CPU, RAM, Disk SMART and Battery metrics
func CollectHardwareDiagnostics() models.HardwareReport {
	report := models.HardwareReport{
		Severity: models.SeverityOK,
		Score:    100,
		Disks:    make([]models.DiskInfo, 0),
	}

	// PowerShell script to gather hardware details in a single fast JSON bundle
	psScript := `$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 Name, NumberOfCores, LoadPercentage
$os = Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory
$bb = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue | Select-Object -First 1 Manufacturer, Product
$bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1 SMBIOSBIOSVersion

$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    $driveLetter = $_.DeviceID
    $vol = Get-Volume -DriveLetter $driveLetter.Replace(':','') -ErrorAction SilentlyContinue
    $phys = Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object -First 1 FriendlyName, MediaType, HealthStatus, OperationalStatus
    [PSCustomObject]@{
        DeviceID = $_.DeviceID
        DriveLetter = $driveLetter
        FileSystem = $_.FileSystem
        TotalBytes = $_.Size
        FreeBytes = $_.FreeSpace
        Model = if ($phys) { $phys.FriendlyName } else { "Local Disk" }
        MediaType = if ($phys) { $phys.MediaType } else { "SSD/HDD" }
        HealthStatus = if ($phys) { $phys.HealthStatus } else { "Healthy" }
        OperationalStatus = if ($phys) { ($phys.OperationalStatus -join ', ') } else { "OK" }
    }
}

$batteryObj = $null
$batt = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1 EstimatedChargeRemaining, BatteryStatus, DesignCapacity, FullChargeCapacity
if ($batt) {
    $batteryObj = [PSCustomObject]@{
        ChargePercent = $batt.EstimatedChargeRemaining
        BatteryStatus = $batt.BatteryStatus
        DesignCapacity = $batt.DesignCapacity
        FullCapacity = $batt.FullChargeCapacity
    }
}

[PSCustomObject]@{
    CPUName = $cpu.Name
    CPUCores = $cpu.NumberOfCores
    CPULoad = $cpu.LoadPercentage
    TotalRAMKB = $os.TotalVisibleMemorySize
    FreeRAMKB = $os.FreePhysicalMemory
    Motherboard = "$($bb.Manufacturer) $($bb.Product)"
    BIOSVersion = $bios.SMBIOSBIOSVersion
    Disks = $disks
    Battery = $batteryObj
} | ConvertTo-Json -Depth 3 -Compress`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		report.CPUModel = "Windows Computer"
		report.CPUCores = 4
		return report
	}

	type rawHW struct {
		CPUName     string      `json:"CPUName"`
		CPUCores    int         `json:"CPUCores"`
		CPULoad     interface{} `json:"CPULoad"`
		TotalRAMKB  int64       `json:"TotalRAMKB"`
		FreeRAMKB   int64       `json:"FreeRAMKB"`
		Motherboard string      `json:"Motherboard"`
		BIOSVersion string      `json:"BIOSVersion"`
		Disks       interface{} `json:"Disks"`
		Battery     *struct {
			ChargePercent  int   `json:"ChargePercent"`
			BatteryStatus  int   `json:"BatteryStatus"`
			DesignCapacity int64 `json:"DesignCapacity"`
			FullCapacity   int64 `json:"FullCapacity"`
		} `json:"Battery"`
	}

	var data rawHW
	if err := json.Unmarshal(out, &data); err != nil {
		return report
	}

	report.CPUModel = strings.TrimSpace(data.CPUName)
	report.CPUCores = data.CPUCores
	if data.CPULoad != nil {
		if val, ok := data.CPULoad.(float64); ok {
			report.CPUUsagePct = val
		}
	}
	report.Motherboard = strings.TrimSpace(data.Motherboard)
	report.BIOSVersion = strings.TrimSpace(data.BIOSVersion)

	if data.TotalRAMKB > 0 {
		report.TotalRAMGB = round(float64(data.TotalRAMKB)/(1024*1024), 1)
		report.FreeRAMGB = round(float64(data.FreeRAMKB)/(1024*1024), 1)
		report.UsedRAMGB = round(report.TotalRAMGB-report.FreeRAMGB, 1)
		if report.TotalRAMGB > 0 {
			report.RAMUsagePct = round((report.UsedRAMGB/report.TotalRAMGB)*100, 1)
		}
	}

	// Parse Disks
	if data.Disks != nil {
		diskBytes, _ := json.Marshal(data.Disks)
		type rawDisk struct {
			DeviceID          string      `json:"DeviceID"`
			DriveLetter       string      `json:"DriveLetter"`
			FileSystem        string      `json:"FileSystem"`
			TotalBytes        int64       `json:"TotalBytes"`
			FreeBytes         int64       `json:"FreeBytes"`
			Model             string      `json:"Model"`
			MediaType         string      `json:"MediaType"`
			HealthStatus      string      `json:"HealthStatus"`
			OperationalStatus string      `json:"OperationalStatus"`
		}

		var diskList []rawDisk
		if strings.HasPrefix(string(diskBytes), "[") {
			_ = json.Unmarshal(diskBytes, &diskList)
		} else if strings.HasPrefix(string(diskBytes), "{") {
			var single rawDisk
			if err := json.Unmarshal(diskBytes, &single); err == nil {
				diskList = append(diskList, single)
			}
		}

		for _, d := range diskList {
			totalGB := round(float64(d.TotalBytes)/(1024*1024*1024), 1)
			freeGB := round(float64(d.FreeBytes)/(1024*1024*1024), 1)
			usedGB := round(totalGB-freeGB, 1)
			var usagePct float64
			if totalGB > 0 {
				usagePct = round((usedGB/totalGB)*100, 1)
			}

			smartHealthy := true
			smartStatus := d.HealthStatus
			if smartStatus == "" {
				smartStatus = "OK"
			}
			if strings.EqualFold(smartStatus, "Unhealthy") || strings.Contains(strings.ToLower(smartStatus), "fail") {
				smartHealthy = false
			}

			report.Disks = append(report.Disks, models.DiskInfo{
				DeviceID:      d.DeviceID,
				Model:         d.Model,
				MediaType:     d.MediaType,
				DriveLetter:   d.DriveLetter,
				FileSystem:    d.FileSystem,
				TotalGB:       totalGB,
				FreeGB:        freeGB,
				UsedGB:        usedGB,
				UsagePct:      usagePct,
				SmartStatus:   smartStatus,
				SmartHealthy:  smartHealthy,
				IsSystemDrive: strings.EqualFold(d.DriveLetter, "C:"),
			})
		}
	}

	// Parse Battery
	if data.Battery != nil {
		batt := &models.BatteryInfo{
			Present:        true,
			ChargePercent:  data.Battery.ChargePercent,
			DesignCapacity: data.Battery.DesignCapacity,
			FullCapacity:   data.Battery.FullCapacity,
		}
		switch data.Battery.BatteryStatus {
		case 1:
			batt.Status = "Urladdas (Batteridrift)"
		case 2:
			batt.Status = "Ansluten till nätström"
		case 3:
			batt.Status = "Fulladdad"
		case 4:
			batt.Status = "Låg batterinivå"
		case 5:
			batt.Status = "Kritisk batterinivå"
		case 6:
			batt.Status = "Laddar"
		default:
			batt.Status = "Normal"
		}

		if data.Battery.DesignCapacity > 0 && data.Battery.FullCapacity > 0 {
			batt.HealthPct = round((float64(data.Battery.FullCapacity)/float64(data.Battery.DesignCapacity))*100, 1)
		} else {
			batt.HealthPct = 100.0
		}
		report.Battery = batt
	}

	// Calculate Score & Severity
	score := 100
	for _, disk := range report.Disks {
		if !disk.SmartHealthy {
			score -= 40
			report.Severity = models.SeverityCritical
		}
		if disk.UsagePct > 92 {
			score -= 20
			if report.Severity != models.SeverityCritical {
				report.Severity = models.SeverityWarning
			}
		} else if disk.UsagePct > 85 {
			score -= 10
		}
	}

	if report.RAMUsagePct > 90 {
		score -= 15
		if report.Severity == models.SeverityOK {
			report.Severity = models.SeverityWarning
		}
	}

	if score < 0 {
		score = 0
	}
	report.Score = score

	return report
}

func round(val float64, precision int) float64 {
	p := math.Pow(10, float64(precision))
	return math.Round(val*p) / p
}
