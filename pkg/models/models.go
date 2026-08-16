package models

import "time"

// Severity represents the issue severity level
type Severity string

const (
	SeverityOK       Severity = "OK"
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

// HealthReport is the top-level report returned to the frontend
type HealthReport struct {
	Timestamp      time.Time         `json:"timestamp"`
	ComputerName   string            `json:"computer_name"`
	OSVersion      string            `json:"os_version"`
	OSBuild        string            `json:"os_build"`
	Architecture   string            `json:"architecture"`
	Uptime         string            `json:"uptime"`
	TotalScore     int               `json:"total_score"`    // 0 - 100
	ScoreRating    string            `json:"score_rating"`   // "Utmärkt", "Bra", "Varning", "Kritiskt"
	SummaryBadges  map[string]int    `json:"summary_badges"` // counts of OK, Warning, Critical
	TopIssues      []IssueSummary    `json:"top_issues"`
	CheckPointVPN  CheckPointReport  `json:"checkpoint_vpn"`
	Hardware       HardwareReport    `json:"hardware"`
	EventLogs      EventLogsReport   `json:"event_logs"`
	Network        NetworkReport     `json:"network"`
	Security       SecurityReport    `json:"security"`
	Performance    PerformanceReport `json:"performance"`
	Integrity      IntegrityReport   `json:"integrity"`
	BootLogon      BootLogonReport   `json:"boot_logon"`
	QuickFixStatus map[string]bool   `json:"quick_fix_status"`
}

type IssueSummary struct {
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	FixActionId string   `json:"fix_action_id,omitempty"`
}

// CheckPointReport contains full diagnostics for Check Point Endpoint Security / VPN
type CheckPointReport struct {
	Detected            bool                `json:"detected"`
	ClientVersion       string              `json:"client_version"`
	InstallPath         string              `json:"install_path"`
	Severity            Severity            `json:"severity"`
	Score               int                 `json:"score"` // 0-100
	Services            []CheckPointService `json:"services"`
	VirtualAdapters     []CheckPointAdapter `json:"virtual_adapters"`
	ActiveRoutes        []string            `json:"active_routes"`
	RecentLogErrors     []string            `json:"recent_log_errors"`
	LogFilesFound       []string            `json:"log_files_found"`
	GatewayConnectivity []GatewayTestResult `json:"gateway_connectivity"`
	ConfigurationFound  bool                `json:"configuration_found"`
	ConfigDetails       map[string]string   `json:"config_details"`
	DiagnosticNotes     []string            `json:"diagnostic_notes"`
	RecommendedAction   string              `json:"recommended_action"`
}

type CheckPointService struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"` // Running, Stopped, etc.
	StartType   string `json:"start_type"`
	BinaryPath  string `json:"binary_path"`
	IsHealthy   bool   `json:"is_healthy"`
}

type CheckPointAdapter struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Status      string   `json:"status"` // Up, Down, Disabled
	IPAddresses []string `json:"ip_addresses"`
	MACAddress  string   `json:"mac_address"`
	MTU         int      `json:"mtu"`
	IsHealthy   bool     `json:"is_healthy"`
}

type GatewayTestResult struct {
	Gateway      string `json:"gateway"`
	Port         int    `json:"port"`
	Reachable    bool   `json:"reachable"`
	LatencyMs    int64  `json:"latency_ms"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// HardwareReport contains CPU, RAM, Disk and Battery metrics
type HardwareReport struct {
	Severity    Severity     `json:"severity"`
	Score       int          `json:"score"`
	CPUModel    string       `json:"cpu_model"`
	CPUCores    int          `json:"cpu_cores"`
	CPUUsagePct float64      `json:"cpu_usage_pct"`
	TotalRAMGB  float64      `json:"total_ram_gb"`
	UsedRAMGB   float64      `json:"used_ram_gb"`
	FreeRAMGB   float64      `json:"free_ram_gb"`
	RAMUsagePct float64      `json:"ram_usage_pct"`
	Disks       []DiskInfo   `json:"disks"`
	Battery     *BatteryInfo `json:"battery,omitempty"`
	Motherboard string       `json:"motherboard"`
	BIOSVersion string       `json:"bios_version"`
}

type DiskInfo struct {
	DeviceID      string  `json:"device_id"`
	Model         string  `json:"model"`
	MediaType     string  `json:"media_type"` // SSD, HDD, NVMe
	DriveLetter   string  `json:"drive_letter"`
	FileSystem    string  `json:"file_system"`
	TotalGB       float64 `json:"total_gb"`
	FreeGB        float64 `json:"free_gb"`
	UsedGB        float64 `json:"used_gb"`
	UsagePct      float64 `json:"usage_pct"`
	SmartStatus   string  `json:"smart_status"` // OK, Pred Fail, Warning
	SmartHealthy  bool    `json:"smart_healthy"`
	IsSystemDrive bool    `json:"is_system_drive"`
}

type BatteryInfo struct {
	Present        bool    `json:"present"`
	ChargePercent  int     `json:"charge_percent"`
	Status         string  `json:"status"`     // Charging, Discharging, AC Connected
	HealthPct      float64 `json:"health_pct"` // Design Capacity vs Full Charge
	DesignCapacity int64   `json:"design_capacity"`
	FullCapacity   int64   `json:"full_capacity"`
	CycleCount     int     `json:"cycle_count"`
}

// EventLogsReport contains crash analysis and recent errors
type EventLogsReport struct {
	Severity           Severity        `json:"severity"`
	Score              int             `json:"score"`
	BSODCrashDumps     []MinidumpInfo  `json:"bsod_crash_dumps"`
	RecentSystemErrors []EventLogEntry `json:"recent_system_errors"`
	RecentAppCrashes   []EventLogEntry `json:"recent_app_crashes"`
	CriticalEventCount int             `json:"critical_event_count"`
	ErrorEventCount    int             `json:"error_event_count"`
}

type MinidumpInfo struct {
	FileName     string    `json:"file_name"`
	FilePath     string    `json:"file_path"`
	CreatedTime  time.Time `json:"created_time"`
	SizeBytes    int64     `json:"size_bytes"`
	BugcheckCode string    `json:"bugcheck_code,omitempty"`
	CausedBy     string    `json:"caused_by,omitempty"`
}

type EventLogEntry struct {
	LogName     string    `json:"log_name"`
	EventID     int64     `json:"event_id"`
	Source      string    `json:"source"`
	TimeCreated time.Time `json:"time_created"`
	Level       string    `json:"level"` // Critical, Error, Warning
	Message     string    `json:"message"`
}

// NetworkReport contains connectivity and DNS information
type NetworkReport struct {
	Severity        Severity          `json:"severity"`
	Score           int               `json:"score"`
	InternetOK      bool              `json:"internet_ok"`
	DefaultGateway  string            `json:"default_gateway"`
	GatewayPingMs   int64             `json:"gateway_ping_ms"`
	PublicIP        string            `json:"public_ip"`
	DNSServers      []DNSServerResult `json:"dns_servers"`
	ActiveAdapters  []NetworkAdapter  `json:"active_adapters"`
	WinsockOK       bool              `json:"winsock_ok"`
	ProxyConfigured bool              `json:"proxy_configured"`
	ProxyDetails    string            `json:"proxy_details,omitempty"`
}

type DNSServerResult struct {
	Server    string `json:"server"`
	IsDefault bool   `json:"is_default"`
	Reachable bool   `json:"reachable"`
	LatencyMs int64  `json:"latency_ms"`
}

type NetworkAdapter struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	InterfaceType string `json:"interface_type"` // Ethernet, Wi-Fi, VPN
	IPv4Address   string `json:"ipv4_address"`
	SubnetMask    string `json:"subnet_mask"`
	Gateway       string `json:"gateway"`
	MAC           string `json:"mac"`
	Status        string `json:"status"` // Up, Down
	SpeedMbps     int64  `json:"speed_mbps"`
}

// WindowsUpdateItem represents a single Windows Update item
type WindowsUpdateItem struct {
	Title       string `json:"title"`
	KBArticleID string `json:"kb_article_id"`
	Category    string `json:"category"`
	IsHidden    bool   `json:"is_hidden"`
}

// SecurityReport contains antivirus, BitLocker, Firewall and Update status
type SecurityReport struct {
	Severity                   Severity            `json:"severity"`
	Score                      int                 `json:"score"`
	AntivirusName              string              `json:"antivirus_name"`
	AntivirusEnabled           bool                `json:"antivirus_enabled"`
	RealtimeProtection         bool                `json:"realtime_protection"`
	DefinitionsUpToDate        bool                `json:"definitions_up_to_date"`
	BitLockerStatus            string              `json:"bitlocker_status"` // FullyEncrypted, Unencrypted, etc.
	BitLockerProtected         bool                `json:"bitlocker_protected"`
	FirewallEnabled            bool                `json:"firewall_enabled"`
	UACLevel                   string              `json:"uac_level"`
	PendingUpdatesCount        int                 `json:"pending_updates_count"`
	PendingUpdatesList         []string            `json:"pending_updates_list"`
	PendingUpdatesDetails      []WindowsUpdateItem `json:"pending_updates_details"`
	HiddenUpdatesCount         int                 `json:"hidden_updates_count"`
	HiddenUpdatesList          []WindowsUpdateItem `json:"hidden_updates_list"`
	LastUpdateSearchTime       string              `json:"last_update_search_time"`
	LastUpdateInstallTime      string              `json:"last_update_install_time"`
	WindowsUpdateServiceOK     bool                `json:"windows_update_service_ok"`
	WindowsUpdateStatus        string              `json:"windows_update_status"`
	WindowsUpdateOverallStatus string              `json:"windows_update_overall_status"`
	RecentUpdatesInstalled     []string            `json:"recent_updates_installed"`
}

// PerformanceReport contains top consumers and startup programs
type PerformanceReport struct {
	Severity            Severity      `json:"severity"`
	Score               int           `json:"score"`
	TopProcessesByCPU   []ProcessInfo `json:"top_processes_by_cpu"`
	TopProcessesByRAM   []ProcessInfo `json:"top_processes_by_ram"`
	StartupPrograms     []StartupItem `json:"startup_programs"`
	TotalRunningProcess int           `json:"total_running_process"`
	TotalThreadsCount   int           `json:"total_threads_count"`
}

type ProcessInfo struct {
	PID        int     `json:"pid"`
	Name       string  `json:"name"`
	CPUPercent float64 `json:"cpu_percent"`
	RAMMB      float64 `json:"ram_mb"`
	User       string  `json:"user"`
	Path       string  `json:"path"`
}

type StartupItem struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	Location string `json:"location"` // Registry, Startup Folder, TaskScheduler
	Enabled  bool   `json:"enabled"`
	Impact   string `json:"impact"` // High, Medium, Low
}

// IntegrityReport contains system file check, device manager errors, and temp file sizes
type IntegrityReport struct {
	Severity             Severity        `json:"severity"`
	Score                int             `json:"score"`
	DeviceManagerErrors  []DeviceProblem `json:"device_manager_errors"`
	TempFilesSizeBytes   int64           `json:"temp_files_size_bytes"`
	TempFilesSizeDisplay string          `json:"temp_files_size_display"`
	PendingReboot        bool            `json:"pending_reboot"`
	PendingRebootReasons []string        `json:"pending_reboot_reasons"`
	SfcLastScanSummary   string          `json:"sfc_last_scan_summary"`
}

type DeviceProblem struct {
	DeviceName   string `json:"device_name"`
	DeviceID     string `json:"device_id"`
	ProblemCode  int    `json:"problem_code"`
	StatusString string `json:"status_string"`
}

// FixActionResult is the result of running a remediation action
type FixActionResult struct {
	ActionID  string    `json:"action_id"`
	Success   bool      `json:"success"`
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	Output    []string  `json:"output"`
	Timestamp time.Time `json:"timestamp"`
}

// BootLogonReport contains boot and logon performance analysis, GPO metrics and unreachable network resources
type BootLogonReport struct {
	Severity                 Severity               `json:"severity"`
	Score                    int                    `json:"score"`
	LastBootTime             string                 `json:"last_boot_time"`
	TotalBootDurationSeconds float64                `json:"total_boot_duration_seconds"`
	MainPathBootSeconds      float64                `json:"main_path_boot_seconds"` // BIOS/Kernel
	UserLogonWaitSeconds     float64                `json:"user_logon_wait_seconds"`
	PostBootDelaySeconds     float64                `json:"post_boot_delay_seconds"`
	FastStartupEnabled       bool                   `json:"fast_startup_enabled"`
	IsDomainJoined           bool                   `json:"is_domain_joined"`
	DomainName               string                 `json:"domain_name"`
	LogonServer              string                 `json:"logon_server"`
	GPOTotalTimeMs           int                    `json:"gpo_total_time_ms"`
	GPODetails               []GPOExtensionMetric   `json:"gpo_details"`
	UnreachableResources     []UnreachableResource  `json:"unreachable_resources"`
	BootDegradations         []BootDegradationItem  `json:"boot_degradations"`
	StartupApps              []StartupItem          `json:"startup_apps"`
	AdvancedAutoruns         []AdvancedAutorunsItem `json:"advanced_autoruns"`
	BootTrace                BootTraceStatus        `json:"boot_trace"`
	SummaryText              string                 `json:"summary_text"`
}

// GPOExtensionMetric represents the execution metrics of a Group Policy Client Side Extension
type GPOExtensionMetric struct {
	Name         string `json:"name"`
	DurationMs   int    `json:"duration_ms"`
	Status       string `json:"status"` // Success, Timeout, Warning
	ErrorMessage string `json:"error_message,omitempty"`
}

// UnreachableResource represents a network drive, UNC path, or server that hangs during logon
type UnreachableResource struct {
	ResourceType      string `json:"resource_type"` // NetworkDrive, RedirectedFolder, Printer, DomainController, GPOScript
	Name              string `json:"name"`
	TargetUNC         string `json:"target_unc"`
	ServerHost        string `json:"server_host"`
	Port              int    `json:"port"`
	IsReachable       bool   `json:"is_reachable"`
	LatencyMs         int    `json:"latency_ms"`
	ImpactDescription string `json:"impact_description"`
}

// BootDegradationItem represents a specific driver, service or app that delayed the boot
type BootDegradationItem struct {
	Type        string `json:"type"` // Driver, Service, Application, GroupPolicy, Profile
	Name        string `json:"name"`
	DurationMs  int    `json:"duration_ms"`
	Description string `json:"description"`
}

// BootTraceStatus represents the current state of Windows Performance Recorder (WPR) boot recording
type BootTraceStatus struct {
	IsAvailable            bool                 `json:"is_available"`
	IsConfigured           bool                 `json:"is_configured"`
	IsRecording            bool                 `json:"is_recording"`
	CanStop                bool                 `json:"can_stop"`
	HasTraceData           bool                 `json:"has_trace_data"`
	State                  string               `json:"state"`
	ProfileName            string               `json:"profile_name"`
	TraceFilePath          string               `json:"trace_file_path,omitempty"`
	TraceFileSize          string               `json:"trace_file_size,omitempty"`
	TraceRecordedAt        string               `json:"trace_recorded_at,omitempty"`
	StatusMessage          string               `json:"status_message"`
	LastError              string               `json:"last_error,omitempty"`
	IsWPAAvailable         bool                 `json:"is_wpa_available"`
	IsWPAExporterAvailable bool                 `json:"is_wpa_exporter_available"`
	WPAExporterPath        string               `json:"wpa_exporter_path,omitempty"`
	AnalysisSource         string               `json:"analysis_source,omitempty"`
	AnalysisError          string               `json:"analysis_error,omitempty"`
	SlowestDrivers         []BootTimingItem     `json:"slowest_drivers,omitempty"`
	SlowestServices        []BootTimingItem     `json:"slowest_services,omitempty"`
	TopProcesses           []BootTimingItem     `json:"top_processes,omitempty"`
	NetworkFindings        []BootNetworkFinding `json:"network_findings,omitempty"`
}

// BootTimingItem represents a driver, service, or process measured during boot
type BootTimingItem struct {
	Name        string  `json:"name"`
	Category    string  `json:"category"` // Driver, Service, Process
	DurationMs  int     `json:"duration_ms"`
	DurationSec float64 `json:"duration_sec"`
	Path        string  `json:"path,omitempty"`
	Description string  `json:"description"`
	Source      string  `json:"source,omitempty"`
	Count       int     `json:"count,omitempty"`
}

// BootNetworkFinding is evidence of a network, domain, SMB, DNS, or GPO delay
// observed during the measured boot. Source makes it explicit whether the
// evidence came from ETL analysis or from a Windows event log fallback.
type BootNetworkFinding struct {
	Provider    string    `json:"provider"`
	EventID     int64     `json:"event_id"`
	TimeCreated time.Time `json:"time_created"`
	DurationMs  int       `json:"duration_ms"`
	Target      string    `json:"target,omitempty"`
	Message     string    `json:"message"`
	Source      string    `json:"source"`
}

// AdvancedAutorunsItem represents a startup item from 30+ locations (Autoruns style)
type AdvancedAutorunsItem struct {
	Category   string `json:"category"` // Winlogon, BootExecute, ScheduledTask, ShellExtension, Service, Driver, Run
	Name       string `json:"name"`
	Publisher  string `json:"publisher"`
	Path       string `json:"path"`
	Location   string `json:"location"`
	Enabled    bool   `json:"enabled"`
	SignStatus string `json:"sign_status"` // Verified, Unsigned, Unknown
}

// GPOReportResult represents the output of running gpresult /h
type GPOReportResult struct {
	Success      bool   `json:"success"`
	FilePath     string `json:"file_path"`
	SummaryText  string `json:"summary_text"`
	ErrorMessage string `json:"error_message,omitempty"`
}
