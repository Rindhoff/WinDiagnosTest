export namespace models {
	
	export class AdvancedAutorunsItem {
	    category: string;
	    name: string;
	    publisher: string;
	    path: string;
	    location: string;
	    enabled: boolean;
	    sign_status: string;
	
	    static createFrom(source: any = {}) {
	        return new AdvancedAutorunsItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.category = source["category"];
	        this.name = source["name"];
	        this.publisher = source["publisher"];
	        this.path = source["path"];
	        this.location = source["location"];
	        this.enabled = source["enabled"];
	        this.sign_status = source["sign_status"];
	    }
	}
	export class BatteryInfo {
	    present: boolean;
	    charge_percent: number;
	    status: string;
	    health_pct: number;
	    design_capacity: number;
	    full_capacity: number;
	    cycle_count: number;
	
	    static createFrom(source: any = {}) {
	        return new BatteryInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.present = source["present"];
	        this.charge_percent = source["charge_percent"];
	        this.status = source["status"];
	        this.health_pct = source["health_pct"];
	        this.design_capacity = source["design_capacity"];
	        this.full_capacity = source["full_capacity"];
	        this.cycle_count = source["cycle_count"];
	    }
	}
	export class BootDegradationItem {
	    type: string;
	    name: string;
	    duration_ms: number;
	    description: string;
	
	    static createFrom(source: any = {}) {
	        return new BootDegradationItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.name = source["name"];
	        this.duration_ms = source["duration_ms"];
	        this.description = source["description"];
	    }
	}
	export class BootNetworkFinding {
	    provider: string;
	    event_id: number;
	    // Go type: time
	    time_created: any;
	    duration_ms: number;
	    target?: string;
	    message: string;
	    source: string;
	
	    static createFrom(source: any = {}) {
	        return new BootNetworkFinding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.provider = source["provider"];
	        this.event_id = source["event_id"];
	        this.time_created = this.convertValues(source["time_created"], null);
	        this.duration_ms = source["duration_ms"];
	        this.target = source["target"];
	        this.message = source["message"];
	        this.source = source["source"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class BootTimingItem {
	    name: string;
	    category: string;
	    duration_ms: number;
	    duration_sec: number;
	    path?: string;
	    description: string;
	    source?: string;
	    count?: number;
	
	    static createFrom(source: any = {}) {
	        return new BootTimingItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.category = source["category"];
	        this.duration_ms = source["duration_ms"];
	        this.duration_sec = source["duration_sec"];
	        this.path = source["path"];
	        this.description = source["description"];
	        this.source = source["source"];
	        this.count = source["count"];
	    }
	}
	export class BootTraceStatus {
	    is_available: boolean;
	    is_configured: boolean;
	    is_recording: boolean;
	    can_stop: boolean;
	    has_trace_data: boolean;
	    state: string;
	    profile_name: string;
	    trace_file_path?: string;
	    trace_file_size?: string;
	    trace_recorded_at?: string;
	    status_message: string;
	    last_error?: string;
	    is_wpa_available: boolean;
	    is_wpa_exporter_available: boolean;
	    wpa_exporter_path?: string;
	    analysis_source?: string;
	    analysis_error?: string;
	    slowest_drivers?: BootTimingItem[];
	    slowest_services?: BootTimingItem[];
	    top_processes?: BootTimingItem[];
	    network_findings?: BootNetworkFinding[];
	
	    static createFrom(source: any = {}) {
	        return new BootTraceStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.is_available = source["is_available"];
	        this.is_configured = source["is_configured"];
	        this.is_recording = source["is_recording"];
	        this.can_stop = source["can_stop"];
	        this.has_trace_data = source["has_trace_data"];
	        this.state = source["state"];
	        this.profile_name = source["profile_name"];
	        this.trace_file_path = source["trace_file_path"];
	        this.trace_file_size = source["trace_file_size"];
	        this.trace_recorded_at = source["trace_recorded_at"];
	        this.status_message = source["status_message"];
	        this.last_error = source["last_error"];
	        this.is_wpa_available = source["is_wpa_available"];
	        this.is_wpa_exporter_available = source["is_wpa_exporter_available"];
	        this.wpa_exporter_path = source["wpa_exporter_path"];
	        this.analysis_source = source["analysis_source"];
	        this.analysis_error = source["analysis_error"];
	        this.slowest_drivers = this.convertValues(source["slowest_drivers"], BootTimingItem);
	        this.slowest_services = this.convertValues(source["slowest_services"], BootTimingItem);
	        this.top_processes = this.convertValues(source["top_processes"], BootTimingItem);
	        this.network_findings = this.convertValues(source["network_findings"], BootNetworkFinding);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class StartupItem {
	    name: string;
	    command: string;
	    location: string;
	    enabled: boolean;
	    impact: string;
	
	    static createFrom(source: any = {}) {
	        return new StartupItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.command = source["command"];
	        this.location = source["location"];
	        this.enabled = source["enabled"];
	        this.impact = source["impact"];
	    }
	}
	export class UnreachableResource {
	    resource_type: string;
	    name: string;
	    target_unc: string;
	    server_host: string;
	    port: number;
	    is_reachable: boolean;
	    latency_ms: number;
	    impact_description: string;
	
	    static createFrom(source: any = {}) {
	        return new UnreachableResource(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.resource_type = source["resource_type"];
	        this.name = source["name"];
	        this.target_unc = source["target_unc"];
	        this.server_host = source["server_host"];
	        this.port = source["port"];
	        this.is_reachable = source["is_reachable"];
	        this.latency_ms = source["latency_ms"];
	        this.impact_description = source["impact_description"];
	    }
	}
	export class GPOExtensionMetric {
	    name: string;
	    duration_ms: number;
	    status: string;
	    error_message?: string;
	
	    static createFrom(source: any = {}) {
	        return new GPOExtensionMetric(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.duration_ms = source["duration_ms"];
	        this.status = source["status"];
	        this.error_message = source["error_message"];
	    }
	}
	export class BootLogonReport {
	    severity: string;
	    score: number;
	    last_boot_time: string;
	    total_boot_duration_seconds: number;
	    main_path_boot_seconds: number;
	    user_logon_wait_seconds: number;
	    post_boot_delay_seconds: number;
	    fast_startup_enabled: boolean;
	    is_domain_joined: boolean;
	    domain_name: string;
	    logon_server: string;
	    gpo_total_time_ms: number;
	    gpo_details: GPOExtensionMetric[];
	    unreachable_resources: UnreachableResource[];
	    boot_degradations: BootDegradationItem[];
	    startup_apps: StartupItem[];
	    advanced_autoruns: AdvancedAutorunsItem[];
	    boot_trace: BootTraceStatus;
	    summary_text: string;
	
	    static createFrom(source: any = {}) {
	        return new BootLogonReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.severity = source["severity"];
	        this.score = source["score"];
	        this.last_boot_time = source["last_boot_time"];
	        this.total_boot_duration_seconds = source["total_boot_duration_seconds"];
	        this.main_path_boot_seconds = source["main_path_boot_seconds"];
	        this.user_logon_wait_seconds = source["user_logon_wait_seconds"];
	        this.post_boot_delay_seconds = source["post_boot_delay_seconds"];
	        this.fast_startup_enabled = source["fast_startup_enabled"];
	        this.is_domain_joined = source["is_domain_joined"];
	        this.domain_name = source["domain_name"];
	        this.logon_server = source["logon_server"];
	        this.gpo_total_time_ms = source["gpo_total_time_ms"];
	        this.gpo_details = this.convertValues(source["gpo_details"], GPOExtensionMetric);
	        this.unreachable_resources = this.convertValues(source["unreachable_resources"], UnreachableResource);
	        this.boot_degradations = this.convertValues(source["boot_degradations"], BootDegradationItem);
	        this.startup_apps = this.convertValues(source["startup_apps"], StartupItem);
	        this.advanced_autoruns = this.convertValues(source["advanced_autoruns"], AdvancedAutorunsItem);
	        this.boot_trace = this.convertValues(source["boot_trace"], BootTraceStatus);
	        this.summary_text = source["summary_text"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	export class CheckPointAdapter {
	    name: string;
	    description: string;
	    status: string;
	    ip_addresses: string[];
	    mac_address: string;
	    mtu: number;
	    is_healthy: boolean;
	
	    static createFrom(source: any = {}) {
	        return new CheckPointAdapter(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	        this.status = source["status"];
	        this.ip_addresses = source["ip_addresses"];
	        this.mac_address = source["mac_address"];
	        this.mtu = source["mtu"];
	        this.is_healthy = source["is_healthy"];
	    }
	}
	export class GatewayTestResult {
	    gateway: string;
	    port: number;
	    reachable: boolean;
	    latency_ms: number;
	    error_message?: string;
	
	    static createFrom(source: any = {}) {
	        return new GatewayTestResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.gateway = source["gateway"];
	        this.port = source["port"];
	        this.reachable = source["reachable"];
	        this.latency_ms = source["latency_ms"];
	        this.error_message = source["error_message"];
	    }
	}
	export class CheckPointService {
	    name: string;
	    display_name: string;
	    status: string;
	    start_type: string;
	    binary_path: string;
	    is_healthy: boolean;
	
	    static createFrom(source: any = {}) {
	        return new CheckPointService(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.display_name = source["display_name"];
	        this.status = source["status"];
	        this.start_type = source["start_type"];
	        this.binary_path = source["binary_path"];
	        this.is_healthy = source["is_healthy"];
	    }
	}
	export class CheckPointReport {
	    detected: boolean;
	    client_version: string;
	    install_path: string;
	    severity: string;
	    score: number;
	    services: CheckPointService[];
	    virtual_adapters: CheckPointAdapter[];
	    active_routes: string[];
	    recent_log_errors: string[];
	    log_files_found: string[];
	    gateway_connectivity: GatewayTestResult[];
	    configuration_found: boolean;
	    config_details: Record<string, string>;
	    diagnostic_notes: string[];
	    recommended_action: string;
	
	    static createFrom(source: any = {}) {
	        return new CheckPointReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.detected = source["detected"];
	        this.client_version = source["client_version"];
	        this.install_path = source["install_path"];
	        this.severity = source["severity"];
	        this.score = source["score"];
	        this.services = this.convertValues(source["services"], CheckPointService);
	        this.virtual_adapters = this.convertValues(source["virtual_adapters"], CheckPointAdapter);
	        this.active_routes = source["active_routes"];
	        this.recent_log_errors = source["recent_log_errors"];
	        this.log_files_found = source["log_files_found"];
	        this.gateway_connectivity = this.convertValues(source["gateway_connectivity"], GatewayTestResult);
	        this.configuration_found = source["configuration_found"];
	        this.config_details = source["config_details"];
	        this.diagnostic_notes = source["diagnostic_notes"];
	        this.recommended_action = source["recommended_action"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class DNSServerResult {
	    server: string;
	    is_default: boolean;
	    reachable: boolean;
	    latency_ms: number;
	
	    static createFrom(source: any = {}) {
	        return new DNSServerResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.server = source["server"];
	        this.is_default = source["is_default"];
	        this.reachable = source["reachable"];
	        this.latency_ms = source["latency_ms"];
	    }
	}
	export class DeviceProblem {
	    device_name: string;
	    device_id: string;
	    problem_code: number;
	    status_string: string;
	
	    static createFrom(source: any = {}) {
	        return new DeviceProblem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.device_name = source["device_name"];
	        this.device_id = source["device_id"];
	        this.problem_code = source["problem_code"];
	        this.status_string = source["status_string"];
	    }
	}
	export class DiskInfo {
	    device_id: string;
	    model: string;
	    media_type: string;
	    drive_letter: string;
	    file_system: string;
	    total_gb: number;
	    free_gb: number;
	    used_gb: number;
	    usage_pct: number;
	    smart_status: string;
	    smart_healthy: boolean;
	    is_system_drive: boolean;
	
	    static createFrom(source: any = {}) {
	        return new DiskInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.device_id = source["device_id"];
	        this.model = source["model"];
	        this.media_type = source["media_type"];
	        this.drive_letter = source["drive_letter"];
	        this.file_system = source["file_system"];
	        this.total_gb = source["total_gb"];
	        this.free_gb = source["free_gb"];
	        this.used_gb = source["used_gb"];
	        this.usage_pct = source["usage_pct"];
	        this.smart_status = source["smart_status"];
	        this.smart_healthy = source["smart_healthy"];
	        this.is_system_drive = source["is_system_drive"];
	    }
	}
	export class EventLogEntry {
	    log_name: string;
	    event_id: number;
	    source: string;
	    // Go type: time
	    time_created: any;
	    level: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new EventLogEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.log_name = source["log_name"];
	        this.event_id = source["event_id"];
	        this.source = source["source"];
	        this.time_created = this.convertValues(source["time_created"], null);
	        this.level = source["level"];
	        this.message = source["message"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class MinidumpInfo {
	    file_name: string;
	    file_path: string;
	    // Go type: time
	    created_time: any;
	    size_bytes: number;
	    bugcheck_code?: string;
	    caused_by?: string;
	
	    static createFrom(source: any = {}) {
	        return new MinidumpInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.file_name = source["file_name"];
	        this.file_path = source["file_path"];
	        this.created_time = this.convertValues(source["created_time"], null);
	        this.size_bytes = source["size_bytes"];
	        this.bugcheck_code = source["bugcheck_code"];
	        this.caused_by = source["caused_by"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class EventLogsReport {
	    severity: string;
	    score: number;
	    bsod_crash_dumps: MinidumpInfo[];
	    recent_system_errors: EventLogEntry[];
	    recent_app_crashes: EventLogEntry[];
	    critical_event_count: number;
	    error_event_count: number;
	
	    static createFrom(source: any = {}) {
	        return new EventLogsReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.severity = source["severity"];
	        this.score = source["score"];
	        this.bsod_crash_dumps = this.convertValues(source["bsod_crash_dumps"], MinidumpInfo);
	        this.recent_system_errors = this.convertValues(source["recent_system_errors"], EventLogEntry);
	        this.recent_app_crashes = this.convertValues(source["recent_app_crashes"], EventLogEntry);
	        this.critical_event_count = source["critical_event_count"];
	        this.error_event_count = source["error_event_count"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class FixActionResult {
	    action_id: string;
	    success: boolean;
	    title: string;
	    message: string;
	    output: string[];
	    // Go type: time
	    timestamp: any;
	
	    static createFrom(source: any = {}) {
	        return new FixActionResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.action_id = source["action_id"];
	        this.success = source["success"];
	        this.title = source["title"];
	        this.message = source["message"];
	        this.output = source["output"];
	        this.timestamp = this.convertValues(source["timestamp"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class GPOReportResult {
	    success: boolean;
	    file_path: string;
	    summary_text: string;
	    error_message?: string;
	
	    static createFrom(source: any = {}) {
	        return new GPOReportResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.file_path = source["file_path"];
	        this.summary_text = source["summary_text"];
	        this.error_message = source["error_message"];
	    }
	}
	
	export class HardwareReport {
	    severity: string;
	    score: number;
	    cpu_model: string;
	    cpu_cores: number;
	    cpu_usage_pct: number;
	    total_ram_gb: number;
	    used_ram_gb: number;
	    free_ram_gb: number;
	    ram_usage_pct: number;
	    disks: DiskInfo[];
	    battery?: BatteryInfo;
	    motherboard: string;
	    bios_version: string;
	
	    static createFrom(source: any = {}) {
	        return new HardwareReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.severity = source["severity"];
	        this.score = source["score"];
	        this.cpu_model = source["cpu_model"];
	        this.cpu_cores = source["cpu_cores"];
	        this.cpu_usage_pct = source["cpu_usage_pct"];
	        this.total_ram_gb = source["total_ram_gb"];
	        this.used_ram_gb = source["used_ram_gb"];
	        this.free_ram_gb = source["free_ram_gb"];
	        this.ram_usage_pct = source["ram_usage_pct"];
	        this.disks = this.convertValues(source["disks"], DiskInfo);
	        this.battery = this.convertValues(source["battery"], BatteryInfo);
	        this.motherboard = source["motherboard"];
	        this.bios_version = source["bios_version"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class IntegrityReport {
	    severity: string;
	    score: number;
	    device_manager_errors: DeviceProblem[];
	    temp_files_size_bytes: number;
	    temp_files_size_display: string;
	    pending_reboot: boolean;
	    pending_reboot_reasons: string[];
	    sfc_last_scan_summary: string;
	
	    static createFrom(source: any = {}) {
	        return new IntegrityReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.severity = source["severity"];
	        this.score = source["score"];
	        this.device_manager_errors = this.convertValues(source["device_manager_errors"], DeviceProblem);
	        this.temp_files_size_bytes = source["temp_files_size_bytes"];
	        this.temp_files_size_display = source["temp_files_size_display"];
	        this.pending_reboot = source["pending_reboot"];
	        this.pending_reboot_reasons = source["pending_reboot_reasons"];
	        this.sfc_last_scan_summary = source["sfc_last_scan_summary"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ProcessInfo {
	    pid: number;
	    name: string;
	    cpu_percent: number;
	    ram_mb: number;
	    user: string;
	    path: string;
	
	    static createFrom(source: any = {}) {
	        return new ProcessInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pid = source["pid"];
	        this.name = source["name"];
	        this.cpu_percent = source["cpu_percent"];
	        this.ram_mb = source["ram_mb"];
	        this.user = source["user"];
	        this.path = source["path"];
	    }
	}
	export class PerformanceReport {
	    severity: string;
	    score: number;
	    top_processes_by_cpu: ProcessInfo[];
	    top_processes_by_ram: ProcessInfo[];
	    startup_programs: StartupItem[];
	    total_running_process: number;
	    total_threads_count: number;
	
	    static createFrom(source: any = {}) {
	        return new PerformanceReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.severity = source["severity"];
	        this.score = source["score"];
	        this.top_processes_by_cpu = this.convertValues(source["top_processes_by_cpu"], ProcessInfo);
	        this.top_processes_by_ram = this.convertValues(source["top_processes_by_ram"], ProcessInfo);
	        this.startup_programs = this.convertValues(source["startup_programs"], StartupItem);
	        this.total_running_process = source["total_running_process"];
	        this.total_threads_count = source["total_threads_count"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class WindowsUpdateItem {
	    title: string;
	    kb_article_id: string;
	    category: string;
	    is_hidden: boolean;
	
	    static createFrom(source: any = {}) {
	        return new WindowsUpdateItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.title = source["title"];
	        this.kb_article_id = source["kb_article_id"];
	        this.category = source["category"];
	        this.is_hidden = source["is_hidden"];
	    }
	}
	export class SecurityReport {
	    severity: string;
	    score: number;
	    antivirus_name: string;
	    antivirus_enabled: boolean;
	    realtime_protection: boolean;
	    definitions_up_to_date: boolean;
	    bitlocker_status: string;
	    bitlocker_protected: boolean;
	    firewall_enabled: boolean;
	    uac_level: string;
	    pending_updates_count: number;
	    pending_updates_list: string[];
	    pending_updates_details: WindowsUpdateItem[];
	    hidden_updates_count: number;
	    hidden_updates_list: WindowsUpdateItem[];
	    last_update_search_time: string;
	    last_update_install_time: string;
	    windows_update_service_ok: boolean;
	    windows_update_status: string;
	    windows_update_overall_status: string;
	    recent_updates_installed: string[];
	
	    static createFrom(source: any = {}) {
	        return new SecurityReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.severity = source["severity"];
	        this.score = source["score"];
	        this.antivirus_name = source["antivirus_name"];
	        this.antivirus_enabled = source["antivirus_enabled"];
	        this.realtime_protection = source["realtime_protection"];
	        this.definitions_up_to_date = source["definitions_up_to_date"];
	        this.bitlocker_status = source["bitlocker_status"];
	        this.bitlocker_protected = source["bitlocker_protected"];
	        this.firewall_enabled = source["firewall_enabled"];
	        this.uac_level = source["uac_level"];
	        this.pending_updates_count = source["pending_updates_count"];
	        this.pending_updates_list = source["pending_updates_list"];
	        this.pending_updates_details = this.convertValues(source["pending_updates_details"], WindowsUpdateItem);
	        this.hidden_updates_count = source["hidden_updates_count"];
	        this.hidden_updates_list = this.convertValues(source["hidden_updates_list"], WindowsUpdateItem);
	        this.last_update_search_time = source["last_update_search_time"];
	        this.last_update_install_time = source["last_update_install_time"];
	        this.windows_update_service_ok = source["windows_update_service_ok"];
	        this.windows_update_status = source["windows_update_status"];
	        this.windows_update_overall_status = source["windows_update_overall_status"];
	        this.recent_updates_installed = source["recent_updates_installed"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class NetworkAdapter {
	    name: string;
	    description: string;
	    interface_type: string;
	    ipv4_address: string;
	    subnet_mask: string;
	    gateway: string;
	    mac: string;
	    status: string;
	    speed_mbps: number;
	
	    static createFrom(source: any = {}) {
	        return new NetworkAdapter(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	        this.interface_type = source["interface_type"];
	        this.ipv4_address = source["ipv4_address"];
	        this.subnet_mask = source["subnet_mask"];
	        this.gateway = source["gateway"];
	        this.mac = source["mac"];
	        this.status = source["status"];
	        this.speed_mbps = source["speed_mbps"];
	    }
	}
	export class NetworkReport {
	    severity: string;
	    score: number;
	    internet_ok: boolean;
	    default_gateway: string;
	    gateway_ping_ms: number;
	    public_ip: string;
	    dns_servers: DNSServerResult[];
	    active_adapters: NetworkAdapter[];
	    winsock_ok: boolean;
	    proxy_configured: boolean;
	    proxy_details?: string;
	
	    static createFrom(source: any = {}) {
	        return new NetworkReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.severity = source["severity"];
	        this.score = source["score"];
	        this.internet_ok = source["internet_ok"];
	        this.default_gateway = source["default_gateway"];
	        this.gateway_ping_ms = source["gateway_ping_ms"];
	        this.public_ip = source["public_ip"];
	        this.dns_servers = this.convertValues(source["dns_servers"], DNSServerResult);
	        this.active_adapters = this.convertValues(source["active_adapters"], NetworkAdapter);
	        this.winsock_ok = source["winsock_ok"];
	        this.proxy_configured = source["proxy_configured"];
	        this.proxy_details = source["proxy_details"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class IssueSummary {
	    category: string;
	    title: string;
	    description: string;
	    severity: string;
	    fix_action_id?: string;
	
	    static createFrom(source: any = {}) {
	        return new IssueSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.category = source["category"];
	        this.title = source["title"];
	        this.description = source["description"];
	        this.severity = source["severity"];
	        this.fix_action_id = source["fix_action_id"];
	    }
	}
	export class HealthReport {
	    // Go type: time
	    timestamp: any;
	    computer_name: string;
	    os_version: string;
	    os_build: string;
	    architecture: string;
	    uptime: string;
	    total_score: number;
	    score_rating: string;
	    summary_badges: Record<string, number>;
	    top_issues: IssueSummary[];
	    checkpoint_vpn: CheckPointReport;
	    hardware: HardwareReport;
	    event_logs: EventLogsReport;
	    network: NetworkReport;
	    security: SecurityReport;
	    performance: PerformanceReport;
	    integrity: IntegrityReport;
	    boot_logon: BootLogonReport;
	    quick_fix_status: Record<string, boolean>;
	
	    static createFrom(source: any = {}) {
	        return new HealthReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = this.convertValues(source["timestamp"], null);
	        this.computer_name = source["computer_name"];
	        this.os_version = source["os_version"];
	        this.os_build = source["os_build"];
	        this.architecture = source["architecture"];
	        this.uptime = source["uptime"];
	        this.total_score = source["total_score"];
	        this.score_rating = source["score_rating"];
	        this.summary_badges = source["summary_badges"];
	        this.top_issues = this.convertValues(source["top_issues"], IssueSummary);
	        this.checkpoint_vpn = this.convertValues(source["checkpoint_vpn"], CheckPointReport);
	        this.hardware = this.convertValues(source["hardware"], HardwareReport);
	        this.event_logs = this.convertValues(source["event_logs"], EventLogsReport);
	        this.network = this.convertValues(source["network"], NetworkReport);
	        this.security = this.convertValues(source["security"], SecurityReport);
	        this.performance = this.convertValues(source["performance"], PerformanceReport);
	        this.integrity = this.convertValues(source["integrity"], IntegrityReport);
	        this.boot_logon = this.convertValues(source["boot_logon"], BootLogonReport);
	        this.quick_fix_status = source["quick_fix_status"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	
	
	
	
	
	
	

}

