import './style.css';
import { 
  GetHealthReport, 
  ExecuteQuickFix, 
  ExportAndOpenHTMLReport, 
  ExportJSONReport, 
  ToggleWindowsUpdateHidden, 
  ToggleStartupApp,
  StartWPRBootTraceWithReboot,
  CancelPendingReboot,
  ClearTraceData,
  CancelWPRBootTrace,
  StopWPRBootTrace,
  OpenTraceFolder,
  OpenTraceInWPA,
  GenerateAndOpenGPOReport
} from '../wailsjs/go/main/App';
import { models } from '../wailsjs/go/models';

// State
let isScanning = false;

const app = document.querySelector<HTMLDivElement>('#app')!;

// Initial HTML Layout
app.innerHTML = `
<div class="app-container">
  <!-- Header -->
  <header class="app-header">
    <div class="brand">
      <div class="brand-icon">🩺</div>
      <div class="brand-info">
        <h1>WinHealth Diagnostic Hub</h1>
        <p>Windows Felsökning & Hälsorapport</p>
      </div>
    </div>

    <div class="system-pill" id="system-pill">
      <div class="system-pill-item">
        <span>Dator:</span>
        <strong id="header-hostname">Läser in...</strong>
      </div>
      <div class="system-pill-item">
        <span>OS:</span>
        <strong id="header-os">Windows</strong>
      </div>
      <div class="system-pill-item">
        <span>Uptime:</span>
        <strong id="header-uptime">-</strong>
      </div>
    </div>

    <div class="header-actions">
      <button class="btn btn-primary" id="btn-scan">
        <span id="scan-icon">🔄</span>
        <span id="scan-label">Skanna datorn</span>
      </button>
      <button class="btn btn-secondary" id="btn-export-html" title="Öppna och spara HTML-rapport">
        📄 Exportera HTML
      </button>
      <button class="btn btn-secondary" id="btn-export-json" title="Spara strukturerad JSON-rapport">
        💾 JSON
      </button>
    </div>
  </header>

  <!-- Main Body -->
  <div class="app-body">
    <!-- Sidebar -->
    <aside class="sidebar">
      <div class="nav-item active" data-tab="tab-overview">
        <span class="nav-icon">📊</span>
        <span>Översikt</span>
        <span class="nav-badge" id="nav-overview-badge" style="display:none;"></span>
      </div>
      <div class="nav-item" data-tab="tab-checkpoint">
        <span class="nav-icon">🔒</span>
        <span>Check Point VPN</span>
        <span class="nav-badge" id="nav-vpn-badge" style="display:none;"></span>
      </div>
      <div class="nav-item" data-tab="tab-hardware">
        <span class="nav-icon">💾</span>
        <span>Hårdvara & SMART</span>
      </div>
      <div class="nav-item" data-tab="tab-network">
        <span class="nav-icon">🌐</span>
        <span>Nätverk & DNS</span>
      </div>
      <div class="nav-item" data-tab="tab-security">
        <span class="nav-icon">🛡️</span>
        <span>Säkerhet & Update</span>
      </div>
      <div class="nav-item" data-tab="tab-crashes">
        <span class="nav-icon">⚠️</span>
        <span>Krascher & Loggar</span>
        <span class="nav-badge" id="nav-crashes-badge" style="display:none;"></span>
      </div>
      <div class="nav-item" data-tab="tab-performance">
        <span class="nav-icon">⚡</span>
        <span>Prestanda & Resurser</span>
      </div>
      <div class="nav-item" data-tab="tab-boot">
        <span class="nav-icon">⏱️</span>
        <span>Uppstart & GPO</span>
        <span class="nav-badge" id="nav-boot-badge" style="display:none;">!</span>
      </div>
      <div class="nav-item" data-tab="tab-fixes">
        <span class="nav-icon">🛠️</span>
        <span>Snabbåtgärder</span>
      </div>
    </aside>

    <!-- Content Area -->
    <main class="content-area">
      <!-- 1. Overview Tab -->
      <section id="tab-overview" class="tab-content active">
        <!-- Hero Health Score -->
        <div class="score-hero">
          <div class="score-gauge-container">
            <svg class="score-gauge-svg" viewBox="0 0 100 100">
              <circle class="score-gauge-bg" cx="50" cy="50" r="42"></circle>
              <circle class="score-gauge-bar" id="score-gauge-bar" cx="50" cy="50" r="42" stroke-dasharray="264" stroke-dashoffset="264" stroke="#10b981"></circle>
            </svg>
            <div class="score-gauge-text">
              <div class="score-number" id="score-number">--</div>
              <div class="score-label">Poäng</div>
            </div>
          </div>
          <div class="score-hero-details">
            <div class="score-hero-title">
              <span id="score-status-text">Systemanalys pågår</span>
              <span class="badge badge-info" id="score-badge">Läser av...</span>
            </div>
            <p class="score-hero-desc" id="score-description">
              Samlar in loggar, hårdvarustatus och kontrollerar systemintegritet...
            </p>
            <div class="score-stat-pills">
              <div class="stat-pill-badge">
                <span>Check Point VPN</span>
                <strong id="pill-vpn-status">-</strong>
              </div>
              <div class="stat-pill-badge">
                <span>Lagring & SMART</span>
                <strong id="pill-disk-status">-</strong>
              </div>
              <div class="stat-pill-badge">
                <span>Kraschar & Minidumps</span>
                <strong id="pill-crash-status">-</strong>
              </div>
              <div class="stat-pill-badge">
                <span>Nätverk</span>
                <strong id="pill-net-status">-</strong>
              </div>
            </div>
          </div>
        </div>

        <!-- Top Issues -->
        <div class="section-title">
          <span>⚠️ Upptäckta Avvikelser & Rekommendationer</span>
          <span class="badge badge-info" id="issues-count-badge">0 punkter</span>
        </div>
        <div id="top-issues-container">
          <div class="card" style="text-align:center; padding: 24px; color: var(--text-secondary);">
            Inga problem har identifierats än. Kör en skanning för att starta.
          </div>
        </div>
      </section>

      <!-- 2. Check Point VPN Tab -->
      <section id="tab-checkpoint" class="tab-content">
        <div class="section-title">
          <span>🔒 Check Point Endpoint Security / VPN Diagnostik</span>
          <button class="btn btn-fix btn-sm" id="btn-fix-vpn-direct">🔄 Återställ & Starta om VPN</button>
        </div>

        <div class="grid-2">
          <!-- Client & Version Details -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">Klientstatus & Konfiguration</div>
              <span class="badge badge-ok" id="cp-detected-badge">Detekterad</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Klientversion:</span>
              <span class="stat-val" id="cp-client-version">-</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Installationssökväg:</span>
              <span class="stat-val" id="cp-install-path" style="font-size:11px;">-</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Konfigurationsfil:</span>
              <span class="stat-val" id="cp-config-found">-</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Rekommendation:</span>
              <span class="stat-val" id="cp-recom-action">-</span>
            </div>
          </div>

          <!-- Gateway & Connection Status -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">VPN-Gateway Anslutningstest</div>
              <span class="badge badge-info">Port 443</span>
            </div>
            <div id="cp-gateways-container">
              <div class="stat-row"><span class="stat-label">Inga gateways konfigurerade.</span></div>
            </div>
          </div>
        </div>

        <!-- Services Table -->
        <div class="card" style="margin-bottom: 20px;">
          <div class="card-header">
            <div class="card-title">Check Point Bakgrundstjänster (Win32 Services)</div>
          </div>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Tjänstenamn</th>
                  <th>Visningsnamn</th>
                  <th>Status</th>
                  <th>Starttyp</th>
                  <th>Hälsa</th>
                </tr>
              </thead>
              <tbody id="cp-services-tbody">
                <tr><td colspan="5" style="text-align:center;">Inga tjänster hittades.</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Virtual Adapters -->
        <div class="card" style="margin-bottom: 20px;">
          <div class="card-header">
            <div class="card-title">Check Point Virtual Network Adapters</div>
          </div>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Kortnamn</th>
                  <th>Beskrivning</th>
                  <th>Status</th>
                  <th>MAC-adress</th>
                </tr>
              </thead>
              <tbody id="cp-adapters-tbody">
                <tr><td colspan="4" style="text-align:center;">Inga virtuella nätverkskort hittades.</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Recent Log Errors -->
        <div class="log-viewer-container">
          <div class="log-viewer-header">
            <div class="log-viewer-title">📝 Senaste Check Point Fel i Klientloggar (trac.log / trac_srv.log)</div>
            <button class="btn btn-secondary btn-sm" id="btn-copy-vpn-logs">📋 Kopiera loggar</button>
          </div>
          <div class="log-viewer-body" id="cp-log-viewer">Inga loggfel registrerade.</div>
        </div>
      </section>

      <!-- 3. Hardware Tab -->
      <section id="tab-hardware" class="tab-content">
        <div class="section-title">💾 Hårdvara, Minne & SMART Diskstatus</div>
        
        <div class="grid-2">
          <!-- CPU & RAM -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">Processor & Primärminne</div>
            </div>
            <div class="stat-row">
              <span class="stat-label">Processor:</span>
              <span class="stat-val" id="hw-cpu-model">-</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Kärnor:</span>
              <span class="stat-val" id="hw-cpu-cores">-</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Moderkort:</span>
              <span class="stat-val" id="hw-motherboard">-</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">BIOS-version:</span>
              <span class="stat-val" id="hw-bios">-</span>
            </div>
            
            <div class="progress-container" style="margin-top: 14px;">
              <div class="progress-header">
                <span>RAM-användning</span>
                <span id="hw-ram-text">- / - GB (-%)</span>
              </div>
              <div class="progress-track">
                <div class="progress-fill" id="hw-ram-bar" style="width: 0%;"></div>
              </div>
            </div>
          </div>

          <!-- Battery (if laptop) -->
          <div class="card" id="hw-battery-card">
            <div class="card-header">
              <div class="card-title">Batterihälsa (Bärbar dator)</div>
              <span class="badge badge-ok" id="hw-battery-badge">Normal</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Laddningsnivå:</span>
              <span class="stat-val" id="hw-battery-charge">-</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Status:</span>
              <span class="stat-val" id="hw-battery-status">-</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Batterihälsa (Kapacitet):</span>
              <span class="stat-val" id="hw-battery-health">-</span>
            </div>
          </div>
        </div>

        <!-- Disks -->
        <div class="section-title">Lagringsenheter & SMART Prediktion</div>
        <div id="hw-disks-container" class="grid-2">
          <!-- Populated dynamically -->
        </div>
      </section>

      <!-- 4. Network Tab -->
      <section id="tab-network" class="tab-content">
        <div class="section-title">
          <span>🌐 Nätverk, DNS & Konnektivitet</span>
          <button class="btn btn-fix btn-sm" id="btn-fix-dns-direct">🌐 Återställ DNS & Winsock</button>
        </div>

        <div class="grid-2">
          <div class="card">
            <div class="card-header">
              <div class="card-title">Internet & Standardgateway</div>
              <span class="badge badge-ok" id="net-internet-badge">Online</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Internetanslutning:</span>
              <span class="stat-val" id="net-internet-val">OK</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Standardgateway:</span>
              <span class="stat-val" id="net-gateway-val">-</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Gateway Ping-latens:</span>
              <span class="stat-val" id="net-gateway-ping">- ms</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Proxykonfiguration:</span>
              <span class="stat-val" id="net-proxy-val">Ingen</span>
            </div>
          </div>

          <!-- DNS Latencies -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">DNS-svarstider & Benchmark</div>
            </div>
            <div id="net-dns-container">
              <!-- Populated dynamically -->
            </div>
          </div>
        </div>

        <!-- Network Adapters -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">Aktiva Nätverkskort (IP & MAC)</div>
          </div>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Typ</th>
                  <th>Kortnamn</th>
                  <th>IPv4-adress</th>
                  <th>Standardgateway</th>
                  <th>MAC-adress</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody id="net-adapters-tbody">
                <!-- Populated dynamically -->
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- 5. Security Tab -->
      <section id="tab-security" class="tab-content">
        <div class="section-title">🛡️ Säkerhet, Kryptering & Windows Update</div>

        <div class="grid-2">
          <!-- Antivirus & Defender -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">Antivirus & Realtidsskydd</div>
              <span class="badge badge-ok" id="sec-av-badge">Aktivt</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Antivirusprogram:</span>
              <span class="stat-val" id="sec-av-name">Windows Defender</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Realtidsskydd:</span>
              <span class="stat-val" id="sec-realtime-val">Aktiverat</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Signaturer / Definitioner:</span>
              <span class="stat-val" id="sec-sig-val">Uppdaterade</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Windows Brandvägg:</span>
              <span class="stat-val" id="sec-firewall-val">Aktiv</span>
            </div>
          </div>

          <!-- BitLocker & Updates -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">BitLocker & Windows Update</div>
              <button class="btn btn-fix btn-sm" id="btn-fix-wu-direct">🔄 Återställ Update</button>
            </div>
            <div class="stat-row">
              <span class="stat-label">BitLocker (C:):</span>
              <span class="stat-val" id="sec-bitlocker-val">-</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Uppdateringsstatus:</span>
              <span class="stat-val" id="sec-wu-overall-val">Läser in...</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Senast uppdaterad:</span>
              <span class="stat-val" id="sec-last-install-val">-</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Senaste uppdateringssökning:</span>
              <span class="stat-val" id="sec-last-search-val">-</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Väntande installationer:</span>
              <span class="stat-val" id="sec-pending-count-val">0 st</span>
            </div>
            <div class="stat-row">
              <span class="stat-label">Väntande omstart:</span>
              <span class="stat-val" id="sec-reboot-val">Nej</span>
            </div>
          </div>
        </div>

        <!-- Pending Updates Waiting for Installation -->
        <div class="card" id="sec-pending-updates-card" style="margin-top: 18px;">
          <div class="card-header">
            <div class="card-title">⏳ Uppdateringar som väntar på installation</div>
            <span class="badge badge-warning" id="sec-pending-badge">0 väntar</span>
          </div>
          <div id="sec-pending-updates-list">
            <div style="padding:8px 0; color:var(--text-secondary);">Inga uppdateringar väntar just nu.</div>
          </div>
        </div>

        <!-- Hidden / Blocked Updates -->
        <div class="card" id="sec-hidden-updates-card" style="margin-top: 18px;">
          <div class="card-header">
            <div class="card-title">🚫 Blockerade / Dolda uppdateringar (Installeras ej)</div>
            <span class="badge badge-info" id="sec-hidden-badge">0 blockerade</span>
          </div>
          <div id="sec-hidden-updates-list">
            <div style="padding:8px 0; color:var(--text-secondary);">Inga uppdateringar är blockerade. Alla godkända installeras normalt.</div>
          </div>
        </div>

        <!-- Recent Updates History -->
        <div class="card" style="margin-top: 18px;">
          <div class="card-header">
            <div class="card-title">✅ Senast installerade Windows-uppdateringar</div>
          </div>
          <div id="sec-recent-updates-list">
            <div style="padding:8px 0; color:var(--text-secondary);">Läser in uppdateringshistorik...</div>
          </div>
        </div>
      </section>

      <!-- 6. Crashes & Logs Tab -->
      <section id="tab-crashes" class="tab-content">
        <div class="section-title">
          <span>⚠️ BSOD Minidumps & Kritiska Windows-fel</span>
          <button class="btn btn-fix btn-sm" id="btn-fix-sfc-direct">🛠️ Kör SFC Systemreparation</button>
        </div>

        <!-- Minidump Card -->
        <div class="card" style="margin-bottom: 20px;">
          <div class="card-header">
            <div class="card-title">Blåskärm / BSOD Kraschdumpar (C:\\Windows\\Minidump)</div>
            <span class="badge badge-ok" id="crash-dumps-count-badge">0 st</span>
          </div>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Filnamn</th>
                  <th>Kraschdatum</th>
                  <th>Filstorlek</th>
                  <th>Sökväg</th>
                </tr>
              </thead>
              <tbody id="crash-dumps-tbody">
                <tr><td colspan="4" style="text-align:center;">Inga kraschdumpar hittades i Minidump-katalogen.</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Event Viewer Filter & Table -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">Kritiska System- & Applikationsfel (Senaste 48h)</div>
            <input type="text" id="event-search-input" class="search-input" placeholder="🔍 Filtrera fel & EventID...">
          </div>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Logg</th>
                  <th>Event ID</th>
                  <th>Källa</th>
                  <th>Tidpunkt</th>
                  <th>Nivå</th>
                  <th>Felbeskrivning</th>
                </tr>
              </thead>
              <tbody id="event-logs-tbody">
                <!-- Populated dynamically -->
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- 7. Performance Tab -->
      <section id="tab-performance" class="tab-content">
        <div class="section-title">⚡ Prestanda, Processer & Autostart</div>

        <div class="grid-2">
          <!-- Top RAM -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">Mest minneskrävande processer</div>
            </div>
            <div class="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>PID</th>
                    <th>Process</th>
                    <th>RAM (MB)</th>
                  </tr>
                </thead>
                <tbody id="perf-ram-tbody">
                  <!-- Populated dynamically -->
                </tbody>
              </table>
            </div>
          </div>

          <!-- Top CPU -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">Mest processorintensiva processer</div>
            </div>
            <div class="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>PID</th>
                    <th>Process</th>
                    <th>CPU (s)</th>
                  </tr>
                </thead>
                <tbody id="perf-cpu-tbody">
                  <!-- Populated dynamically -->
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- Startup Programs -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">Autostartande program & aktiviteter</div>
          </div>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Namn</th>
                  <th>Plats</th>
                  <th>Kommando / Sökväg</th>
                </tr>
              </thead>
              <tbody id="perf-startup-tbody">
                <!-- Populated dynamically -->
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- 8. Boot & Logon Tab -->
      <section id="tab-boot" class="tab-content">
        <div class="section-title">⏱️ Uppstarts- & Inloggningsanalys (GPO, Nätverk & Tidstjuvar)</div>

        <!-- Hero Boot Overview -->
        <div class="card" style="margin-bottom: 20px;">
          <div class="card-header">
            <div class="card-title">Uppstartsprestanda</div>
            <span class="badge badge-ok" id="boot-status-badge">Snabb start</span>
          </div>
          <div class="grid-4" style="margin-top: 10px; margin-bottom: 16px;">
            <div class="stat-box">
              <span class="stat-box-num" id="boot-total-sec">-</span>
              <span class="stat-box-label">Total uppstartstid</span>
            </div>
            <div class="stat-box">
              <span class="stat-box-num" id="boot-mainpath-sec">-</span>
              <span class="stat-box-label">BIOS & Windows Kärna</span>
            </div>
            <div class="stat-box">
              <span class="stat-box-num" id="boot-logon-sec">-</span>
              <span class="stat-box-label">Inloggning & Profil</span>
            </div>
            <div class="stat-box">
              <span class="stat-box-num" id="boot-postboot-sec">-</span>
              <span class="stat-box-label">Post-Boot / Autostartfas</span>
            </div>
          </div>
          <div class="stat-row">
            <span class="stat-label">Windows Snabbstart (Fast Startup):</span>
            <span class="stat-val" id="boot-faststartup-val">Aktiverad</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Senaste uppstart:</span>
            <span class="stat-val" id="boot-last-time-val">-</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Sammanfattning:</span>
            <span class="stat-val" id="boot-summary-val" style="color:var(--text-secondary);">-</span>
          </div>
        </div>

        <!-- Enterprise / Domain & Unreachable Network Resources -->
        <div class="card" style="margin-bottom: 20px;">
          <div class="card-header">
            <div class="card-title">🏢 Företagsresurser & GPO-analys vid inloggning</div>
            <div style="display:flex; gap:8px; align-items:center;">
              <span class="badge badge-info" id="boot-domain-badge">Arbetsgrupp</span>
              <button class="btn btn-secondary btn-sm" id="btn-generate-gpo" style="display:flex; align-items:center; gap:6px;">
                <span>📄 Generera GPO-rapport</span>
              </button>
            </div>
          </div>
          <div class="stat-row">
            <span class="stat-label">Domän / Miljö:</span>
            <span class="stat-val" id="boot-domain-name">WORKGROUP</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Inloggningsserver (DC):</span>
            <span class="stat-val" id="boot-logonserver">-</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">GPO-bearbetningstid:</span>
            <span class="stat-val" id="boot-gpo-time">-</span>
          </div>

          <!-- Unreachable Resources List -->
          <div id="boot-unreachable-container" style="margin-top: 14px;">
            <!-- Populated dynamically -->
          </div>
        </div>

        <!-- Advanced Boot Trace (WPR - Windows Performance Recorder) -->
        <div class="card" style="margin-bottom: 24px; border: 1px solid rgba(56, 189, 248, 0.25);" id="boot-wpr-card">
          <div class="card-header">
            <div class="card-title" style="display:flex; align-items:center; gap:8px;">
              <span style="font-size:18px;">🔬</span>
              <span>Djupgående Boot-Spårning (Windows Performance Recorder / WPR)</span>
            </div>
            <span class="badge badge-info" id="boot-wpr-badge">Redo</span>
          </div>

          <!-- Wizard Guide / Explanation -->
          <div style="background:rgba(15, 23, 42, 0.6); padding:12px 16px; border-radius:8px; margin-bottom:14px; border-left:3px solid var(--sky-500);">
            <div style="font-size:13px; font-weight:600; color:var(--text-primary); margin-bottom:4px;">
              Hur fungerar djupgående boot-spårning?
            </div>
            <div style="font-size:12px; color:var(--text-secondary); line-height:1.6;">
              1. <strong>Schemalägg & Starta om:</strong> WPR konfigureras och datorn startas om.<br/>
              2. <strong>Kärnmätning:</strong> Windows Performance Recorder mäter varenda CPU-cykel, drivrutin och disk-I/O under hela uppstarten.<br/>
              3. <strong>Automatisk analys vid inloggning:</strong> WinHealth startar automatiskt när du loggar in och sammanställer spårningsrapporten.
            </div>
          </div>

          <!-- Status Row -->
          <div class="stat-row" style="margin-bottom:10px;">
            <span class="stat-label">Aktuell spårningsstatus:</span>
            <span class="stat-val" id="boot-wpr-status-text" style="font-weight:600;">-</span>
          </div>

          <!-- Pending Reboot Banner -->
          <div id="boot-wpr-reboot-banner" style="display:none; margin-top:10px; margin-bottom:12px; padding:12px 16px; background:rgba(245, 158, 11, 0.15); border-radius:8px; border:1px solid rgba(245, 158, 11, 0.4);">
            <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px;">
              <div style="display:flex; align-items:center; gap:8px;">
                <span style="font-size:20px;">⏳</span>
                <div>
                  <strong style="color:#fbbf24;">Datorn startar om för att spela in uppstarten...</strong>
                  <div style="font-size:12px; color:var(--text-secondary);">WinHealth öppnas automatiskt efter inloggning för att visa resultaten.</div>
                </div>
              </div>
              <button class="btn btn-secondary btn-sm" id="btn-cancel-reboot">
                🛑 Avbryt omstart
              </button>
            </div>
          </div>

          <!-- Active Recording Alert Banner -->
          <div id="boot-wpr-recording-banner" style="display:none; margin-top:10px; margin-bottom:12px; padding:14px 18px; background:rgba(239, 68, 68, 0.15); border-radius:8px; border:1px solid rgba(239, 68, 68, 0.4);">
            <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px;">
              <div style="display:flex; align-items:center; gap:10px;">
                <span style="font-size:22px;">🔴</span>
                <div>
                  <strong style="color:#f87171; font-size:14px;">WPR spelar in kärndata i bakgrunden just nu!</strong>
                  <div style="font-size:12px; color:var(--text-secondary);">Datorn har startats om med aktiv spårning. Klicka för att slutföra och generera analysen.</div>
                </div>
              </div>
              <button class="btn btn-fix btn-sm" id="btn-stop-wpr-banner" style="font-weight:600;">
                💾 Spara & Slutför WPR-analys
              </button>
            </div>
          </div>

          <!-- Action Buttons Container -->
          <div style="display:flex; gap:10px; margin-top:12px; flex-wrap:wrap;" id="boot-wpr-actions">
            <button class="btn btn-primary btn-sm" id="btn-start-wpr-reboot" style="display:flex; align-items:center; gap:6px; font-weight:600;">
              <span>🚀 Schemalägg & Starta om datorn nu</span>
            </button>
            <button class="btn btn-secondary btn-sm" id="btn-start-wpr-manual" style="display:flex; align-items:center; gap:6px;">
              <span>⚡ Schemalägg utan omstart</span>
            </button>
            <button class="btn btn-fix btn-sm" id="btn-stop-wpr" style="display:none; align-items:center; gap:6px;">
              <span>💾 Spara & Analysera Boot-spårning</span>
            </button>
            <button class="btn btn-secondary btn-sm" id="btn-open-trace-folder" style="display:none; align-items:center; gap:6px;">
              <span>📂 Visa spårningsfil (.etl)</span>
            </button>
            <button class="btn btn-secondary btn-sm" id="btn-open-trace-wpa" style="display:none; align-items:center; gap:6px;">
              <span>📊 Öppna i WPA</span>
            </button>
            <button class="btn btn-danger-outline btn-sm" id="btn-cancel-wpr" style="display:none; align-items:center; gap:6px;">
              <span>🛑 Avbryt schemaläggning</span>
            </button>
            <button class="btn btn-secondary btn-sm" id="btn-clear-trace" style="display:none; align-items:center; gap:6px;">
              <span>🗑️ Rensa sparad spårning</span>
            </button>
          </div>

          <!-- WPR Deep Results Section (Hero display) -->
          <div id="boot-wpr-results-section" style="display:none; margin-top:20px; border-top:1px solid rgba(255,255,255,0.08); padding-top:16px;">
            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;">
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="badge badge-ok" style="font-size:12px; padding:4px 10px; font-weight:700; background:rgba(16,185,129,0.2); border:1px solid rgba(16,185,129,0.4); color:#34d399;">
                  ✨ RESULTAT FRÅN DJUPGÅENDE WPR-KÄRNSPÅRNING
                </span>
              </div>
              <span id="boot-wpr-timestamp" style="font-size:12px; color:var(--text-secondary); font-family:monospace;">-</span>
            </div>

            <!-- Trace File info pill -->
            <div style="display:flex; justify-content:space-between; align-items:center; padding:10px 14px; background:rgba(56, 189, 248, 0.08); border-radius:6px; border:1px solid rgba(56, 189, 248, 0.2); margin-bottom:16px; flex-wrap:wrap; gap:8px;">
              <div>
                <span style="font-size:12px; color:var(--text-secondary);">📁 Sparad spårningsfil: </span>
                <code id="boot-wpr-filepath" style="font-size:11px; color:#38bdf8;">-</code>
              </div>
              <span id="boot-wpr-filesize" class="badge badge-info" style="font-size:11px;">-</span>
            </div>

            <!-- Drivers and Services Breakdown Tables -->
            <div style="font-weight:600; font-size:13px; margin-bottom:8px; color:var(--sky-500);">
              ⚡ Mätta Drivrutiner & Komponenter under uppstarten:
            </div>
            <div class="table-wrapper" style="margin-bottom:12px;">
              <table>
                <thead>
                  <tr>
                    <th>Komponent / Drivrutin</th>
                    <th>Kategori</th>
                    <th>Uppmätt tid</th>
                    <th>Sökväg på disk</th>
                  </tr>
                </thead>
                <tbody id="boot-wpr-drivers-tbody">
                  <!-- Populated dynamically -->
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- Boot Degradation Culprits -->
        <div class="card" style="margin-bottom: 20px;">
          <div class="card-header">
            <div class="card-title">⚠️ Identifierade Tidstjuvar vid boot (Drivrutiner, Tjänster & Appar)</div>
            <span class="badge badge-warning" id="boot-deg-badge">0 identifierade</span>
          </div>
          <div id="boot-degradations-list">
            <div style="padding:8px 0; color:var(--text-secondary);">Inga signifikanta fördröjningar registrerade i Windows Eventlogg.</div>
          </div>
        </div>

        <!-- Startup Apps Manager -->
        <div class="card" style="margin-bottom: 20px;">
          <div class="card-header">
            <div class="card-title">🚀 Autostarthanterare (Stäng av onödiga program)</div>
            <span class="badge badge-ok" id="boot-startup-count">0 appar</span>
          </div>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Program</th>
                  <th>Plats</th>
                  <th>Påverkan</th>
                  <th>Status</th>
                  <th>Åtgärd</th>
                </tr>
              </thead>
              <tbody id="boot-startup-tbody">
                <!-- Populated dynamically -->
              </tbody>
            </table>
          </div>
        </div>

        <!-- Advanced 30+ Categories Autoruns Scanner (Sysinternals Style) -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">🔍 Avancerad Autoruns-skanning (30+ Platser, Sysinternals-stil)</div>
            <div style="display:flex; gap:8px; align-items:center;">
              <input type="text" id="autoruns-search-input" placeholder="Filtrera autostart..." style="padding:4px 10px; font-size:12px; border-radius:4px; border:1px solid var(--border-color); background:var(--bg-card); color:var(--text-primary); width:180px;" />
              <span class="badge badge-info" id="autoruns-count-badge">0 punkter</span>
            </div>
          </div>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Kategori</th>
                  <th>Namn</th>
                  <th>Utgivare</th>
                  <th>Sökväg / Registrering</th>
                  <th>Verifiering</th>
                </tr>
              </thead>
              <tbody id="autoruns-tbody">
                <!-- Populated dynamically -->
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- 9. Fixes Tab -->
      <section id="tab-fixes" class="tab-content">
        <div class="section-title">🛠️ Klickbara Snabbåtgärder för Windows & VPN</div>

        <div class="grid-2">
          <!-- Fix 1: Check Point -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">🔒 Återställ Check Point VPN</div>
              <button class="btn btn-fix btn-sm btn-run-fix" data-action="restart_checkpoint_vpn">Kör åtgärd</button>
            </div>
            <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 10px;">
              Stoppar hängda VPN-tjänster (TracSrvWrapper / CPNetServices), rensar processlåsningar och återaktiverar det virtuella nätverkskortet.
            </p>
          </div>

          <!-- Fix 2: Flush DNS & Winsock -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">🌐 Återställ DNS & Winsock</div>
              <button class="btn btn-fix btn-sm btn-run-fix" data-action="flush_dns_winsock">Kör åtgärd</button>
            </div>
            <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 10px;">
              Tömmer lokal DNS-cache (<kbd>ipconfig /flushdns</kbd>), registrerar om namn och återställer Winsock och TCP/IP-stacken vid anslutningsfel.
            </p>
          </div>

          <!-- Fix 3: Clean Temp Files -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">🧹 Rensa Temporära Filer</div>
              <button class="btn btn-fix btn-sm btn-run-fix" data-action="clean_temp_files">Kör åtgärd</button>
            </div>
            <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 10px;">
              Rensar säkert filer i <kbd>%TEMP%</kbd> och <kbd>C:\\Windows\\Temp</kbd> för att frigöra diskutrymme och snabba upp systemet.
            </p>
          </div>

          <!-- Fix 4: Reset Windows Update -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">🔄 Återställ Windows Update</div>
              <button class="btn btn-fix btn-sm btn-run-fix" data-action="reset_windows_update">Kör åtgärd</button>
            </div>
            <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 10px;">
              Stoppar uppdateringstjänsten, rensar eventuellt korrupta nedladdningsfiler i <kbd>SoftwareDistribution</kbd> och startar om tjänsterna.
            </p>
          </div>

          <!-- Fix 5: SFC Scan -->
          <div class="card">
            <div class="card-header">
              <div class="card-title">🛠️ Kör SFC Systemfilsreparation</div>
              <button class="btn btn-fix btn-sm btn-run-fix" data-action="run_sfc_scan">Kör åtgärd</button>
            </div>
            <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 10px;">
              Startar <kbd>sfc /scannow</kbd> med administratörsrättigheter för att identifiera och automatiskt reparera skadade systemfiler.
            </p>
          </div>
        </div>

        <!-- Action Execution Console -->
        <div id="action-console" class="action-console">
          <div style="display:flex; justify-content:space-between; margin-bottom: 8px; color: #38bdf8; font-weight: 600;">
            <span id="console-action-title">▶ Kör åtgärd...</span>
            <span id="console-status-badge">Körs...</span>
          </div>
          <div id="console-output" style="color: #cbd5e1; line-height: 1.6;"></div>
        </div>
      </section>
    </main>
  </div>
</div>
`;

// Setup Event Listeners
function setupEvents() {
  // Tabs navigation
  document.querySelectorAll<HTMLElement>('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      const targetTab = item.getAttribute('data-tab');
      if (!targetTab) return;
      switchTab(targetTab);
    });
  });

  // Scan button
  document.querySelector('#btn-scan')?.addEventListener('click', () => {
    runDiagnosticScan();
  });

  // Export HTML button
  document.querySelector('#btn-export-html')?.addEventListener('click', async () => {
    try {
      const path = await ExportAndOpenHTMLReport();
      if (path) {
        showToast(`Hälsorapport sparad och öppnad: ${path}`, 'success');
      }
    } catch (err: any) {
      showToast(`Fel vid export: ${err}`, 'error');
    }
  });

  // Export JSON button
  document.querySelector('#btn-export-json')?.addEventListener('click', async () => {
    try {
      const path = await ExportJSONReport();
      if (path) {
        showToast(`JSON exporterad: ${path}`, 'success');
      }
    } catch (err: any) {
      showToast(`Fel vid export: ${err}`, 'error');
    }
  });

  // Direct fix buttons
  document.querySelector('#btn-fix-vpn-direct')?.addEventListener('click', () => {
    executeFixAction('restart_checkpoint_vpn');
  });
  document.querySelector('#btn-fix-dns-direct')?.addEventListener('click', () => {
    executeFixAction('flush_dns_winsock');
  });
  document.querySelector('#btn-fix-wu-direct')?.addEventListener('click', () => {
    executeFixAction('reset_windows_update');
  });
  document.querySelector('#btn-fix-sfc-direct')?.addEventListener('click', () => {
    executeFixAction('run_sfc_scan');
  });

  // Generic Run Fix Buttons
  document.querySelectorAll<HTMLElement>('.btn-run-fix').forEach(btn => {
    btn.addEventListener('click', () => {
      const actionId = btn.getAttribute('data-action');
      if (actionId) {
        executeFixAction(actionId);
      }
    });
  });

  // Copy VPN logs
  document.querySelector('#btn-copy-vpn-logs')?.addEventListener('click', () => {
    const text = document.querySelector('#cp-log-viewer')?.textContent || '';
    navigator.clipboard.writeText(text);
    showToast('VPN-loggar kopierades till urklipp!', 'success');
  });

  // Search filter for event logs
  document.querySelector<HTMLInputElement>('#event-search-input')?.addEventListener('input', (e) => {
    const q = (e.target as HTMLInputElement).value.toLowerCase();
    filterEventLogs(q);
  });

  // GPO Report button
  document.querySelector('#btn-generate-gpo')?.addEventListener('click', async () => {
    showToast('Genererar fullständig GPO-rapport med gpresult...', 'info');
    try {
      const res = await GenerateAndOpenGPOReport();
      if (res.success) {
        showToast(res.summary_text, 'success');
      } else {
        showToast(`GPO: ${res.error_message || res.summary_text}`, 'error');
      }
    } catch (err: any) {
      showToast(`Kunde inte generera GPO: ${err}`, 'error');
    }
  });

  // WPR Start with Reboot button
  document.querySelector('#btn-start-wpr-reboot')?.addEventListener('click', async () => {
    showToast('Konfigurerar WPR och planerar omstart...', 'info');
    try {
      const res = await StartWPRBootTraceWithReboot('GeneralProfile', true);
      if (res.success) {
        showToast(res.message, 'success');
        const rebootBanner = document.querySelector('#boot-wpr-reboot-banner') as HTMLElement;
        if (rebootBanner) rebootBanner.style.display = 'block';
        runDiagnosticScan();
      } else {
        showToast(`WPR fel: ${res.message}`, 'error');
      }
    } catch (err: any) {
      showToast(`Kunde inte starta WPR: ${err}`, 'error');
    }
  });

  // WPR Start Manual (no instant reboot) button
  document.querySelector('#btn-start-wpr-manual')?.addEventListener('click', async () => {
    showToast('Konfigurerar WPR boot-spårning...', 'info');
    try {
      const res = await StartWPRBootTraceWithReboot('GeneralProfile', false);
      if (res.success) {
        showToast(res.message, 'success');
        runDiagnosticScan();
      } else {
        showToast(`WPR fel: ${res.message}`, 'error');
      }
    } catch (err: any) {
      showToast(`Kunde inte starta WPR: ${err}`, 'error');
    }
  });

  // Cancel Pending Reboot button
  document.querySelector('#btn-cancel-reboot')?.addEventListener('click', async () => {
    try {
      const res = await CancelPendingReboot();
      showToast(res.message, res.success ? 'success' : 'error');
      const rebootBanner = document.querySelector('#boot-wpr-reboot-banner') as HTMLElement;
      if (rebootBanner) rebootBanner.style.display = 'none';
    } catch (err: any) {
      showToast(`Fel: ${err}`, 'error');
    }
  });

  // WPR Stop buttons
  const handleStopWpr = async () => {
    showToast('Stoppar och analyserar boot-spårning...', 'info');
    try {
      const res = await StopWPRBootTrace();
      if (res.success) {
        showToast(res.message, 'success');
        runDiagnosticScan();
      } else {
        showToast(`WPR fel: ${res.message}`, 'error');
      }
    } catch (err: any) {
      showToast(`Kunde inte stoppa WPR: ${err}`, 'error');
    }
  };
  document.querySelector('#btn-stop-wpr')?.addEventListener('click', handleStopWpr);
  document.querySelector('#btn-stop-wpr-banner')?.addEventListener('click', handleStopWpr);

  // WPR Clear Trace button
  document.querySelector('#btn-clear-trace')?.addEventListener('click', async () => {
    try {
      const res = await ClearTraceData();
      showToast(res.message, 'info');
      runDiagnosticScan();
    } catch (err: any) {
      showToast(`Kunde inte rensa spårning: ${err}`, 'error');
    }
  });

  // WPR Open Trace Folder button
  document.querySelector('#btn-open-trace-folder')?.addEventListener('click', async () => {
    try {
      await OpenTraceFolder();
      showToast('Öppnade spårningsmappen i Utforskaren.', 'info');
    } catch (err: any) {
      showToast(`Kunde inte öppna mapp: ${err}`, 'error');
    }
  });

  // WPR Open in WPA button
  document.querySelector('#btn-open-trace-wpa')?.addEventListener('click', async () => {
    try {
      const ok = await OpenTraceInWPA();
      if (ok) {
        showToast('Startade Windows Performance Analyzer.', 'success');
      } else {
        showToast('Windows Performance Analyzer hittades inte på datorn.', 'error');
      }
    } catch (err: any) {
      showToast(`WPA: ${err}`, 'error');
    }
  });

  // WPR Cancel button
  document.querySelector('#btn-cancel-wpr')?.addEventListener('click', async () => {
    showToast('Avbryter WPR boot-spårning...', 'info');
    try {
      const res = await CancelWPRBootTrace();
      showToast(res.message, res.success ? 'success' : 'error');
      const rebootBanner = document.querySelector('#boot-wpr-reboot-banner') as HTMLElement;
      if (rebootBanner) rebootBanner.style.display = 'none';
      runDiagnosticScan();
    } catch (err: any) {
      showToast(`Fel: ${err}`, 'error');
    }
  });

  // Autoruns search filter
  document.querySelector<HTMLInputElement>('#autoruns-search-input')?.addEventListener('input', (e) => {
    const q = (e.target as HTMLInputElement).value.toLowerCase();
    filterAutoruns(q);
  });
}

function switchTab(tabId: string) {
  document.querySelectorAll('.nav-item').forEach(nav => {
    if (nav.getAttribute('data-tab') === tabId) {
      nav.classList.add('active');
    } else {
      nav.classList.remove('active');
    }
  });

  document.querySelectorAll('.tab-content').forEach(content => {
    if (content.id === tabId) {
      content.classList.add('active');
    } else {
      content.classList.remove('active');
    }
  });
}

// Perform Diagnostic Scan
async function runDiagnosticScan() {
  if (isScanning) return;
  isScanning = true;

  const btnScan = document.querySelector('#btn-scan')!;
  const scanLabel = document.querySelector('#scan-label')!;

  btnScan.classList.add('btn-spinning');
  scanLabel.textContent = 'Skannar systemet...';
  showToast('Diagnostikskanning startad...', 'info');

  try {
    const report = await GetHealthReport();
    renderHealthReport(report);
    showToast('Skanning slutförd!', 'success');
  } catch (err: any) {
    showToast(`Skanningsfel: ${err}`, 'error');
  } finally {
    isScanning = false;
    btnScan.classList.remove('btn-spinning');
    scanLabel.textContent = 'Skanna datorn';
  }
}

// Render Health Report
function renderHealthReport(r: models.HealthReport) {
  // Header details
  document.querySelector('#header-hostname')!.textContent = r.computer_name || 'Denna dator';
  document.querySelector('#header-os')!.textContent = r.os_version || 'Windows';
  document.querySelector('#header-uptime')!.textContent = r.uptime || '-';

  // Overall Score Gauge
  renderScoreGauge(r.total_score, r.score_rating);

  // Status Stat Pills
  const vpnPill = document.querySelector('#pill-vpn-status') as HTMLElement;
  if (r.checkpoint_vpn.detected) {
    vpnPill.textContent = `${r.checkpoint_vpn.score}/100`;
    vpnPill.style.color = getScoreColor(r.checkpoint_vpn.score);
  } else {
    vpnPill.textContent = 'Ej installerad';
    vpnPill.style.color = '#94a3b8';
  }

  const diskPill = document.querySelector('#pill-disk-status') as HTMLElement;
  diskPill.textContent = `${r.hardware.score}/100`;
  diskPill.style.color = getScoreColor(r.hardware.score);

  const crashPill = document.querySelector('#pill-crash-status') as HTMLElement;
  crashPill.textContent = `${r.event_logs.bsod_crash_dumps.length} BSOD`;
  crashPill.style.color = r.event_logs.bsod_crash_dumps.length > 0 ? '#ef4444' : '#10b981';

  const netPill = document.querySelector('#pill-net-status') as HTMLElement;
  netPill.textContent = r.network.internet_ok ? 'Online' : 'Offline';
  netPill.style.color = r.network.internet_ok ? '#10b981' : '#ef4444';

  // Top Issues
  renderTopIssues(r.top_issues);

  // Render Sub-tabs
  renderCheckPointTab(r.checkpoint_vpn);
  renderHardwareTab(r.hardware);
  renderNetworkTab(r.network);
  renderSecurityTab(r.security);
  renderCrashesTab(r.event_logs);
  renderPerformanceTab(r.performance);
  renderBootTab(r.boot_logon);

  // Nav badges
  const navVpn = document.querySelector('#nav-vpn-badge') as HTMLElement;
  if (r.checkpoint_vpn.detected && r.checkpoint_vpn.score < 80) {
    navVpn.style.display = 'inline-block';
    navVpn.className = `nav-badge ${r.checkpoint_vpn.score < 50 ? 'crit' : 'warn'}`;
    navVpn.textContent = '!';
  } else {
    navVpn.style.display = 'none';
  }

  const navCrashes = document.querySelector('#nav-crashes-badge') as HTMLElement;
  if (r.event_logs.bsod_crash_dumps.length > 0 || r.event_logs.critical_event_count > 0) {
    navCrashes.style.display = 'inline-block';
    navCrashes.className = 'nav-badge crit';
    navCrashes.textContent = String(r.event_logs.bsod_crash_dumps.length + r.event_logs.critical_event_count);
  } else {
    navCrashes.style.display = 'none';
  }

  const navBoot = document.querySelector('#nav-boot-badge') as HTMLElement;
  if (r.boot_logon && (r.boot_logon.unreachable_resources.length > 0 || r.boot_logon.total_boot_duration_seconds > 45)) {
    navBoot.style.display = 'inline-block';
    navBoot.className = 'nav-badge crit';
    navBoot.textContent = r.boot_logon.unreachable_resources.length > 0 ? String(r.boot_logon.unreachable_resources.length) : '!';
  } else {
    navBoot.style.display = 'none';
  }
}

// Animate Score Gauge
function renderScoreGauge(score: number, rating: string) {
  const scoreNum = document.querySelector('#score-number')!;
  const scoreBar = document.querySelector('#score-gauge-bar') as SVGPathElement;
  const scoreBadge = document.querySelector('#score-badge')!;
  const scoreStatusText = document.querySelector('#score-status-text')!;
  const scoreDesc = document.querySelector('#score-description')!;

  scoreNum.textContent = String(score);
  scoreStatusText.textContent = rating;

  const color = getScoreColor(score);
  scoreBar.style.stroke = color;
  scoreNum.setAttribute('style', `color: ${color}`);

  // Circumference is 2 * PI * 42 ~= 263.89
  const maxOffset = 264;
  const offset = maxOffset - (score / 100) * maxOffset;
  scoreBar.style.strokeDashoffset = String(offset);

  if (score >= 90) {
    scoreBadge.className = 'badge badge-ok';
    scoreBadge.textContent = 'Utmärkt';
    scoreDesc.textContent = 'Datorn mår mycket bra! Inga kritiska problem eller allvarliga loggfel upptäcktes.';
  } else if (score >= 75) {
    scoreBadge.className = 'badge badge-warning';
    scoreBadge.textContent = 'Varning';
    scoreDesc.textContent = 'Datorn fungerar, men några anmärkningar eller varningar hittades som bör ses över.';
  } else {
    scoreBadge.className = 'badge badge-critical';
    scoreBadge.textContent = 'Åtgärd krävs';
    scoreDesc.textContent = 'Kritiska avvikelser upptäcktes. Använd snabbåtgärderna nedan för att åtgärda problemen.';
  }
}

function getScoreColor(score: number): string {
  if (score >= 90) return '#10b981';
  if (score >= 75) return '#f59e0b';
  return '#ef4444';
}

// Render Top Issues
function renderTopIssues(issues: models.IssueSummary[]) {
  const container = document.querySelector('#top-issues-container')!;
  const countBadge = document.querySelector('#issues-count-badge')!;

  countBadge.textContent = `${issues.length} punkter`;

  if (issues.length === 0) {
    container.innerHTML = `
      <div class="card" style="text-align:center; padding: 24px; color: var(--emerald-500);">
        ✅ Inga problem eller avvikelser hittades. Systemet fungerar optimalt!
      </div>
    `;
    return;
  }

  container.innerHTML = issues.map(iss => {
    const sevClass = iss.severity.toLowerCase() === 'critical' ? 'crit' : (iss.severity.toLowerCase() === 'warning' ? 'warn' : 'info');
    const fixBtn = iss.fix_action_id ? `
      <button class="btn btn-fix btn-sm btn-run-fix" data-action="${iss.fix_action_id}">
        Åtgärda nu
      </button>
    ` : '';

    return `
      <div class="issue-card ${sevClass}">
        <div class="issue-left">
          <div class="issue-tag">[${iss.category}]</div>
          <div class="issue-title">${escapeHtml(iss.title)}</div>
          <div class="issue-desc">${escapeHtml(iss.description)}</div>
        </div>
        ${fixBtn}
      </div>
    `;
  }).join('');

  // Re-bind click handlers for dynamic buttons
  container.querySelectorAll<HTMLElement>('.btn-run-fix').forEach(btn => {
    btn.addEventListener('click', () => {
      const actionId = btn.getAttribute('data-action');
      if (actionId) executeFixAction(actionId);
    });
  });
}

// Check Point VPN Tab
function renderCheckPointTab(cp: models.CheckPointReport) {
  const detectedBadge = document.querySelector('#cp-detected-badge')!;
  if (cp.detected) {
    detectedBadge.className = 'badge badge-ok';
    detectedBadge.textContent = 'Detekterad & Aktiv';
  } else {
    detectedBadge.className = 'badge badge-info';
    detectedBadge.textContent = 'Ej installerad';
  }

  document.querySelector('#cp-client-version')!.textContent = cp.client_version || 'Check Point Endpoint Security';
  document.querySelector('#cp-install-path')!.textContent = cp.install_path || 'Standard';
  document.querySelector('#cp-config-found')!.textContent = cp.configuration_found ? 'Ja (trac.config aktiv)' : 'Standardkonfiguration';
  document.querySelector('#cp-recom-action')!.textContent = cp.recommended_action || '-';

  // Gateways
  const gwContainer = document.querySelector('#cp-gateways-container')!;
  if (cp.gateway_connectivity && cp.gateway_connectivity.length > 0) {
    gwContainer.innerHTML = cp.gateway_connectivity.map(gw => `
      <div class="stat-row">
        <span class="stat-label">${escapeHtml(gw.gateway)} (Port ${gw.port})</span>
        <span class="stat-val" style="color: ${gw.reachable ? '#10b981' : '#ef4444'};">
          ${gw.reachable ? `🟢 Nås (${gw.latency_ms} ms)` : `🔴 Misslyckades (${gw.error_message || 'Timeout'})`}
        </span>
      </div>
    `).join('');
  } else {
    gwContainer.innerHTML = `<div class="stat-row"><span class="stat-label">Inga gateways specificerade i lokal profil.</span></div>`;
  }

  // Services
  const servicesTbody = document.querySelector('#cp-services-tbody')!;
  if (cp.services && cp.services.length > 0) {
    servicesTbody.innerHTML = cp.services.map(s => `
      <tr>
        <td><code>${escapeHtml(s.name)}</code></td>
        <td><strong>${escapeHtml(s.display_name)}</strong></td>
        <td><span class="badge ${s.is_healthy ? 'badge-ok' : 'badge-critical'}">${s.status}</span></td>
        <td>${s.start_type}</td>
        <td>${s.is_healthy ? '🟢 OK' : '🔴 Fel'}</td>
      </tr>
    `).join('');
  } else {
    servicesTbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-secondary);">Inga Check Point-specifika Windows-tjänster hittades.</td></tr>`;
  }

  // Virtual Adapters
  const adaptersTbody = document.querySelector('#cp-adapters-tbody')!;
  if (cp.virtual_adapters && cp.virtual_adapters.length > 0) {
    adaptersTbody.innerHTML = cp.virtual_adapters.map(a => `
      <tr>
        <td><strong>${escapeHtml(a.name)}</strong></td>
        <td>${escapeHtml(a.description)}</td>
        <td><span class="badge ${a.is_healthy ? 'badge-ok' : 'badge-warning'}">${a.status}</span></td>
        <td><code>${a.mac_address || '-'}</code></td>
      </tr>
    `).join('');
  } else {
    adaptersTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-secondary);">Inga virtuella Check Point-nätverkskort detekterades.</td></tr>`;
  }

  // Logs
  const logViewer = document.querySelector('#cp-log-viewer')!;
  if (cp.recent_log_errors && cp.recent_log_errors.length > 0) {
    logViewer.textContent = cp.recent_log_errors.join('\n');
  } else {
    logViewer.textContent = 'Inga fel loggade i Check Point klientloggar de senaste 7 dagarna.';
  }
}

// Hardware Tab
function renderHardwareTab(hw: models.HardwareReport) {
  document.querySelector('#hw-cpu-model')!.textContent = hw.cpu_model || 'Windows Processor';
  document.querySelector('#hw-cpu-cores')!.textContent = `${hw.cpu_cores} kärnor`;
  document.querySelector('#hw-motherboard')!.textContent = hw.motherboard || 'Standard PC';
  document.querySelector('#hw-bios')!.textContent = hw.bios_version || 'UEFI';

  document.querySelector('#hw-ram-text')!.textContent = `${hw.used_ram_gb} / ${hw.total_ram_gb} GB (${hw.ram_usage_pct}%)`;
  const ramBar = document.querySelector('#hw-ram-bar') as HTMLElement;
  ramBar.style.width = `${hw.ram_usage_pct}%`;
  ramBar.className = `progress-fill ${hw.ram_usage_pct > 90 ? 'crit' : (hw.ram_usage_pct > 75 ? 'warn' : 'ok')}`;

  // Battery
  const battCard = document.querySelector('#hw-battery-card') as HTMLElement;
  if (hw.battery && hw.battery.present) {
    battCard.style.display = 'block';
    document.querySelector('#hw-battery-charge')!.textContent = `${hw.battery.charge_percent}%`;
    document.querySelector('#hw-battery-status')!.textContent = hw.battery.status;
    document.querySelector('#hw-battery-health')!.textContent = `${hw.battery.health_pct}% av ursprunglig design`;
  } else {
    battCard.style.display = 'none';
  }

  // Disks
  const disksContainer = document.querySelector('#hw-disks-container')!;
  if (hw.disks && hw.disks.length > 0) {
    disksContainer.innerHTML = hw.disks.map(d => `
      <div class="card">
        <div class="card-header">
          <div class="card-title">Enhet ${d.drive_letter} (${d.model})</div>
          <span class="badge ${d.smart_healthy ? 'badge-ok' : 'badge-critical'}">
            ${d.smart_healthy ? 'SMART: Bra' : 'SMART: Varning'}
          </span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Typ & Filsystem:</span>
          <span class="stat-val">${d.media_type} (${d.file_system})</span>
        </div>
        <div class="stat-row">
          <span class="stat-label">Ledigt utrymme:</span>
          <span class="stat-val">${d.free_gb} GB ledigt av ${d.total_gb} GB</span>
        </div>
        <div class="progress-container">
          <div class="progress-header">
            <span>Användning</span>
            <span>${d.usage_pct}%</span>
          </div>
          <div class="progress-track">
            <div class="progress-fill ${d.usage_pct > 90 ? 'crit' : (d.usage_pct > 75 ? 'warn' : 'ok')}" style="width: ${d.usage_pct}%;"></div>
          </div>
        </div>
      </div>
    `).join('');
  }
}

// Network Tab
function renderNetworkTab(net: models.NetworkReport) {
  const internetBadge = document.querySelector('#net-internet-badge')!;
  internetBadge.className = `badge ${net.internet_ok ? 'badge-ok' : 'badge-critical'}`;
  internetBadge.textContent = net.internet_ok ? 'Ansluten' : 'Offline';

  document.querySelector('#net-internet-val')!.textContent = net.internet_ok ? 'Aktiv anslutning' : 'Ingen internetkontakt';
  document.querySelector('#net-gateway-val')!.textContent = net.default_gateway || 'Ingen';
  document.querySelector('#net-gateway-ping')!.textContent = `${net.gateway_ping_ms} ms`;
  document.querySelector('#net-proxy-val')!.textContent = net.proxy_configured ? net.proxy_details || 'Aktiv proxy' : 'Ingen proxy';

  // DNS
  const dnsContainer = document.querySelector('#net-dns-container')!;
  if (net.dns_servers && net.dns_servers.length > 0) {
    dnsContainer.innerHTML = net.dns_servers.map(dns => `
      <div class="stat-row">
        <span class="stat-label">${escapeHtml(dns.server)}</span>
        <span class="stat-val" style="color: ${dns.reachable ? '#10b981' : '#ef4444'};">
          ${dns.reachable ? `🟢 ${dns.latency_ms} ms` : '🔴 Svarar ej'}
        </span>
      </div>
    `).join('');
  }

  // Adapters
  const adaptersTbody = document.querySelector('#net-adapters-tbody')!;
  if (net.active_adapters && net.active_adapters.length > 0) {
    adaptersTbody.innerHTML = net.active_adapters.map(a => `
      <tr>
        <td><span class="badge badge-info">${a.interface_type}</span></td>
        <td><strong>${escapeHtml(a.name)}</strong></td>
        <td><code>${a.ipv4_address || '-'}</code></td>
        <td>${a.gateway || '-'}</td>
        <td><code>${a.mac}</code></td>
        <td><span class="badge badge-ok">${a.status}</span></td>
      </tr>
    `).join('');
  }
}

// Security Tab
function renderSecurityTab(sec: models.SecurityReport) {
  const avBadge = document.querySelector('#sec-av-badge')!;
  avBadge.className = `badge ${sec.realtime_protection ? 'badge-ok' : 'badge-critical'}`;
  avBadge.textContent = sec.realtime_protection ? 'Skyddad' : 'Varning';

  document.querySelector('#sec-av-name')!.textContent = sec.antivirus_name || 'Windows Defender';
  document.querySelector('#sec-realtime-val')!.textContent = sec.realtime_protection ? 'Aktivt' : 'Inaktivt';
  document.querySelector('#sec-sig-val')!.textContent = sec.definitions_up_to_date ? 'Aktuella' : 'Föråldrade';
  document.querySelector('#sec-firewall-val')!.textContent = sec.firewall_enabled ? 'Aktiverad' : 'Inaktiverad';

  document.querySelector('#sec-bitlocker-val')!.textContent = sec.bitlocker_status;
  document.querySelector('#sec-wu-overall-val')!.textContent = sec.windows_update_overall_status || (sec.pending_updates_count > 0 ? `${sec.pending_updates_count} st väntar` : 'Datorn är uppdaterad');
  document.querySelector('#sec-last-install-val')!.textContent = sec.last_update_install_time || 'Nyligen';
  document.querySelector('#sec-last-search-val')!.textContent = sec.last_update_search_time || 'Nyligen';
  document.querySelector('#sec-pending-count-val')!.textContent = `${sec.pending_updates_count} st`;
  document.querySelector('#sec-reboot-val')!.textContent = (sec.pending_updates_count > 0 && sec.windows_update_overall_status.includes('Omstart')) ? 'Ja (Krävs för slutförande)' : 'Nej';

  // Pending Updates Waiting to be installed
  const pendingBadge = document.querySelector('#sec-pending-badge')!;
  pendingBadge.textContent = `${sec.pending_updates_count} väntar`;
  pendingBadge.className = `badge ${sec.pending_updates_count > 0 ? 'badge-warning' : 'badge-ok'}`;

  const pendingContainer = document.querySelector('#sec-pending-updates-list')!;
  const pendingItems = (sec.pending_updates_details && sec.pending_updates_details.length > 0)
    ? sec.pending_updates_details
    : (sec.pending_updates_list || []).map(t => ({ title: t, category: 'Uppdatering', kb_article_id: '', is_hidden: false }));

  if (pendingItems.length > 0) {
    pendingContainer.innerHTML = pendingItems.map(u => `
      <div class="stat-row" style="align-items: center; gap: 12px; padding: 8px 0;">
        <div style="flex: 1;">
          <span class="badge badge-warning" style="font-size:10px; margin-right:6px;">${escapeHtml(u.category || 'System')}</span>
          <strong>${escapeHtml(u.title)}</strong>
        </div>
        <button class="btn-danger-outline btn-hide-update" data-title="${escapeHtml(u.title)}">
          🚫 Dölj / Blockera
        </button>
      </div>
    `).join('');
  } else {
    pendingContainer.innerHTML = '<div style="padding:8px 0; color:var(--emerald-500);">✅ Inga väntande uppdateringar i kön just nu.</div>';
  }

  // Hidden / Blocked Updates
  const hiddenBadge = document.querySelector('#sec-hidden-badge')!;
  const hiddenCount = sec.hidden_updates_count || (sec.hidden_updates_list ? sec.hidden_updates_list.length : 0);
  hiddenBadge.textContent = `${hiddenCount} blockerade`;
  hiddenBadge.className = `badge ${hiddenCount > 0 ? 'badge-info' : 'badge-ok'}`;

  const hiddenContainer = document.querySelector('#sec-hidden-updates-list')!;
  if (sec.hidden_updates_list && sec.hidden_updates_list.length > 0) {
    hiddenContainer.innerHTML = sec.hidden_updates_list.map(u => `
      <div class="stat-row" style="align-items: center; gap: 12px; padding: 8px 0;">
        <div style="flex: 1;">
          <span class="badge badge-info" style="font-size:10px; margin-right:6px;">Blockerad</span>
          <span>${escapeHtml(u.title)}</span>
        </div>
        <button class="btn-success-outline btn-unhide-update" data-title="${escapeHtml(u.title)}">
          👁️ Tillåt / Återställ
        </button>
      </div>
    `).join('');
  } else {
    hiddenContainer.innerHTML = '<div style="padding:8px 0; color:var(--text-secondary);">Inga uppdateringar är blockerade. Alla godkända installeras normalt.</div>';
  }

  // Bind click handlers for Hide / Unhide buttons
  pendingContainer.querySelectorAll<HTMLElement>('.btn-hide-update').forEach(btn => {
    btn.addEventListener('click', async () => {
      const title = btn.getAttribute('data-title');
      if (title) await handleToggleUpdateHidden(title, true);
    });
  });

  hiddenContainer.querySelectorAll<HTMLElement>('.btn-unhide-update').forEach(btn => {
    btn.addEventListener('click', async () => {
      const title = btn.getAttribute('data-title');
      if (title) await handleToggleUpdateHidden(title, false);
    });
  });

  // Recent successfully installed updates
  const updatesContainer = document.querySelector('#sec-recent-updates-list')!;
  if (sec.recent_updates_installed && sec.recent_updates_installed.length > 0) {
    updatesContainer.innerHTML = sec.recent_updates_installed.map(u => `
      <div class="stat-row">
        <span class="stat-label">🟢 ${escapeHtml(u)}</span>
        <span class="stat-val" style="color:#34d399; font-size:11px;">Installerad</span>
      </div>
    `).join('');
  } else {
    updatesContainer.innerHTML = '<div style="padding:8px 0; color:var(--text-secondary);">Ingen nylig uppdateringshistorik hittades.</div>';
  }
}

async function handleToggleUpdateHidden(title: string, hide: boolean) {
  const actionText = hide ? 'Döljer / Blockerar' : 'Återställer / Tillåter';
  showToast(`${actionText} uppdateringen...`, 'info');
  try {
    const res = await ToggleWindowsUpdateHidden(title, hide);
    if (res.success) {
      showToast(res.message || 'Uppdateringsstatus ändrad!', 'success');
      runDiagnosticScan();
    } else {
      showToast(`Fel: ${res.message}`, 'error');
    }
  } catch (err: any) {
    showToast(`Kunde inte ändra status: ${err}`, 'error');
  }
}

// Crashes & Logs Tab
let cachedEventLogs: models.EventLogEntry[] = [];

function renderCrashesTab(logs: models.EventLogsReport) {
  // Dumps
  const dumpCount = document.querySelector('#crash-dumps-count-badge')!;
  dumpCount.textContent = `${logs.bsod_crash_dumps.length} st`;
  dumpCount.className = `badge ${logs.bsod_crash_dumps.length > 0 ? 'badge-critical' : 'badge-ok'}`;

  const dumpsTbody = document.querySelector('#crash-dumps-tbody')!;
  if (logs.bsod_crash_dumps && logs.bsod_crash_dumps.length > 0) {
    dumpsTbody.innerHTML = logs.bsod_crash_dumps.map(d => `
      <tr>
        <td><strong>${escapeHtml(d.file_name)}</strong></td>
        <td>${d.created_time ? new Date(d.created_time).toLocaleString('sv-SE') : '-'}</td>
        <td>${(d.size_bytes / 1024).toFixed(0)} KB</td>
        <td><code>${escapeHtml(d.file_path)}</code></td>
      </tr>
    `).join('');
  } else {
    dumpsTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-secondary);">Inga kraschdumpar hittades.</td></tr>`;
  }

  // Events
  cachedEventLogs = [...(logs.recent_system_errors || []), ...(logs.recent_app_crashes || [])];
  renderEventLogsTable(cachedEventLogs);
}

function renderEventLogsTable(events: models.EventLogEntry[]) {
  const eventsTbody = document.querySelector('#event-logs-tbody')!;
  if (events.length > 0) {
    eventsTbody.innerHTML = events.map(e => `
      <tr>
        <td><span class="badge ${e.log_name === 'System' ? 'badge-info' : 'badge-warning'}">${e.log_name}</span></td>
        <td><code>${e.event_id}</code></td>
        <td>${escapeHtml(e.source)}</td>
        <td>${e.time_created ? new Date(e.time_created).toLocaleTimeString('sv-SE') : '-'}</td>
        <td><span class="badge ${e.level === 'Critical' ? 'badge-critical' : 'badge-warning'}">${e.level}</span></td>
        <td style="max-width: 400px;">${escapeHtml(e.message)}</td>
      </tr>
    `).join('');
  } else {
    eventsTbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-secondary);">Inga fel registrerade de senaste 48 timmarna.</td></tr>`;
  }
}

function filterEventLogs(query: string) {
  if (!query) {
    renderEventLogsTable(cachedEventLogs);
    return;
  }
  const filtered = cachedEventLogs.filter(e => 
    String(e.event_id).includes(query) ||
    e.source.toLowerCase().includes(query) ||
    e.message.toLowerCase().includes(query) ||
    e.log_name.toLowerCase().includes(query)
  );
  renderEventLogsTable(filtered);
}

// Performance Tab
function renderPerformanceTab(perf: models.PerformanceReport) {
  // RAM processes
  const ramTbody = document.querySelector('#perf-ram-tbody')!;
  if (perf.top_processes_by_ram && perf.top_processes_by_ram.length > 0) {
    ramTbody.innerHTML = perf.top_processes_by_ram.map(p => `
      <tr>
        <td><code>${p.pid}</code></td>
        <td><strong>${escapeHtml(p.name)}</strong></td>
        <td>${p.ram_mb} MB</td>
      </tr>
    `).join('');
  }

  // CPU processes
  const cpuTbody = document.querySelector('#perf-cpu-tbody')!;
  if (perf.top_processes_by_cpu && perf.top_processes_by_cpu.length > 0) {
    cpuTbody.innerHTML = perf.top_processes_by_cpu.map(p => `
      <tr>
        <td><code>${p.pid}</code></td>
        <td><strong>${escapeHtml(p.name)}</strong></td>
        <td>${p.cpu_percent} s</td>
      </tr>
    `).join('');
  }

  // Startup
  const startupTbody = document.querySelector('#perf-startup-tbody')!;
  if (perf.startup_programs && perf.startup_programs.length > 0) {
    startupTbody.innerHTML = perf.startup_programs.map(s => `
      <tr>
        <td><strong>${escapeHtml(s.name)}</strong></td>
        <td><span class="badge badge-info">${s.location}</span></td>
        <td style="max-width:350px; font-size:11px; word-break:break-all;"><code>${escapeHtml(s.command)}</code></td>
      </tr>
    `).join('');
  }
}

// Boot & Logon Tab
function renderBootTab(boot: models.BootLogonReport) {
  if (!boot) return;

  // Header & Stats
  const statusBadge = document.querySelector('#boot-status-badge')!;
  if (boot.total_boot_duration_seconds > 45 || (boot.unreachable_resources && boot.unreachable_resources.length > 0)) {
    statusBadge.className = 'badge badge-critical';
    statusBadge.textContent = 'Långsam / Problem';
  } else if (boot.total_boot_duration_seconds > 25) {
    statusBadge.className = 'badge badge-warning';
    statusBadge.textContent = 'Normal';
  } else {
    statusBadge.className = 'badge badge-ok';
    statusBadge.textContent = 'Snabb start';
  }

  document.querySelector('#boot-total-sec')!.textContent = `${boot.total_boot_duration_seconds.toFixed(1)}s`;
  document.querySelector('#boot-mainpath-sec')!.textContent = `${boot.main_path_boot_seconds.toFixed(1)}s`;
  document.querySelector('#boot-logon-sec')!.textContent = `${boot.user_logon_wait_seconds.toFixed(1)}s`;
  document.querySelector('#boot-postboot-sec')!.textContent = `${boot.post_boot_delay_seconds.toFixed(1)}s`;

  document.querySelector('#boot-faststartup-val')!.textContent = boot.fast_startup_enabled ? '🟢 Aktiverad (Hiberboot)' : '🔴 Inaktiverad';
  document.querySelector('#boot-last-time-val')!.textContent = boot.last_boot_time || '-';
  document.querySelector('#boot-summary-val')!.textContent = boot.summary_text || '-';

  // Domain & Enterprise info
  const domainBadge = document.querySelector('#boot-domain-badge')!;
  domainBadge.className = `badge ${boot.is_domain_joined ? 'badge-ok' : 'badge-info'}`;
  domainBadge.textContent = boot.is_domain_joined ? 'Domänansluten' : 'Arbetsgrupp';

  document.querySelector('#boot-domain-name')!.textContent = boot.domain_name || 'WORKGROUP';
  document.querySelector('#boot-logonserver')!.textContent = boot.logon_server || (boot.is_domain_joined ? 'Lokal cache' : 'Lokal inloggning');
  document.querySelector('#boot-gpo-time')!.textContent = boot.gpo_total_time_ms > 0 ? `${boot.gpo_total_time_ms} ms` : (boot.is_domain_joined ? 'Ej uppmätt' : 'Lokal dator (Ingen GPO)');

  // Unreachable Resources Container
  const unContainer = document.querySelector('#boot-unreachable-container')!;
  if (boot.unreachable_resources && boot.unreachable_resources.length > 0) {
    unContainer.innerHTML = `
      <div style="font-weight:600; color:#ef4444; margin-bottom:8px; font-size:13px;">
        ⚠️ Upptäckta Onåbara Resurser (Orsak till inloggningstimeouter):
      </div>
      ${boot.unreachable_resources.map(un => `
        <div class="issue-card crit" style="margin-bottom:8px;">
          <div class="issue-left">
            <div class="issue-tag">[${escapeHtml(un.resource_type)}] ${escapeHtml(un.name)}</div>
            <div class="issue-title" style="color:#f87171;">❌ ${escapeHtml(un.target_unc)} (Port ${un.port})</div>
            <div class="issue-desc">${escapeHtml(un.impact_description)}</div>
          </div>
        </div>
      `).join('')}
    `;
  } else {
    unContainer.innerHTML = `
      <div style="padding: 10px 0; color: #34d399; font-size: 13px;">
        ✅ Inga onåbara nätverksenheter eller servrar identifierades. Alla resurser svarar normalt.
      </div>
    `;
  }

  // Degradation Culprits
  const degBadge = document.querySelector('#boot-deg-badge')!;
  const degCount = boot.boot_degradations ? boot.boot_degradations.length : 0;
  degBadge.textContent = `${degCount} identifierade`;
  degBadge.className = `badge ${degCount > 0 ? 'badge-warning' : 'badge-ok'}`;

  const degList = document.querySelector('#boot-degradations-list')!;
  if (boot.boot_degradations && boot.boot_degradations.length > 0) {
    degList.innerHTML = boot.boot_degradations.map(deg => `
      <div class="stat-row" style="align-items:center; padding:8px 0;">
        <span class="stat-label">
          <span class="badge badge-warning" style="font-size:10px; margin-right:6px;">${escapeHtml(deg.type)}</span>
          <strong>${escapeHtml(deg.name)}</strong>
        </span>
        <span class="stat-val" style="color:#f59e0b; font-weight:600;">+${deg.duration_ms} ms fördröjning</span>
      </div>
    `).join('');
  } else {
    degList.innerHTML = `<div style="padding:8px 0; color:var(--text-secondary);">Inga signifikanta fördröjningshändelser registrerade i Windows Eventlogg.</div>`;
  }

  // Startup Apps Manager
  const startupCountBadge = document.querySelector('#boot-startup-count')!;
  const startupItems = boot.startup_apps || [];
  startupCountBadge.textContent = `${startupItems.length} appar`;

  const startupTbody = document.querySelector('#boot-startup-tbody')!;
  if (startupItems.length > 0) {
    startupTbody.innerHTML = startupItems.map(app => `
      <tr>
        <td><strong>${escapeHtml(app.name)}</strong></td>
        <td><span class="badge badge-info" style="font-size:10px;">${escapeHtml(app.location)}</span></td>
        <td><span class="badge ${app.impact === 'High' ? 'badge-warning' : 'badge-ok'}">${app.impact || 'Normal'}</span></td>
        <td>
          <span class="badge ${app.enabled ? 'badge-ok' : 'badge-info'}">
            ${app.enabled ? '🟢 Aktiv' : '⚪ Avstängd'}
          </span>
        </td>
        <td>
          <button class="${app.enabled ? 'btn-danger-outline' : 'btn-success-outline'} btn-toggle-startup" 
                  data-name="${escapeHtml(app.name)}" 
                  data-loc="${escapeHtml(app.location)}" 
                  data-enabled="${app.enabled}">
            ${app.enabled ? 'Stäng av' : 'Aktivera'}
          </button>
        </td>
      </tr>
    `).join('');

    // Bind click handlers
    startupTbody.querySelectorAll<HTMLElement>('.btn-toggle-startup').forEach(btn => {
      btn.addEventListener('click', async () => {
        const name = btn.getAttribute('data-name');
        const loc = btn.getAttribute('data-loc') || 'HKCU';
        const isEnabled = btn.getAttribute('data-enabled') === 'true';
        if (name) {
          await handleToggleStartupApp(name, loc, !isEnabled);
        }
      });
    });
  } else {
    startupTbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-secondary);">Inga autostartprogram hittades i registret.</td></tr>`;
  }

  // WPR Status and Action Buttons
  const wprStatusText = document.querySelector('#boot-wpr-status-text')!;
  const wprBadge = document.querySelector('#boot-wpr-badge')!;
  const btnStartWprReboot = document.querySelector('#btn-start-wpr-reboot') as HTMLElement;
  const btnStartWprManual = document.querySelector('#btn-start-wpr-manual') as HTMLElement;
  const btnStopWpr = document.querySelector('#btn-stop-wpr') as HTMLElement;
  const btnOpenFolder = document.querySelector('#btn-open-trace-folder') as HTMLElement;
  const btnOpenWPA = document.querySelector('#btn-open-trace-wpa') as HTMLElement;
  const btnCancelWpr = document.querySelector('#btn-cancel-wpr') as HTMLElement;
  const btnClearTrace = document.querySelector('#btn-clear-trace') as HTMLElement;
  const wprRecordingBanner = document.querySelector('#boot-wpr-recording-banner') as HTMLElement;
  const wprResultsSection = document.querySelector('#boot-wpr-results-section') as HTMLElement;
  const wprDriversTbody = document.querySelector('#boot-wpr-drivers-tbody')!;

  if (boot.boot_trace) {
    wprStatusText.textContent = boot.boot_trace.status_message || 'Redo.';
    
    if (boot.boot_trace.is_recording) {
      wprBadge.className = 'badge badge-critical';
      wprBadge.textContent = '🔴 Spelar in';
      if (wprRecordingBanner) wprRecordingBanner.style.display = 'block';
      if (btnStartWprReboot) btnStartWprReboot.style.display = 'none';
      if (btnStartWprManual) btnStartWprManual.style.display = 'none';
      if (btnStopWpr) btnStopWpr.style.display = 'inline-flex';
      if (btnCancelWpr) btnCancelWpr.style.display = 'inline-flex';
      if (btnOpenFolder) btnOpenFolder.style.display = 'none';
      if (btnOpenWPA) btnOpenWPA.style.display = 'none';
      if (btnClearTrace) btnClearTrace.style.display = 'none';
    } else if (boot.boot_trace.is_configured) {
      wprBadge.className = 'badge badge-warning';
      wprBadge.textContent = '⚡ Schemalagd';
      if (wprRecordingBanner) wprRecordingBanner.style.display = 'none';
      if (btnStartWprReboot) btnStartWprReboot.style.display = 'none';
      if (btnStartWprManual) btnStartWprManual.style.display = 'none';
      if (btnStopWpr) btnStopWpr.style.display = 'none';
      if (btnCancelWpr) btnCancelWpr.style.display = 'inline-flex';
      if (btnOpenFolder) btnOpenFolder.style.display = 'none';
      if (btnOpenWPA) btnOpenWPA.style.display = 'none';
      if (btnClearTrace) btnClearTrace.style.display = 'none';
    } else if (boot.boot_trace.has_trace_data) {
      wprBadge.className = 'badge badge-ok';
      wprBadge.textContent = '✅ Analyserad';
      if (wprRecordingBanner) wprRecordingBanner.style.display = 'none';
      if (btnStartWprReboot) {
        btnStartWprReboot.style.display = 'inline-flex';
        btnStartWprReboot.innerHTML = '<span>🔄 Ny spårning & Starta om</span>';
      }
      if (btnStartWprManual) {
        btnStartWprManual.style.display = 'inline-flex';
        btnStartWprManual.innerHTML = '<span>⚡ Ny spårning utan omstart</span>';
      }
      if (btnStopWpr) btnStopWpr.style.display = 'none';
      if (btnCancelWpr) btnCancelWpr.style.display = 'none';
      if (btnOpenFolder) btnOpenFolder.style.display = 'inline-flex';
      if (btnOpenWPA) btnOpenWPA.style.display = boot.boot_trace.is_wpa_available ? 'inline-flex' : 'none';
      if (btnClearTrace) btnClearTrace.style.display = 'inline-flex';
    } else {
      wprBadge.className = 'badge badge-ok';
      wprBadge.textContent = 'Redo';
      if (wprRecordingBanner) wprRecordingBanner.style.display = 'none';
      if (btnStartWprReboot) {
        btnStartWprReboot.style.display = 'inline-flex';
        btnStartWprReboot.innerHTML = '<span>🚀 Schemalägg & Starta om datorn nu</span>';
      }
      if (btnStartWprManual) {
        btnStartWprManual.style.display = 'inline-flex';
        btnStartWprManual.innerHTML = '<span>⚡ Schemalägg utan omstart</span>';
      }
      if (btnStopWpr) btnStopWpr.style.display = 'none';
      if (btnCancelWpr) btnCancelWpr.style.display = 'none';
      if (btnOpenFolder) btnOpenFolder.style.display = 'none';
      if (btnOpenWPA) btnOpenWPA.style.display = 'none';
      if (btnClearTrace) btnClearTrace.style.display = 'none';
    }

    // Trace File info & Driver/Service table
    if (boot.boot_trace.has_trace_data && boot.boot_trace.trace_file_path) {
      if (wprResultsSection) wprResultsSection.style.display = 'block';
      const fpElem = document.querySelector('#boot-wpr-filepath');
      if (fpElem) fpElem.textContent = boot.boot_trace.trace_file_path;
      const fsElem = document.querySelector('#boot-wpr-filesize');
      if (fsElem) fsElem.textContent = boot.boot_trace.trace_file_size || '-';
      const tsElem = document.querySelector('#boot-wpr-timestamp');
      if (tsElem) tsElem.textContent = boot.boot_trace.trace_recorded_at || '';

      const drivers = [...(boot.boot_trace.slowest_drivers || []), ...(boot.boot_trace.slowest_services || [])];
      if (drivers.length > 0 && wprDriversTbody) {
        wprDriversTbody.innerHTML = drivers.map(d => `
          <tr>
            <td><strong>${escapeHtml(d.name)}</strong></td>
            <td><span class="badge badge-info">${escapeHtml(d.category)}</span></td>
            <td style="color:#38bdf8; font-weight:600;">${d.duration_ms} ms</td>
            <td style="max-width:300px; font-size:11px; word-break:break-all;"><code>${escapeHtml(d.path || '-')}</code></td>
          </tr>
        `).join('');
      }
    } else {
      if (wprResultsSection) wprResultsSection.style.display = 'none';
    }
  }

  // Autoruns Table
  cachedAutoruns = boot.advanced_autoruns || [];
  renderAutorunsTable(cachedAutoruns);
}

let cachedAutoruns: models.AdvancedAutorunsItem[] = [];

function renderAutorunsTable(items: models.AdvancedAutorunsItem[]) {
  const tbody = document.querySelector('#autoruns-tbody')!;
  const countBadge = document.querySelector('#autoruns-count-badge')!;
  countBadge.textContent = `${items.length} punkter`;

  if (items.length > 0) {
    tbody.innerHTML = items.map(item => `
      <tr>
        <td><span class="badge badge-info" style="font-size:10px;">${escapeHtml(item.category)}</span></td>
        <td><strong>${escapeHtml(item.name)}</strong></td>
        <td>${escapeHtml(item.publisher || '-')}</td>
        <td style="max-width:300px; font-size:11px; word-break:break-all;"><code>${escapeHtml(item.path)}</code></td>
        <td>
          <span class="badge ${item.sign_status === 'Verified' ? 'badge-ok' : 'badge-warning'}">
            ${item.sign_status === 'Verified' ? '✔ Verifierad' : '⚪ Okänd / 3:e part'}
          </span>
        </td>
      </tr>
    `).join('');
  } else {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-secondary);">Inga poster matchade sökningen.</td></tr>`;
  }
}

function filterAutoruns(query: string) {
  if (!query) {
    renderAutorunsTable(cachedAutoruns);
    return;
  }
  const q = query.toLowerCase();
  const filtered = cachedAutoruns.filter(i => 
    i.name.toLowerCase().includes(q) ||
    i.category.toLowerCase().includes(q) ||
    i.publisher.toLowerCase().includes(q) ||
    i.path.toLowerCase().includes(q)
  );
  renderAutorunsTable(filtered);
}

async function handleToggleStartupApp(name: string, location: string, enable: boolean) {
  const verb = enable ? 'Aktiverar' : 'Inaktiverar';
  showToast(`${verb} autostart för "${name}"...`, 'info');
  try {
    const res = await ToggleStartupApp(name, location, enable);
    if (res.success) {
      showToast(res.message, 'success');
      runDiagnosticScan();
    } else {
      showToast(`Fel: ${res.message}`, 'error');
    }
  } catch (err: any) {
    showToast(`Kunde inte ändra autostart: ${err}`, 'error');
  }
}

// Execute Remediation Fix Action
async function executeFixAction(actionId: string) {
  const consoleElem = document.querySelector('#action-console') as HTMLElement;
  const consoleTitle = document.querySelector('#console-action-title')!;
  const consoleStatus = document.querySelector('#console-status-badge')!;
  const consoleOutput = document.querySelector('#console-output')!;

  switchTab('tab-fixes');
  consoleElem.classList.add('active');
  consoleTitle.textContent = `▶ Kör åtgärd: ${actionId}...`;
  consoleStatus.textContent = 'Körs...';
  consoleStatus.className = 'badge badge-warning';
  consoleOutput.innerHTML = `<div style="color:#94a3b8;">Triggar reparationskommandon i bakgrunden...</div>`;

  showToast('Startar snabbåtgärd...', 'info');

  try {
    const res = await ExecuteQuickFix(actionId);
    consoleTitle.textContent = `✔ ${res.title}`;
    consoleStatus.textContent = res.success ? 'Slutförd' : 'Varning';
    consoleStatus.className = res.success ? 'badge badge-ok' : 'badge badge-critical';

    const lines = res.output.map(l => `<div>${escapeHtml(l)}</div>`).join('');
    consoleOutput.innerHTML = `
      <div style="color: ${res.success ? '#34d399' : '#f87171'}; font-weight: 600; margin-bottom: 6px;">
        ${escapeHtml(res.message)}
      </div>
      ${lines}
    `;

    showToast(res.message, res.success ? 'success' : 'error');

    // Auto-refresh after 2 seconds
    setTimeout(() => {
      runDiagnosticScan();
    }, 2500);
  } catch (err: any) {
    consoleStatus.textContent = 'Fel';
    consoleStatus.className = 'badge badge-critical';
    consoleOutput.innerHTML = `<div style="color:#ef4444;">Fel under körning: ${err}</div>`;
    showToast(`Åtgärdsfel: ${err}`, 'error');
  }
}

// Toast Notifications
function showToast(message: string, type: 'success' | 'error' | 'info' = 'info') {
  const container = document.querySelector('#toast-container')!;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  let icon = 'ℹ️';
  if (type === 'success') icon = '✅';
  if (type === 'error') icon = '❌';

  toast.innerHTML = `<span>${icon}</span><span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(12px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function escapeHtml(str: string): string {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Initialise App
setupEvents();
runDiagnosticScan();
