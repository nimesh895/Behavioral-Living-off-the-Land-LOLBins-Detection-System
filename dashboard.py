"""Interactive SOC Analyst Web Dashboard for lolbins-detector.

Zero-dependency local HTTP server providing real-time alert triage, interactive
process lineage trees, ± 5–10 minute timeline inspection, and SOC playbooks.
"""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from pathlib import Path
import sys
import urllib.parse

from output.timeline import TimelineReconstructor
from storage.database import DatabaseManager
from utils.config import load_config
from utils.logger import setup_logger

logger = logging.getLogger("lolbins-detector.dashboard")


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LOLBins Detection System - SOC Analyst Triage Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&display=swap">
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --text-bright: #f0f6fc;
      --accent: #58a6ff;
      --critical: #f85149;
      --high: #d29922;
      --medium: #e3b341;
      --low: #3fb950;
      --code-bg: #090d13;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    h1 {
      font-size: 1.4rem;
      font-weight: 700;
      color: var(--text-bright);
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .badge-live {
      background: rgba(63, 185, 80, 0.15);
      color: var(--low);
      font-size: 0.75rem;
      padding: 3px 8px;
      border-radius: 12px;
      border: 1px solid rgba(63, 185, 80, 0.3);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .kpi-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px 20px;
    }
    .kpi-title { font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; letter-spacing: 0.5px; }
    .kpi-val { font-size: 1.8rem; font-weight: 700; color: var(--text-bright); margin-top: 4px; }
    .kpi-val.crit { color: var(--critical); }
    .kpi-val.high { color: var(--high); }

    .controls {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    input[type="text"], select {
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 14px;
      border-radius: 6px;
      font-size: 0.9rem;
      outline: none;
    }
    input[type="text"]:focus, select:focus { border-color: var(--accent); }
    input[type="text"] { flex-grow: 1; max-width: 400px; }

    .table-container {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow-x: auto;
    }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.88rem; }
    th {
      background: #1f242c;
      padding: 12px 16px;
      color: var(--text-muted);
      font-weight: 600;
      border-bottom: 1px solid var(--border);
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.5px;
    }
    td { padding: 12px 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    tr:hover td { background: rgba(88, 166, 255, 0.04); cursor: pointer; }

    .sev-pill {
      display: inline-block;
      font-size: 0.72rem;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .sev-critical { background: rgba(248, 81, 73, 0.2); color: #ff7b72; border: 1px solid rgba(248, 81, 73, 0.4); }
    .sev-high { background: rgba(210, 153, 34, 0.2); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.4); }
    .sev-medium { background: rgba(227, 179, 65, 0.2); color: #e3b341; border: 1px solid rgba(227, 179, 65, 0.4); }
    .sev-low { background: rgba(63, 185, 80, 0.2); color: #3fb950; border: 1px solid rgba(63, 185, 80, 0.4); }

    .code-cmd {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      background: var(--code-bg);
      padding: 3px 6px;
      border-radius: 4px;
      border: 1px solid rgba(255,255,255,0.06);
      max-width: 320px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      display: block;
    }

    /* Modal / Drawer */
    .drawer-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.7);
      backdrop-filter: blur(2px);
      display: none;
      justify-content: flex-end;
      z-index: 1000;
    }
    .drawer-overlay.active { display: flex; }
    .drawer {
      background: #12161f;
      width: 780px;
      max-width: 90vw;
      height: 100%;
      border-left: 1px solid var(--border);
      padding: 30px;
      overflow-y: auto;
      box-shadow: -10px 0 30px rgba(0,0,0,0.5);
    }
    .drawer-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 20px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    .btn-close {
      background: none;
      border: none;
      color: var(--text-muted);
      font-size: 1.5rem;
      cursor: pointer;
    }
    .section-title {
      font-size: 0.82rem;
      text-transform: uppercase;
      font-weight: 700;
      color: var(--text-muted);
      letter-spacing: 0.8px;
      margin: 24px 0 10px 0;
    }
    .tree-block, .cmd-full-block {
      font-family: 'JetBrains Mono', monospace;
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
      font-size: 0.82rem;
      color: #79c0ff;
      white-space: pre-wrap;
      overflow-x: auto;
    }
    .mitre-tag {
      background: rgba(88, 166, 255, 0.15);
      color: var(--accent);
      border: 1px solid rgba(88, 166, 255, 0.3);
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      margin-right: 6px;
    }
  </style>
</head>
<body>
  <header>
    <h1>
      🛡️ LOLBins Detection System
      <span class="badge-live">Live SOC Triage</span>
    </h1>
    <div style="font-size:0.85rem; color:var(--text-muted);">
      Host: <strong style="color:var(--text-bright);">ENDPOINT-MONITOR</strong> | Port: 8080
    </div>
  </header>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-title">Total Process Events</div>
      <div class="kpi-val" id="kpi-events">-</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Total Security Alerts</div>
      <div class="kpi-val" id="kpi-alerts">-</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Critical Severity</div>
      <div class="kpi-val crit" id="kpi-critical">-</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">High Severity</div>
      <div class="kpi-val high" id="kpi-high">-</div>
    </div>
  </div>

  <div class="controls">
    <input type="text" id="search-input" placeholder="Search by Rule, Image, PID, User, or Command Line...">
    <select id="severity-filter">
      <option value="all">All Severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
    </select>
  </div>

  <div class="table-container">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Rule ID / Name</th>
          <th>Process (PID)</th>
          <th>Security User</th>
          <th>Command Line</th>
          <th>Timestamp (UTC)</th>
        </tr>
      </thead>
      <tbody id="alerts-tbody">
        <tr><td colspan="6" style="text-align:center; padding: 24px;">Loading alert telemetry...</td></tr>
      </tbody>
    </table>
  </div>

  <!-- Incident Details Drawer -->
  <div class="drawer-overlay" id="drawer-overlay" onclick="closeDrawer(event)">
    <div class="drawer" onclick="event.stopPropagation()">
      <div class="drawer-header">
        <div>
          <span class="sev-pill" id="d-sev">-</span>
          <h2 id="d-rule-name" style="color:var(--text-bright); margin-top: 6px; font-size:1.25rem;">-</h2>
          <div id="d-rule-desc" style="color:var(--text-muted); font-size:0.85rem; margin-top:4px;">-</div>
        </div>
        <button class="btn-close" onclick="closeDrawer()">&times;</button>
      </div>

      <div class="section-title">MITRE ATT&CK Matrix</div>
      <div id="d-mitre"></div>

      <div class="section-title">Target Execution Context</div>
      <table style="width:100%; border:1px solid var(--border); border-radius:6px;">
        <tr><td style="color:var(--text-muted); width:30%;">Executable</td><td id="d-image" style="font-weight:600;"></td></tr>
        <tr><td style="color:var(--text-muted);">Process ID / PPID</td><td id="d-pid"></td></tr>
        <tr><td style="color:var(--text-muted);">Parent Executable</td><td id="d-parent"></td></tr>
        <tr><td style="color:var(--text-muted);">Security Account</td><td id="d-user"></td></tr>
        <tr><td style="color:var(--text-muted);">Integrity Level</td><td id="d-integrity"></td></tr>
      </table>

      <div class="section-title">Command Line Invocation</div>
      <div class="cmd-full-block" id="d-cmdline"></div>

      <div class="section-title">Reconstructed Process Lineage</div>
      <div class="tree-block" id="d-tree"></div>

      <div class="section-title">SOC Response Playbook</div>
      <div style="background:var(--card-bg); border:1px solid var(--border); border-radius:6px; padding:14px; font-size:0.85rem;">
        <p>1. <strong>Terminate Process</strong>: Isolate or terminate PID <span id="d-contain-pid"></span> immediately.</p>
        <p style="margin-top:6px;">2. <strong>Inspect Drop Directories</strong>: Check <code>%TEMP%</code>, <code>%APPDATA%</code>, and <code>%PROGRAMDATA%</code> for staged scripts.</p>
        <p style="margin-top:6px;">3. <strong>Network Quarantine</strong>: Check perimeter logs for outbound socket transfers around incident timestamp.</p>
      </div>
    </div>
  </div>

  <script>
    let allAlerts = [];

    async function loadData() {
      try {
        const statsRes = await fetch('/api/stats');
        const stats = await statsRes.json();
        document.getElementById('kpi-events').innerText = stats.total_events || 0;
        document.getElementById('kpi-alerts').innerText = stats.total_alerts || 0;

        const alertsRes = await fetch('/api/alerts');
        allAlerts = await alertsRes.json();

        let critCount = 0;
        let highCount = 0;
        allAlerts.forEach(a => {
          const s = (a.severity || '').toLowerCase();
          if (s === 'critical') critCount++;
          if (s === 'high') highCount++;
        });
        document.getElementById('kpi-critical').innerText = critCount;
        document.getElementById('kpi-high').innerText = highCount;

        renderTable();
      } catch (err) {
        console.error('Error fetching dashboard telemetry:', err);
      }
    }

    function renderTable() {
      const tbody = document.getElementById('alerts-tbody');
      const query = document.getElementById('search-input').value.toLowerCase();
      const sevFilter = document.getElementById('severity-filter').value.toLowerCase();

      const filtered = allAlerts.filter(a => {
        const matchSev = sevFilter === 'all' || (a.severity || '').toLowerCase() === sevFilter;
        const text = `${a.rule_id} ${a.rule_name} ${a.image} ${a.pid} ${a.user} ${a.command_line}`.toLowerCase();
        const matchText = !query || text.includes(query);
        return matchSev && matchText;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 24px; color:var(--text-muted);">No security alerts matching filter.</td></tr>';
        return;
      }

      tbody.innerHTML = filtered.map(a => {
        const sevClass = `sev-${(a.severity || 'low').toLowerCase()}`;
        return `
          <tr onclick="openDrawer('${a.alert_id}')">
            <td><span class="sev-pill ${sevClass}">${a.severity}</span></td>
            <td><strong>${a.rule_id}</strong><div style="font-size:0.75rem; color:var(--text-muted);">${a.rule_name}</div></td>
            <td><code>${a.image}</code> <span style="color:var(--text-muted); font-size:0.75rem;">(${a.pid})</span></td>
            <td>${a.user}</td>
            <td><span class="code-cmd">${a.command_line}</span></td>
            <td style="color:var(--text-muted); font-size:0.8rem;">${a.timestamp}</td>
          </tr>
        `;
      }).join('');
    }

    function openDrawer(alertId) {
      const alert = allAlerts.find(a => a.alert_id === alertId);
      if (!alert) return;

      const s = (alert.severity || 'low').toLowerCase();
      const sevPill = document.getElementById('d-sev');
      sevPill.className = `sev-pill sev-${s}`;
      sevPill.innerText = alert.severity;

      document.getElementById('d-rule-name').innerText = alert.rule_name;
      document.getElementById('d-rule-desc').innerText = alert.description;
      document.getElementById('d-image').innerText = alert.image;
      document.getElementById('d-pid').innerText = `${alert.pid} (PPID: ${alert.ppid})`;
      document.getElementById('d-parent').innerText = alert.parent_image;
      document.getElementById('d-user').innerText = alert.user;
      document.getElementById('d-integrity').innerText = alert.integrity_level;
      document.getElementById('d-cmdline').innerText = alert.command_line;
      document.getElementById('d-contain-pid').innerText = alert.pid;

      const mitreDiv = document.getElementById('d-mitre');
      const tags = (alert.mitre_attack || []).map(t => `<span class="mitre-tag">${t}</span>`).join('');
      mitreDiv.innerHTML = tags || '<span style="color:var(--text-muted);">N/A</span>';

      const tree = `${alert.parent_image} (PID: ${alert.ppid})\\n└── ${alert.image} (PID: ${alert.pid}) [TRIGGER]`;
      document.getElementById('d-tree').innerText = tree;

      document.getElementById('drawer-overlay').classList.add('active');
    }

    function closeDrawer() {
      document.getElementById('drawer-overlay').classList.remove('active');
    }

    document.getElementById('search-input').addEventListener('input', renderTable);
    document.getElementById('severity-filter').addEventListener('change', renderTable);

    loadData();
    setInterval(loadData, 5000);
  </script>
</body>
</html>
"""


class DashboardHTTPHandler(BaseHTTPRequestHandler):
    """HTTP Request handler serving API and modern dashboard UI."""

    db_manager: DatabaseManager

    def do_GET(self) -> None:
        """Handle incoming GET requests."""
        url_parts = urllib.parse.urlparse(self.path)
        path = url_parts.path

        if path in ("/", "/index.html"):
            self._send_html(DASHBOARD_HTML)
        elif path == "/api/stats":
            stats = self.db_manager.get_statistics()
            self._send_json(stats)
        elif path == "/api/alerts":
            alerts = self.db_manager.get_recent_alerts(limit=100)
            self._send_json(alerts)
        else:
            self.send_error(404, "Not Found")

    def _send_html(self, content: str) -> None:
        body = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, data: Any) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Quiet default console logging."""
        return


def run_dashboard_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Start local SOC dashboard server."""
    config = load_config()
    db = DatabaseManager(config.storage.database_path)

    DashboardHTTPHandler.db_manager = db

    server = ThreadingHTTPServer((host, port), DashboardHTTPHandler)
    print("\n" + "=" * 70)
    print(f"  🚀 LOLBins Detection System - Interactive SOC Analyst Dashboard")
    print(f"  Listening on: http://{host}:{port}/")
    print("=" * 70 + "\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_dashboard_server(port=port_arg)
