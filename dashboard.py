"""
SOC Triage Dashboard - Simple web UI for viewing triage outputs.
Run this alongside the poller to see live triage results.
"""

import http.server
import json
import os
import re
from datetime import datetime
from pathlib import Path

from config import OUTPUTS_DIR

PORT = 8080


def get_triage_reports(limit: int = 10) -> list[dict]:
    """Get the most recent triage reports."""
    reports = []

    if not OUTPUTS_DIR.exists():
        return reports

    # Get all triage markdown files
    files = list(OUTPUTS_DIR.glob("triage_*.md"))

    # Sort by modification time (newest first)
    files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

    for filepath in files[:limit]:
        try:
            content = filepath.read_text(encoding='utf-8')

            # Parse the markdown content
            report = {
                'filename': filepath.name,
                'timestamp': datetime.fromtimestamp(filepath.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'incident_id': '',
                'alert_type': '',
                'status': '',
                'triage_output': '',
            }

            # Extract metadata from markdown
            for line in content.split('\n'):
                if line.startswith('**Incident ID:**'):
                    report['incident_id'] = line.replace('**Incident ID:**', '').strip()
                elif line.startswith('**Alert Type:**'):
                    report['alert_type'] = line.replace('**Alert Type:**', '').strip()
                elif line.startswith('**Status:**'):
                    report['status'] = line.replace('**Status:**', '').strip()

            # Extract JSON triage output
            json_match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
            if json_match:
                try:
                    report['triage_output'] = json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    report['triage_output'] = json_match.group(1)
            else:
                # Just get the triage output section
                if '## Triage Output' in content:
                    report['triage_output'] = content.split('## Triage Output')[-1].strip()

            reports.append(report)
        except Exception as e:
            print(f"Error reading {filepath}: {e}")

    return reports


def generate_html() -> str:
    """Generate the dashboard HTML."""
    reports = get_triage_reports(limit=10)

    # Build report cards
    def get_field(d: dict, *keys, default=None):
        """Get field by trying multiple key variations (snake_case, Title Case, etc.)."""
        for key in keys:
            if key in d:
                return d[key]
        return default

    cards_html = ""
    for report in reports:
        triage = report['triage_output']

        if isinstance(triage, dict):
            # Format the structured output (handle both snake_case and Title Case)
            summary = get_field(triage, 'executive_summary', 'Executive Summary', default=[])
            if isinstance(summary, list):
                summary = '<br>'.join(f"• {s}" for s in summary)

            entities = get_field(triage, 'key_entities', 'Key Entities', default={})
            users = get_field(entities, 'users', 'Users', default=[])
            ips = get_field(entities, 'ips', 'IPs', default=[])
            # Handle case where value is a string like "Not provided" instead of a list
            if isinstance(users, str):
                users = [users] if users and users.lower() != 'not provided' else []
            if isinstance(ips, str):
                ips = [ips] if ips and ips.lower() != 'not provided' else []

            mitre = get_field(triage, 'mitre_mapping', 'MITRE Mapping', 'mitre', default={})
            tactics = get_field(mitre, 'tactics', 'Tactics', default=[])
            techniques = get_field(mitre, 'techniques', 'Techniques', default=[])

            actions = get_field(triage, 'immediate_containment_actions', 'Immediate Containment Actions', default=[])
            if isinstance(actions, list):
                actions = '<br>'.join(f"• {a}" for a in actions)

            confidence = get_field(triage, 'confidence_score', 'Confidence Score', default='N/A')

            triage_html = f"""
            <div class="triage-content">
                <div class="section">
                    <h4>Summary</h4>
                    <p>{summary}</p>
                </div>
                <div class="section">
                    <h4>Key Entities</h4>
                    <p><strong>Users:</strong> {', '.join(users) if users else 'None'}</p>
                    <p><strong>IPs:</strong> {', '.join(ips) if ips else 'None'}</p>
                </div>
                <div class="section">
                    <h4>MITRE ATT&CK</h4>
                    <p><strong>Tactics:</strong> {', '.join(tactics) if tactics else 'None'}</p>
                    <p><strong>Techniques:</strong> {', '.join(techniques) if techniques else 'None'}</p>
                </div>
                <div class="section">
                    <h4>Immediate Actions</h4>
                    <p>{actions}</p>
                </div>
                <div class="confidence">
                    Confidence: <strong>{confidence}</strong>/100
                </div>
            </div>
            """
        else:
            triage_html = f"<pre>{triage}</pre>"

        # Severity color
        alert_type = report['alert_type']
        severity_class = 'severity-medium'
        if 'high' in str(report).lower():
            severity_class = 'severity-high'
        elif 'low' in str(report).lower() or 'info' in str(report).lower():
            severity_class = 'severity-low'

        cards_html += f"""
        <div class="card {severity_class}">
            <div class="card-header">
                <span class="alert-type">{alert_type}</span>
                <span class="timestamp">{report['timestamp']}</span>
            </div>
            <div class="incident-id">Incident: {report['incident_id'][:20]}...</div>
            {triage_html}
        </div>
        """

    if not cards_html:
        cards_html = """
        <div class="no-reports">
            <h3>No triage reports yet</h3>
            <p>Run the poller with triage to generate reports:</p>
            <code>python incident_poller.py --triage</code>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="5">
    <title>SOC Triage Dashboard</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            padding: 20px;
            min-height: 100vh;
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border-radius: 10px;
            border: 1px solid #2a2a4a;
        }}
        .header h1 {{
            color: #00d4ff;
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .header p {{
            color: #888;
            font-size: 0.9em;
        }}
        .status-bar {{
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 15px;
        }}
        .status-item {{
            background: #1a1a2e;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.85em;
        }}
        .status-item.live {{
            color: #00ff88;
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
        }}
        .cards {{
            display: grid;
            gap: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }}
        .card {{
            background: #12121a;
            border-radius: 10px;
            padding: 20px;
            border-left: 4px solid #666;
            transition: transform 0.2s;
        }}
        .card:hover {{
            transform: translateX(5px);
        }}
        .severity-high {{
            border-left-color: #ff4757;
        }}
        .severity-medium {{
            border-left-color: #ffa502;
        }}
        .severity-low {{
            border-left-color: #2ed573;
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .alert-type {{
            background: #2a2a4a;
            color: #00d4ff;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.85em;
        }}
        .incident-id {{
            color: #888;
            font-size: 0.8em;
            margin-bottom: 15px;
            font-family: monospace;
        }}
        .triage-content {{
            display: grid;
            gap: 15px;
        }}
        .section {{
            background: #1a1a2e;
            padding: 12px;
            border-radius: 8px;
        }}
        .section h4 {{
            color: #00d4ff;
            font-size: 0.9em;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .section p {{
            font-size: 0.9em;
            line-height: 1.6;
        }}
        .confidence {{
            text-align: right;
            color: #00ff88;
            font-size: 0.9em;
            padding-top: 10px;
            border-top: 1px solid #2a2a4a;
        }}
        .no-reports {{
            text-align: center;
            padding: 60px 20px;
            background: #12121a;
            border-radius: 10px;
        }}
        .no-reports h3 {{
            color: #666;
            margin-bottom: 15px;
        }}
        .no-reports code {{
            background: #1a1a2e;
            padding: 10px 20px;
            border-radius: 5px;
            display: inline-block;
            margin-top: 10px;
            color: #00d4ff;
        }}
        pre {{
            background: #1a1a2e;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.85em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SOC Triage Dashboard</h1>
        <p>AI-Powered Security Incident Triage</p>
        <div class="status-bar">
            <span class="status-item live">Auto-refresh: 5s</span>
            <span class="status-item">{len(reports)} Reports</span>
            <span class="status-item">{datetime.now().strftime('%H:%M:%S')}</span>
        </div>
    </div>
    <div class="cards">
        {cards_html}
    </div>
</body>
</html>"""

    return html


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the dashboard."""

    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(generate_html().encode())
        elif self.path == '/api/reports':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            reports = get_triage_reports()
            self.wfile.write(json.dumps(reports, indent=2).encode())
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        # Suppress request logging for cleaner output
        pass


def main():
    print(f"""
============================================================
           SOC Triage Dashboard
============================================================
  Open in browser: http://localhost:{PORT}
  Auto-refreshes every 5 seconds
  Press Ctrl+C to stop
============================================================
""")

    server = http.server.HTTPServer(('localhost', PORT), DashboardHandler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
        server.shutdown()


if __name__ == "__main__":
    main()
