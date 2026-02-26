# 🍯 Lightweight HTTP-Based IoT Honeypot

A lightweight, HTTP-based IoT honeypot designed for cybersecurity research and education. The system simulates vulnerable IoT web interfaces to capture, classify, and visualize HTTP-based attacks in a controlled environment.

## Features

- **Multi-Vendor Persona System** — 10 switchable IoT device personas (Cisco, TP-Link, Netgear, D-Link, Hikvision, Dahua, Axis, etc.) with protocol-level deception
- **Dual-Mode Architecture** — Switch between Simulation Mode (safe classroom exercises) and Internet Mode (real-world traffic capture) without restart
- **Real-Time Dashboard** — Attack statistics, geographic map, attack distribution charts, and threat feed with 5-second auto-refresh
- **MITRE ATT&CK Classification** — Automatic attack categorization with technique IDs (T1110, T1190, T1059, T1083, T1595)
- **Interactive Simulation Lab** — Split-screen attacker/defender interface with 4 active countermeasures (IP Block, Rate Limit, Lockout, WAF)
- **Cyber Kill Chain Mission Mode** — Guided 4-phase attack exercise (Recon → Weaponize → Exploit → Success)
- **Threat Intelligence** — AbuseIPDB integration with local caching for IP reputation lookups
- **Email Alerts** — Real-time attack notifications and daily summary reports via Gmail SMTP
- **Data Export** — CSV/JSON export with optional IP anonymization for research sharing

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python 3, Flask |
| Database | SQLite with SQLAlchemy |
| Frontend | HTML5, CSS3 (Tailwind), JavaScript, Chart.js, Leaflet.js |
| Reverse Proxy | Nginx (ports 80/443) |
| Threat Intel | AbuseIPDB API |
| Deployment | VMware Workstation Pro |

## Architecture

```
Attacker (Kali VM) → Nginx (ports 80/443) → Flask (port 5000) → SQLite
                      ↓ SSL termination        ↓ Attack classification
                      ↓ Layer 1 rate limit      ↓ IP reputation lookup
                      ↓ X-Forwarded-For         ↓ Email alerts
                                                ↓ Dashboard/Logs
```

## Setup

### Prerequisites

- VMware Workstation Pro (or VirtualBox)
- Ubuntu 24.04.3 LTS (CLI) — Sensor VM (2GB RAM, 4 vCPU)
- Kali Linux — Attacker VM (optional, for penetration testing)
- Python 3.10+

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/iot-honeypot.git
cd iot-honeypot

# Install Python dependencies
pip install flask sqlalchemy requests

# Run the honeypot
python3 app.py
```

### Nginx Configuration (for HTTP/HTTPS)

```bash
# Copy the Nginx config
sudo cp honeypot_nginx.conf /etc/nginx/sites-available/honeypot
sudo ln -s /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx
```

### Optional: AbuseIPDB API Key

1. Register at [AbuseIPDB](https://www.abuseipdb.com/) (free tier: 1,000 queries/day)
2. Navigate to Settings page → AbuseIPDB Integration → Enter API key

## Usage

1. Access the honeypot at `http://<SENSOR_VM_IP>` (attacker-facing login page)
2. Access admin panel at `http://<SENSOR_VM_IP>/honeypot-admin` (default credentials in config)
3. Navigate using the sidebar: Dashboard, Attack Logs, Simulation Lab, Settings

### Deployment Modes

- **Simulation Mode** — Safe for classrooms. Use the built-in Simulation Lab for guided exercises.
- **Internet Mode** — For research. Exposes the honeypot to real network traffic with enhanced logging, stealth rate limiting, and email alerts.

## Project Structure

```
├── app.py                  # Main Flask application
├── internet_routes.py      # Internet Mode middleware and honey routes
├── lab_routes.py           # Simulation Lab backend
├── notifier.py             # Email notification system
├── honeypot_config.json    # Persisted configuration
├── honeypot_nginx.conf     # Nginx reverse proxy config
├── login.html              # Router admin login page
├── camera_login.html       # IP Camera NVR login page
├── dashboard.html          # Security dashboard
├── logs.html               # Historical attack logs
├── settings.html           # System configuration
├── simulation.html         # Simulation Lab landing page
├── interactive_lab.html    # Split-screen attacker/defender lab
├── mission_recon.html      # Mission Phase 1: Reconnaissance
├── mission_weapon.html     # Mission Phase 2: Weaponization
├── mission_success.html    # Mission Phase 4: Success
└── base.html               # Shared layout template
```

## Screenshots

| Dashboard | Interactive Lab |
|---|---|
| ![Dashboard](screenshots/dashboard.png) | ![Lab](screenshots/interactive_lab.png) |

## License

This project is licensed under the MIT License.

## Disclaimer

This tool is intended for **educational and authorized research purposes only**. Deploy only in isolated lab environments or with explicit authorization. The authors are not responsible for any misuse of this software.
