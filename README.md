# pega-pega

Multi-protocol request logger and catcher. Listens on **14 protocols**, logs every incoming request, and displays them in a web dashboard and terminal UI.

```
  ____  _____ ____    _        ____  _____ ____    _
 |  _ \| ____/ ___|  / \      |  _ \| ____/ ___|  / \
 | |_) |  _|| |  _  / _ \ ____| |_) |  _|| |  _  / _ \
 |  __/| |__| |_| |/ ___ \____|  __/| |__| |_| |/ ___ \
 |_|   |_____\____/_/   \_\   |_|   |_____\____/_/   \_\
```

## Screenshots

### Dashboard
<p align="center">
  <img src="screenshots/dashboard.png" alt="Dashboard" width="100%">
</p>

### Mock Endpoints
<p align="center">
  <img src="screenshots/mock.png" alt="Mock Endpoints" width="100%">
</p>

### Terminal UI
<p align="center">
  <img src="screenshots/cli.svg" alt="Terminal UI" width="100%">
</p>

## Install

```bash
curl -sSL https://raw.githubusercontent.com/caioluders/pega-pega/main/install.sh | sudo bash -s -- \
  --domain yourdomain.com \
  --ip 1.2.3.4 \
  --letsencrypt --email admin@yourdomain.com \
  --password s3cret
```

All flags are optional — running without arguments uses sensible defaults (domain `pega.local`, auto-detect IP, no auth).

After install, point a wildcard DNS record (`*.yourdomain.com`) to your server.

<details>
<summary>Install options</summary>

```
--domain, -d DOMAIN    Base domain for subdomain tracking (default: pega.local)
--ip, -i IP            Response IP for DNS queries (default: auto-detect)
--dashboard PORT       Web dashboard port (default: 8443)
--password PASS        Dashboard password (empty = no auth)
--letsencrypt          Enable Let's Encrypt SSL via certbot
--email, -e EMAIL      Email for Let's Encrypt
--no-service           Don't create systemd service
--update               Update existing installation
--uninstall            Remove completely
```
</details>

<details>
<summary>Service management</summary>

```bash
journalctl -u pega-pega -f          # live logs
systemctl restart pega-pega         # restart
vim /etc/pega-pega/config.yaml      # edit config

# update
curl -sSL https://raw.githubusercontent.com/caioluders/pega-pega/main/install.sh | sudo bash -s -- --update

# uninstall
curl -sSL https://raw.githubusercontent.com/caioluders/pega-pega/main/install.sh | sudo bash -s -- --uninstall
```
</details>

## Usage

```bash
sudo pega-pega                          # all protocols (needs root for ports < 1024)
pega-pega -p http,dns,ftp               # specific protocols only
pega-pega -d yourdomain.com -r 1.2.3.4  # custom domain and response IP
pega-pega --no-dashboard                # disable web dashboard
```

<details>
<summary>CLI options</summary>

```
-c, --config PATH        Path to config YAML
-b, --bind IP            Bind address (default: 0.0.0.0)
-d, --domain DOMAIN      Base domain for subdomain tracking
-r, --response-ip IP     IP for DNS responses (auto-detect if not set)
--dashboard-port PORT    Dashboard port (default: 8443)
--db PATH                SQLite database path
--no-dashboard           Disable web dashboard
-p, --protocols LIST     Comma-separated protocols to enable
-v, --verbose            Verbose logging
```
</details>

## Protocols

| Protocol | Port | What's captured |
|----------|------|-----------------|
| HTTP | 80 (+8080, 8888, 3000, 5000, 8000, 8081) | Method, path, headers, body |
| HTTPS | 443 (+4443, 9443) | Same as HTTP (auto-generated wildcard cert) |
| DNS | 53 | Query name, type — responds with your IP |
| FTP | 21 | Credentials, commands |
| SMTP | 25 | EHLO, AUTH, envelope, mail body |
| POP3 | 110 | Login credentials |
| IMAP | 143 | Login credentials, commands |
| SSH | 22 | Password and pubkey auth attempts |
| Telnet | 23 | Credentials, raw input |
| LDAP | 389 | Bind DN/credentials, search queries |
| MySQL | 3306 | Username, database, auth data |
| Raw TCP | 9999 | Hex dump of raw bytes |
| SNMP | 161 | Community strings, OIDs |
| Syslog | 514 | Facility, severity, message |

All handlers return **realistic responses** to encourage clients to send full payloads.

## Features

- **Web dashboard** — real-time updates via WebSocket, protocol filtering, search, hex viewer
- **Request actions** — per-request menu to block IP or delete individual entries, plus bulk clear
- **IP blocking** — blocked IPs are filtered from all views, counts, and stats
- **Subdomain tracking** — DNS resolves all subdomains to your IP, HTTP extracts subdomain from Host header
- **Dashboard auth** — optional password protection
- **Let's Encrypt** — automatic SSL certificates via certbot
- **SQLite persistence** — all requests stored and queryable
- **Configurable** — YAML config to enable/disable protocols, remap ports, set bind addresses

## Mock HTTP Endpoints

Define custom HTTP responses at `/mock` on the dashboard. Requests matching a mock rule get your configured response; they're still captured in the main log.

**Path patterns:**
- Exact: `/api/users`, `/health`
- Param wildcard: `/api/users/:id` — matches any single segment (`/api/users/123`)
- Star wildcard: `/static/*` — matches anything after prefix

**Method matching:** filter by GET, POST, PUT, DELETE, PATCH — or use ANY to match all methods.

**Custom responses:** set status code (200, 404, 500...), response body, Content-Type, and arbitrary headers per rule.

**Priority:** rules are evaluated top-down — first match wins. Drag to reorder in the UI. Rules can be toggled on/off without deleting.

## Configuration

See [`config.default.yaml`](config.default.yaml) for all options.

```yaml
bind_ip: "0.0.0.0"
domain: "yourdomain.com"
response_ip: ""              # auto-detect if empty
dashboard_port: 8443
dashboard_password: ""       # empty = no auth
db_path: "pega_pega.db"

protocols:
  http:
    enabled: true
    port: 80
    extra_ports: [8080, 8888, 3000, 5000, 8000, 8081]
  # ... 14 protocols total — see config.default.yaml
```

## Development

```bash
git clone https://github.com/caioluders/pega-pega.git
cd pega-pega
pip install -e .
sudo pega-pega
```

## Architecture

```
pega_pega/
├── models.py            # CapturedRequest, MockRule, Protocol enum
├── bus.py               # Async fan-out event bus
├── store.py             # SQLite persistence + blocked IPs
├── mock.py              # Mock rule matcher (path/method patterns → regex)
├── display.py           # Rich terminal live table
├── server.py            # Main orchestrator
├── cli.py               # Click CLI
├── config.py            # YAML config loading
├── certs.py             # Self-signed certificate generation
├── letsencrypt.py       # Let's Encrypt / certbot integration
├── protocols/           # 14 protocol handlers
│   ├── base.py          # BaseProtocolHandler ABC
│   ├── http_handler.py
│   ├── dns_handler.py
│   └── ...
├── dashboard/           # FastAPI web dashboard
│   ├── app.py
│   └── templates/
│       ├── index.html   # Main dashboard
│       ├── mock.html    # Mock rules page
│       └── login.html   # Login page
└── utils/               # DNS/LDAP/SNMP wire-format parsers
```

Every protocol handler publishes `CapturedRequest` events to a central async event bus. Consumers (SQLite store, terminal display, WebSocket broadcaster) each subscribe independently.
