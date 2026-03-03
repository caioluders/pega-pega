# pega-pega

Multi-protocol request logger and catcher. Think Responder meets Burp Collaborator — listens on 14 protocols, logs every incoming request, and displays them in a rich terminal UI and web dashboard.

```
  ____  _____ ____    _        ____  _____ ____    _
 |  _ \| ____/ ___|  / \      |  _ \| ____/ ___|  / \
 | |_) |  _|| |  _  / _ \ ____| |_) |  _|| |  _  / _ \
 |  __/| |__| |_| |/ ___ \____|  __/| |__| |_| |/ ___ \
 |_|   |_____\____/_/   \_\   |_|   |_____\____/_/   \_\
```

## Protocols

| Protocol | Port | What's captured |
|----------|------|-----------------|
| HTTP | 80 | Method, path, headers, body, query params |
| HTTPS | 443 | Same as HTTP (auto-generated wildcard cert) |
| DNS | 53 | Query name, type — responds with your IP |
| FTP | 21 | Credentials, commands |
| SMTP | 25 | EHLO, AUTH creds, envelope, mail body |
| POP3 | 110 | Login credentials |
| IMAP | 143 | Login credentials, commands |
| SSH | 22 | Password and pubkey auth attempts |
| Telnet | 23 | Login credentials, raw input |
| LDAP | 389 | Bind DN/credentials, search queries |
| MySQL | 3306 | Username, database, auth data |
| Raw TCP | 9999 | Hex dump of anything |
| SNMP | 161 | Community strings, OIDs |
| Syslog | 514 | Facility, severity, message |

All handlers return **realistic responses** to encourage clients to send full payloads.

## Features

- **Subdomain tracking** — DNS responds with your IP for all queries, HTTP extracts subdomain from Host header
- **Rich terminal UI** — color-coded live table with protocol tags
- **Web dashboard** — real-time updates via WebSocket, filtering, search, hex viewer (port 8443)
- **SQLite persistence** — all captured requests stored and queryable
- **Configurable** — YAML config to enable/disable protocols, remap ports, set bind addresses

## Install

```bash
git clone https://github.com/caioluders/pega-pega.git
cd pega-pega
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

```bash
# Run all protocols (needs root for ports < 1024)
sudo pega-pega

# Run specific protocols
pega-pega -p http,dns,ftp

# Custom domain and response IP
pega-pega -d yourdomain.com -r 1.2.3.4

# Custom config file
pega-pega -c config.default.yaml

# High ports for unprivileged testing
pega-pega -p http,raw_tcp -c my-config.yaml

# Disable web dashboard
pega-pega --no-dashboard
```

### CLI options

```
  -c, --config PATH        Path to config YAML file
  -b, --bind IP            IP to bind all listeners (default: 0.0.0.0)
  -d, --domain DOMAIN      Base domain for subdomain tracking
  -r, --response-ip IP     IP to return in DNS responses (auto-detect if not set)
  --dashboard-port PORT    Web dashboard port (default: 8443)
  --db PATH                SQLite database path
  --no-dashboard           Disable web dashboard
  -p, --protocols LIST     Comma-separated list of protocols to enable
  -v, --verbose            Verbose logging
```

## Deploy to a server

```bash
./deploy.sh root@your-server-ip
./deploy.sh root@your-server-ip --config my-config.yaml
```

The deploy script builds a wheel, uploads it via SCP, installs into `/opt/pega-pega`, deploys the config to `/etc/pega-pega/config.yaml`, and creates a systemd service.

After deploying, point your domain's DNS to the server:
- Set a wildcard A record: `*.yourdomain.com → server_ip`
- Or set an NS record so pega-pega handles DNS directly

## Configuration

See [`config.default.yaml`](config.default.yaml) for all options. Key settings:

```yaml
bind_ip: "0.0.0.0"
domain: "yourdomain.com"     # base domain for subdomain tracking
response_ip: ""              # IP for DNS responses (auto-detect if empty)
dashboard_port: 8443
db_path: "pega_pega.db"

protocols:
  http:
    enabled: true
    port: 80
  dns:
    enabled: true
    port: 53
  # ... see config.default.yaml for all 14 protocols
```

## Architecture

```
pega_pega/
├── models.py            # CapturedRequest dataclass, Protocol enum
├── bus.py               # Async fan-out event bus
├── store.py             # SQLite persistence
├── display.py           # Rich terminal live table
├── server.py            # Main orchestrator
├── cli.py               # Click CLI
├── certs.py             # Self-signed certificate generation
├── config.py            # YAML config loading
├── protocols/           # 14 protocol handlers
│   ├── base.py          # BaseProtocolHandler ABC
│   ├── http_handler.py
│   ├── dns_handler.py
│   ├── ssh_handler.py
│   └── ...
├── dashboard/           # FastAPI web dashboard
│   ├── app.py
│   └── templates/
└── utils/               # DNS/LDAP/SNMP wire-format parsers
```

Every protocol handler publishes `CapturedRequest` events to a central async event bus. Consumers (SQLite store, terminal display, WebSocket broadcaster) each subscribe independently.
