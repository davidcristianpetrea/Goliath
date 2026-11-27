#!/usr/bin/env bash
# Goliath Native LXC / Linux Installer (Zero Docker Required)
# Tested for Debian 12/13 & Ubuntu 22.04/24.04 (Proxmox LXC unprivileged & privileged).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR="/opt/goliath"
SERVICE_USER="goliath"
PORT="8787"
PROXY_PORT="8788"
TOOLS_PROFILE="standard"
ALLOW_PRIVATE_LLM="1"
NON_INTERACTIVE=0
PREBUILT_BIN=""
FROM_RELEASE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --tools) TOOLS_PROFILE="${2:-standard}"; shift 2 ;;
    --port) PORT="${2:-8787}"; shift 2 ;;
    --proxy-port) PROXY_PORT="${2:-8788}"; shift 2 ;;
    --install-dir) INSTALL_DIR="${2:-/opt/goliath}"; shift 2 ;;
    --allow-private-llm) ALLOW_PRIVATE_LLM="1"; shift ;;
    --no-private-llm) ALLOW_PRIVATE_LLM="0"; shift ;;
    --binary) PREBUILT_BIN="${2:-}"; shift 2 ;;
    --from-release) FROM_RELEASE=1; shift ;;
    -h|--help)
      cat <<EOF
Goliath Native LXC / Linux Installer (No Docker)

Options:
  --non-interactive       Use defaults without prompting
  --tools <profile>       minimal | standard (default) | full | none
  --port <port>           Web UI port (default: 8787)
  --proxy-port <port>     MITM proxy port (default: 8788)
  --install-dir <path>    Install directory (default: /opt/goliath)
  --allow-private-llm     Allow LAN/localhost LLM endpoints (default)
  --no-private-llm        Restrict LLM endpoints to public IPs only
  --binary <path>         Use a prebuilt goliath binary instead of compiling
  --from-release          Download latest GitHub release binary (falls back to source build)
EOF
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
die(){  printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
rand(){ head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24; }
ask(){
  local p="$1" d="${2:-}" a
  if [[ "$NON_INTERACTIVE" -eq 1 ]]; then echo "$d"; return; fi
  read -rp "$p${d:+ [$d]}: " a
  echo "${a:-$d}"
}

[[ $EUID -eq 0 ]] || die "Run as root inside your LXC container or Linux host."

if grep -qa 'container=lxc' /proc/1/environ 2>/dev/null || [[ -f /run/systemd/container ]]; then
  info "LXC container environment detected — applying LXC-safe systemd & PostgreSQL setup."
fi

if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
  echo "========================================"
  echo "  Goliath Native LXC / Linux Installer"
  echo "========================================"
  INSTALL_DIR="$(ask 'Install directory' "$INSTALL_DIR")"
  PORT="$(ask 'Web UI port' "$PORT")"
  PROXY_PORT="$(ask 'MITM proxy port' "$PROXY_PORT")"
  TOOLS_PROFILE="$(ask 'Pentest toolset profile (minimal|standard|full|none)' "$TOOLS_PROFILE")"
  ALLOW_PRIVATE_LLM="$(ask 'Allow private/LAN LLM endpoints like local Ollama/NIM? (1=yes, 0=no)' "$ALLOW_PRIVATE_LLM")"
fi

export DEBIAN_FRONTEND=noninteractive
info "Installing base OS packages & PostgreSQL..."
apt-get update -qq
apt-get install -y --no-install-recommends \
  ca-certificates curl wget gnupg git jq unzip xz-utils ripgrep \
  postgresql postgresql-contrib sudo

info "Ensuring PostgreSQL is running..."
systemctl enable --now postgresql || service postgresql start

DB_PASS="$(rand)"
DB_USER="goliath"
DB_NAME="goliath"

if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1; then
  sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}' NOSUPERUSER NOCREATEDB NOCREATEROLE;"
  ok "Created PostgreSQL role '${DB_USER}'"
else
  info "PostgreSQL role '${DB_USER}' already exists (preserving existing password if config.json exists)"
fi

if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
  sudo -u postgres createdb --owner="${DB_USER}" "${DB_NAME}"
  ok "Created PostgreSQL database '${DB_NAME}'"
fi

install -d -o root -g root -m 0755 "$INSTALL_DIR"
install -d -o root -g root -m 0755 "$INSTALL_DIR/data"
install -d -o root -g root -m 0700 "$INSTALL_DIR/keys"
install -d -o root -g root -m 0755 "$INSTALL_DIR/skills"

if [[ -d "$REPO_DIR/skills" ]]; then
  cp -rn "$REPO_DIR/skills/." "$INSTALL_DIR/skills/"
  chown -R root:root "$INSTALL_DIR/skills"
  find "$INSTALL_DIR/skills" -type d -exec chmod 0755 {} +
  find "$INSTALL_DIR/skills" -type f -exec chmod 0644 {} +
  ok "Installed built-in skills to $INSTALL_DIR/skills"
fi

if [[ ! -f "$INSTALL_DIR/config.json" ]]; then
  cat > "$INSTALL_DIR/config.json" <<JSON
{
  "database": {
    "host": "127.0.0.1",
    "port": 5432,
    "user": "${DB_USER}",
    "password": "${DB_PASS}",
    "dbname": "${DB_NAME}",
    "sslmode": "disable"
  }
}
JSON
  chown root:root "$INSTALL_DIR/config.json"
  chmod 0600 "$INSTALL_DIR/config.json"
  ok "Generated $INSTALL_DIR/config.json"
else
  chown root:root "$INSTALL_DIR/config.json"
  chmod 0600 "$INSTALL_DIR/config.json"
  info "Preserving existing $INSTALL_DIR/config.json"
fi

# Build or install binary
if [[ -z "$PREBUILT_BIN" && "$FROM_RELEASE" -eq 1 ]]; then
  ARCH_RAW="$(uname -m)"
  case "$ARCH_RAW" in
    x86_64|amd64) RARCH="amd64" ;;
    aarch64|arm64) RARCH="arm64" ;;
    *) RARCH="amd64" ;;
  esac
  REL_URL="https://github.com/davidcristianpetrea/Goliath/releases/latest/download/goliath-linux-${RARCH}.zip"
  info "Attempting to download release binary ($REL_URL)..."
  REL_TMP="$(mktemp -d)"
  if curl -fsSL "$REL_URL" -o "$REL_TMP/goliath.zip" && unzip -q -o "$REL_TMP/goliath.zip" -d "$REL_TMP/out"; then
    FOUND_BIN="$(find "$REL_TMP/out" -type f -name goliath | head -n1 || true)"
    if [[ -n "$FOUND_BIN" ]]; then
      PREBUILT_BIN="$FOUND_BIN"
      ok "Downloaded prebuilt release binary."
    fi
  else
    warn "No matching release asset found yet; falling back to source build."
  fi
fi

if [[ -n "$PREBUILT_BIN" ]]; then
  install -o root -g root -m 0755 "$PREBUILT_BIN" "$INSTALL_DIR/goliath"
  rm -rf "${REL_TMP:-}" 2>/dev/null || true
else
  # Ensure Node >= 20
  NEED_NODE=1
  if command -v node >/dev/null 2>&1; then
    NODE_MAJ="$(node -v | sed 's/^v//' | cut -d. -f1)"
    [[ "$NODE_MAJ" -ge 20 ]] && NEED_NODE=0
  fi
  if [[ "$NEED_NODE" -eq 1 ]]; then
    info "Installing Node.js 22 LTS..."
    ARCH_RAW="$(uname -m)"
    case "$ARCH_RAW" in
      x86_64|amd64) NARCH="x64" ;;
      aarch64|arm64) NARCH="arm64" ;;
      *) die "Unsupported arch: $ARCH_RAW" ;;
    esac
    curl -fsSL "https://nodejs.org/dist/v22.23.4/node-v22.23.4-linux-${NARCH}.tar.xz" -o /tmp/node.tar.xz
    tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --no-same-owner
    rm -f /tmp/node.tar.xz
  fi

  # Ensure Go 1.26.11
  NEED_GO=1
  if command -v go >/dev/null 2>&1; then
    if go version | grep -qE 'go1\.(2[6-9]|[3-9][0-9])'; then
      NEED_GO=0
    fi
  fi
  if [[ "$NEED_GO" -eq 1 ]]; then
    info "Installing Go 1.26.11..."
    ARCH_RAW="$(uname -m)"
    case "$ARCH_RAW" in
      x86_64|amd64) GARCH="amd64" ;;
      aarch64|arm64) GARCH="arm64" ;;
      *) die "Unsupported arch: $ARCH_RAW" ;;
    esac
    curl -fsSL "https://go.dev/dl/go1.26.11.linux-${GARCH}.tar.gz" -o /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:$PATH"
  fi

  info "Building Goliath web UI & Go binary..."
  cd "$REPO_DIR"
  (cd web && npm ci --ignore-scripts && npm run build:static)
  rm -rf server/webui/dist && mkdir -p server/webui && cp -r web/out server/webui/dist
  CGO_ENABLED=0 go build -tags embedui -trimpath -o "$INSTALL_DIR/goliath.new" ./cmd/artex
  mv -f "$INSTALL_DIR/goliath.new" "$INSTALL_DIR/goliath"
  chown root:root "$INSTALL_DIR/goliath"
  chmod 0755 "$INSTALL_DIR/goliath"
  ok "Built and installed $INSTALL_DIR/goliath"
fi

# Install pentest tools
bash "$REPO_DIR/scripts/install-tools.sh" --profile "$TOOLS_PROFILE"

# Install LXC-safe systemd unit (runs as root so executor processes drop cleanly to UID/GID 10001)
cat > /etc/systemd/system/goliath.service <<UNIT
[Unit]
Description=Goliath Autonomous Penetration Testing Platform
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/goliath
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

Environment=GOLIATH_ADDR=0.0.0.0:${PORT}
Environment=GOLIATH_PORT=${PORT}
Environment=GOLIATH_PROXY_ADDR=127.0.0.1:${PROXY_PORT}
Environment=GOLIATH_PROXY_PORT=${PROXY_PORT}
Environment=GOLIATH_JWT_KEY_DIR=${INSTALL_DIR}/keys
Environment=GOLIATH_LLM_ALLOW_PRIVATE=${ALLOW_PRIVATE_LLM}
Environment=NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates
Environment=DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true

# LXC-compatible hardening (omits PrivateTmp which fails in unprivileged LXCs without nesting)
NoNewPrivileges=yes
UMask=0022

[Install]
WantedBy=multi-user.target
UNIT

# Install goliath-ctl helper
cat > /usr/local/bin/goliath-ctl <<CTL
#!/usr/bin/env bash
set -euo pipefail
case "\${1:-status}" in
  start|stop|restart|status) systemctl "\$1" goliath ;;
  logs) journalctl -u goliath -f -n 100 ;;
  setup-token) journalctl -u goliath --no-pager | grep -i "Setup token" | tail -n 5 || true ;;
  doctor)
    echo "=== Service ==="
    systemctl is-active goliath || true
    echo "=== Database ==="
    systemctl is-active postgresql || true
    echo "=== Installed Security Tools ==="
    for b in nmap nuclei httpx subfinder katana ffuf dalfox sqlmap bbot hydra john curl python3 jq rg dig whois nc; do
      if command -v "\$b" >/dev/null 2>&1; then
        printf "  [OK]   %-12s %s\n" "\$b" "\$(command -v "\$b")"
      else
        printf "  [MISS] %-12s\n" "\$b"
      fi
    done
    ;;
  backup)
    ts="\$(date +%Y%m%d-%H%M%S)"
    out="/root/goliath-backup-\${ts}.sql"
    sudo -u postgres pg_dump "${DB_NAME}" > "\$out"
    echo "Database backed up to \$out"
    ;;
  trust-ca)
    ca_file="\$(find "${INSTALL_DIR}/data" -maxdepth 3 -type f \( -name 'ca.crt' -o -name 'ca.pem' \) | head -n1 || true)"
    if [[ -z "\$ca_file" ]]; then
      echo "No MITM CA certificate found under ${INSTALL_DIR}/data yet (start a task with traffic capture enabled first)."
      exit 1
    fi
    cp "\$ca_file" /usr/local/share/ca-certificates/goliath-mitm.crt
    update-ca-certificates
    echo "Installed Goliath MITM CA into system trust store."
    ;;
  update)
    src="${REPO_DIR}"
    if [[ ! -d "\$src/.git" ]]; then
      echo "Source checkout not found at \$src"
      exit 1
    fi
    cd "\$src"
    git pull --ff-only
    (cd web && npm ci --ignore-scripts && npm run build:static)
    rm -rf server/webui/dist && mkdir -p server/webui && cp -r web/out server/webui/dist
    CGO_ENABLED=0 go build -tags embedui -trimpath -o "${INSTALL_DIR}/goliath.new" ./cmd/artex
    cp -f "${INSTALL_DIR}/goliath" "${INSTALL_DIR}/goliath.prev" 2>/dev/null || true
    mv -f "${INSTALL_DIR}/goliath.new" "${INSTALL_DIR}/goliath"
    chown root:root "${INSTALL_DIR}/goliath"
    chmod 0755 "${INSTALL_DIR}/goliath"
    if [[ -d "\$src/skills" ]]; then
      mkdir -p "${INSTALL_DIR}/skills"
      cp -rn "\$src/skills/." "${INSTALL_DIR}/skills/"
      chown -R root:root "${INSTALL_DIR}/skills"
      find "${INSTALL_DIR}/skills" -type d -exec chmod 0755 {} +
      find "${INSTALL_DIR}/skills" -type f -exec chmod 0644 {} +
    fi
    systemctl restart goliath
    sleep 3
    if ! systemctl is-active --quiet goliath; then
      echo "Restart failed! Rolling back to previous binary..."
      mv -f "${INSTALL_DIR}/goliath.prev" "${INSTALL_DIR}/goliath"
      systemctl restart goliath
      exit 1
    fi
    echo "Goliath updated and running."
    ;;
  *)
    echo "Usage: goliath-ctl {start|stop|restart|status|logs|setup-token|doctor|backup|trust-ca|update}"
    exit 1
    ;;
esac
CTL
chmod 0755 /usr/local/bin/goliath-ctl

systemctl daemon-reload
systemctl enable --now goliath
sleep 2

IP_ADDR="$(hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1')"
ok "Goliath is running!"
echo ""
echo "  Web UI:      http://${IP_ADDR}:${PORT}"
echo "  MITM Proxy:  ${IP_ADDR}:${PROXY_PORT}"
echo "  Control CLI: goliath-ctl {status|logs|setup-token|doctor|backup}"
echo ""
echo "Initial setup token (if first run):"
journalctl -u goliath --no-pager -n 40 | grep -i "Setup token" || echo "  Run 'goliath-ctl setup-token' in a few seconds."
