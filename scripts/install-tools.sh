#!/usr/bin/env bash
# Goliath native Linux tool installer (no Docker).
# Installs pinned, checksum-verified security tools onto Debian 12/13 or Ubuntu 22.04/24.04.
#
# Usage:
#   sudo bash scripts/install-tools.sh [--profile minimal|standard|full|none]
set -euo pipefail

PROFILE="standard"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="${2:-standard}"; shift 2 ;;
    --profile=*) PROFILE="${1#*=}"; shift ;;
    -h|--help)
      echo "Usage: $0 [--profile minimal|standard|full|none]"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

case "$PROFILE" in
  none)
    echo "[*] Skipping security tool installation (--profile none)"
    exit 0
    ;;
  minimal|standard|full) ;;
  *) echo "[x] Invalid profile: $PROFILE (expected minimal|standard|full|none)" >&2; exit 1 ;;
esac

if [[ $EUID -ne 0 ]]; then
  echo "[x] Please run as root (sudo bash scripts/install-tools.sh)" >&2
  exit 1
fi

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok(){   printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "[x] Unsupported architecture: $ARCH_RAW" >&2; exit 1 ;;
esac

export DEBIAN_FRONTEND=noninteractive
info "Installing minimal CLI & Python tooling ($ARCH)..."
apt-get update -qq
apt-get install -y --no-install-recommends \
  ca-certificates curl wget git jq unzip xz-utils ripgrep \
  dnsutils iputils-ping netcat-openbsd whois nmap sqlite3 \
  python3 python3-venv python3-pip

# Install core Python HTTP/parsing libs into a dedicated venv or system packages
apt-get install -y --no-install-recommends \
  python3-requests python3-bs4 python3-lxml python3-urllib3 python3-yaml 2>/dev/null || true

if [[ "$PROFILE" == "minimal" ]]; then
  ok "Minimal toolset installed."
  exit 0
fi

# Pinned ProjectDiscovery & recon binaries (matching upstream Dockerfile digests)
NUCLEI_VERSION="3.11.1"
NUCLEI_SHA256_AMD64="ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6"
NUCLEI_SHA256_ARM64="8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07"

HTTPX_VERSION="1.12.0"
HTTPX_SHA256_AMD64="9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76"
HTTPX_SHA256_ARM64="fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e"

SUBFINDER_VERSION="2.17.0"
SUBFINDER_SHA256_AMD64="a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37"
SUBFINDER_SHA256_ARM64="24913d49dddc1d3a5e99a4a7580da5be980959b9415b96f52c4f7f4124392190"

KATANA_VERSION="1.8.0"
KATANA_SHA256_AMD64="cb027ae99d0757061b70c07a15c7a80f62c5a535ab52c4a329f80c4b0a7309d2"
KATANA_SHA256_ARM64="80e269210727a855511ffac8dfb01297b2344742acec71a35e8ba4a67a90f0f2"

FFUF_VERSION="2.3.0"
FFUF_SHA256_AMD64="b2a3c725fcb9da175159682f54d6e9149f2905b00d84d155e7efc5d599975ceb"
FFUF_SHA256_ARM64="e2d712615d53da797ee929006e41f2df5a7960a5353133db9c150ddaa22ae4e8"

DALFOX_VERSION="3.2.4"
DALFOX_SHA256_AMD64="c11cfd2f8261973f0a2a2a1eba5a147ce77712a29acfa6343f9847fb8bb7eca2"
DALFOX_SHA256_ARM64="fd56b0b7da2d06868cd73b504f41d21314629feffcd5bdc97718db1c9dd2fa70"

SQLMAP_COMMIT="cceda39208b5aa4f7f0fd36559a9114cb9e3281d"

install_zip_bin() {
  local name="$1" url="$2" sha="$3" bin_name="${4:-$1}"
  local tmpdir
  tmpdir="$(mktemp -d)"
  info "Downloading $name..."
  if curl -fsSL "$url" -o "$tmpdir/pkg.zip"; then
    local got
    got="$(sha256sum "$tmpdir/pkg.zip" | cut -d' ' -f1)"
    if [[ "$got" != "$sha" ]]; then
      warn "SHA-256 mismatch for $name (want $sha, got $got) — skipping"
      rm -rf "$tmpdir"
      return 1
    fi
    unzip -q -o "$tmpdir/pkg.zip" -d "$tmpdir/out"
    local found
    found="$(find "$tmpdir/out" -type f -name "$bin_name" | head -n1 || true)"
    if [[ -n "$found" ]]; then
      install -m 0755 "$found" "/usr/local/bin/$bin_name"
      ok "Installed $bin_name"
    else
      warn "Binary $bin_name not found inside archive"
    fi
  else
    warn "Failed to download $name from $url"
  fi
  rm -rf "$tmpdir"
}

install_tar_bin() {
  local name="$1" url="$2" sha="$3" bin_name="${4:-$1}"
  local tmpdir
  tmpdir="$(mktemp -d)"
  info "Downloading $name..."
  if curl -fsSL "$url" -o "$tmpdir/pkg.tar.gz"; then
    local got
    got="$(sha256sum "$tmpdir/pkg.tar.gz" | cut -d' ' -f1)"
    if [[ "$got" != "$sha" ]]; then
      warn "SHA-256 mismatch for $name (want $sha, got $got) — skipping"
      rm -rf "$tmpdir"
      return 1
    fi
    tar -xzf "$tmpdir/pkg.tar.gz" -C "$tmpdir"
    local found
    found="$(find "$tmpdir" -type f -name "$bin_name" | head -n1 || true)"
    if [[ -n "$found" ]]; then
      install -m 0755 "$found" "/usr/local/bin/$bin_name"
      ok "Installed $bin_name"
    else
      warn "Binary $bin_name not found inside tarball"
    fi
  else
    warn "Failed to download $name from $url"
  fi
  rm -rf "$tmpdir"
}

if [[ "$ARCH" == "amd64" ]]; then
  NUCLEI_SHA="$NUCLEI_SHA256_AMD64"
  HTTPX_SHA="$HTTPX_SHA256_AMD64"
  SUBFINDER_SHA="$SUBFINDER_SHA256_AMD64"
  KATANA_SHA="$KATANA_SHA256_AMD64"
  FFUF_SHA="$FFUF_SHA256_AMD64"
  DALFOX_SHA="$DALFOX_SHA256_AMD64"
else
  NUCLEI_SHA="$NUCLEI_SHA256_ARM64"
  HTTPX_SHA="$HTTPX_SHA256_ARM64"
  SUBFINDER_SHA="$SUBFINDER_SHA256_ARM64"
  KATANA_SHA="$KATANA_SHA256_ARM64"
  FFUF_SHA="$FFUF_SHA256_ARM64"
  DALFOX_SHA="$DALFOX_SHA256_ARM64"
fi

install_zip_bin "nuclei"    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip"       "$NUCLEI_SHA"    "nuclei" || true
install_zip_bin "httpx"     "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${ARCH}.zip"          "$HTTPX_SHA"     "httpx" || true
install_zip_bin "subfinder" "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${ARCH}.zip" "$SUBFINDER_SHA" "subfinder" || true
install_zip_bin "katana"    "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${ARCH}.zip"       "$KATANA_SHA"    "katana" || true
install_tar_bin "ffuf"      "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${ARCH}.tar.gz"                        "$FFUF_SHA"      "ffuf" || true
install_tar_bin "dalfox"    "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox_linux_${ARCH}.tar.gz"                               "$DALFOX_SHA"    "dalfox" || true

if [[ ! -d /opt/sqlmap ]]; then
  info "Installing pinned sqlmap..."
  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
  (cd /opt/sqlmap && git fetch --depth 1 origin "$SQLMAP_COMMIT" && git checkout "$SQLMAP_COMMIT" 2>/dev/null || true)
  ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap
  chmod +x /opt/sqlmap/sqlmap.py
  ok "Installed sqlmap"
fi

if command -v nuclei >/dev/null 2>&1; then
  mkdir -p /opt/nuclei-templates
  info "Updating nuclei templates into /opt/nuclei-templates..."
  NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates nuclei -ut -ud /opt/nuclei-templates -silent || true
  chmod -R a+rX /opt/nuclei-templates || true
fi

if [[ "$PROFILE" == "full" ]]; then
  info "Installing full offensive/network toolset..."
  apt-get install -y --no-install-recommends \
    arp-scan fping iproute2 net-tools hashcat hydra john ncrack \
    openssh-client sshpass python3-impacket python3-paramiko python3-scapy || true
  if [[ ! -d /opt/bbot ]]; then
    python3 -m venv /opt/bbot
    /opt/bbot/bin/pip install --no-cache-dir "bbot==3.0.2" || true
    ln -sf /opt/bbot/bin/bbot /usr/local/bin/bbot
  fi
fi

ok "Tool installation complete (profile=$PROFILE)"
