# Native Proxmox LXC & Linux Deployment (No Docker)

Goliath is designed to run natively inside a standard Debian 12/13 or Ubuntu 22.04/24.04 LXC container without Docker-in-Docker or nested container overhead.

## Recommended LXC Sizing

- **OS Template**: Debian 12 (Bookworm), Debian 13 (Trixie), or Ubuntu 24.04 LTS
- **Container Type**: Unprivileged LXC (supported out of the box)
- **CPU**: 2–4 vCPUs
- **RAM**: 4–8 GB (PostgreSQL + Go runtime + concurrent recon tools)
- **Disk**: 20–40 GB (Nuclei templates + SQLite HTTP traffic captures + task workspaces)
- **Features**: Standard unprivileged container works; `nesting=1` is optional and not required since Goliath runs natively via `systemd`.

## Proxmox Host Provisioning (1-Command LXC Creation)

Run on your **Proxmox VE host** as `root` to create an unprivileged Debian 12 LXC container and automatically install Goliath inside it:

```bash
curl -fsSL https://raw.githubusercontent.com/davidcristianpetrea/Goliath/main/scripts/proxmox-create-lxc.sh | bash
```

## One-Step Install (Inside an Existing Debian/Ubuntu LXC)

Inside the LXC container as `root`:

```bash
git clone https://github.com/davidcristianpetrea/Goliath.git /opt/goliath-src
cd /opt/goliath-src
bash scripts/lxc-install.sh
```

Or non-interactively (add `--from-release` to pull a prebuilt GitHub Release binary when available):

```bash
bash scripts/lxc-install.sh --non-interactive --tools standard --allow-private-llm
```

### Tool Profiles (`--tools`)

- `minimal`: `nmap`, `curl`, `wget`, `dig`, `nc`, `whois`, `ripgrep`, `jq`, `sqlite3`, `python3`
- `standard` *(default)*: `minimal` + pinned SHA-256-verified `nuclei` (+ templates in `/opt/nuclei-templates`), `httpx`, `subfinder`, `katana`, `ffuf`, `dalfox`, `sqlmap`
- `full`: `standard` + `impacket`, `hydra`, `john`, `ncrack`, `ssh-audit`, `sshpass`, `arp-scan`, `fping`, `bbot`
- `none`: Skip tool installation (Goliath's runtime tool inventory will automatically inform agents which CLI tools are missing)

## Day-to-Day Management (`goliath-ctl`)

```bash
goliath-ctl status       # Check systemd service status
goliath-ctl logs         # Follow live logs
goliath-ctl setup-token  # Print the initial /setup token
goliath-ctl doctor       # Verify PostgreSQL + installed pentest binaries
goliath-ctl backup       # Dump PostgreSQL database to /root/
goliath-ctl trust-ca     # Trust Goliath MITM CA in system certificates
goliath-ctl update       # Pull latest main, rebuild with rollback safety, restart
goliath-ctl restart      # Restart Goliath
```

## Connecting Local / LAN LLMs (Ollama, Local NVIDIA NIM, vLLM)

The LXC installer enables `GOLIATH_LLM_ALLOW_PRIVATE=1` by default so Goliath can talk to Ollama, vLLM, LM Studio, or local NVIDIA NIM instances on `127.0.0.1` or your LAN (`192.168.x.x` / `10.x.x.x`), while still blocking cloud metadata endpoints (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`).
