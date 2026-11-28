<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="web/public/logo-dark.svg" />
  <source media="(prefers-color-scheme: light)" srcset="web/public/logo-light.svg" />
  <img src="web/public/logo-dark.svg" width="320" alt="Goliath logo" />
</picture>

**Self-hosted autonomous penetration testing — LXC-native, NVIDIA NIM & local-LLM ready, evidence-verified.**

An actively reworked, open-source (AGPL-3.0) fork of [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX).

[![License](https://img.shields.io/badge/License-AGPL--3.0-101012)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-09090b)](go.mod)

[Quick Start (Proxmox LXC / No Docker)](#quick-start-proxmox-lxc--no-docker) · [NVIDIA NIM & Local Models](#nvidia-nim--local-models) · [What Goliath Improves](#what-goliath-improves) · [Docker Compose](#docker-compose)

</div>

---

## What Goliath Improves

| Area | Upstream ARTEX | Goliath |
| :--- | :--- | :--- |
| **Deployment** | Built primarily around Docker & Docker Compose | **First-class Proxmox LXC / Debian / Ubuntu installer** (`scripts/lxc-install.sh`, `scripts/proxmox-create-lxc.sh`) with zero Docker dependency, `--from-release`, LXC-safe `systemd` unit, `goliath-ctl` CLI (`update`, `trust-ca`, `doctor`, `backup`), and `GOLIATH_*` env aliases |
| **Runtime Tooling** | Assumes Docker image tools exist on `PATH` | **Runtime CLI tool inventory** (`agent/tool_inventory.go`) probes `PATH`, feeds agents only installed tools, and displays live status in **System → Tools** |
| **NVIDIA NIM & Local LLMs** | Ollama regex 400 crash, `max_tokens` context overflow, local OpenAI key gate, private LAN SSRF block | **One-click provider presets** (NVIDIA NIM Cloud/Local, Ollama, vLLM, LM Studio, llama.cpp, OpenRouter, Gemini), **0-based ascending LLM pool priority** (0 = highest) with bounded circuit-breaker jitter, **auto-detected context windows**, **keyless local OpenAI**, **Allow Private/LAN** toggle (metadata IPs still blocked), `Retry-After` 429 backoff, and `/api/tags` fallback |
| **False-Positive Defense & Compaction** | LLM triage locked to custom llama.cpp `/v1/systemone` endpoint; weak deterministic checks | **9-rule Deterministic FP Guard** (`agent/fp_guard.go`: XSS `Content-Type`/escaping/CSP, 4xx/5xx-only, baseline-identical & soft-404/SPA shell, SSRF 3xx-only, header/CORS/rate-limit inflation) + **Universal `ChatTriageClient`** (dedup & live FP judge across all proof bodies) + **Brotli/Zstd** verification + **Re-verify** button + resilient cold-graph compaction retries |
| **Web UI & Mobile Experience** | Default light theme, glare on auth panels, desktop-only tables | **Goliath Teal/Carbon** theme (`#080e12` / `#38d9d4`) & Deep Matte Carbon dark mode inspired by [davidpetrea.ro](https://davidpetrea.ro), **mobile-first responsive UI** (bottom nav bar, mobile task/finding cards, collapsible chat & filter drawers, auto-closing sidebar), pure-vector **GOLIATH** wordmark, and HackerOne/Bugcrowd scope paste parser |

---

## Quick Start: Proxmox LXC / No Docker

Run on a fresh **Debian 12/13** or **Ubuntu 22.04/24.04** LXC container (unprivileged or privileged) as `root`:

```bash
git clone https://github.com/davidcristianpetrea/Goliath.git /opt/goliath-src
cd /opt/goliath-src
bash scripts/lxc-install.sh
```

Or non-interactively with the standard recon toolset (`nmap`, `nuclei`, `httpx`, `subfinder`, `katana`, `ffuf`, `dalfox`, `sqlmap`):

```bash
bash scripts/lxc-install.sh --non-interactive --tools standard --allow-private-llm
```

Manage the service anytime with `goliath-ctl`:

```bash
goliath-ctl status       # Check systemd service
goliath-ctl logs         # Follow live logs
goliath-ctl setup-token  # Print the one-time /setup token
goliath-ctl doctor       # Verify PostgreSQL + installed pentest binaries
goliath-ctl backup       # Dump PostgreSQL database
```

See [docs/lxc-deployment.md](docs/lxc-deployment.md) for sizing, firewall, and reverse-proxy notes.

---

## NVIDIA NIM & Local Models

1. Open **System → LLM → Create**.
2. Click a preset (**NVIDIA NIM**, **NIM Local**, **Ollama**, **vLLM**, **LM Studio**, or **llama.cpp**).
3. For LAN/localhost endpoints (`127.0.0.1`, `192.168.x.x`, `10.x.x.x`), enable **Allow private / LAN model endpoints** under **System → LLM → Pool settings** (or set `GOLIATH_LLM_ALLOW_PRIVATE=1`, enabled by default in LXC installs). Cloud metadata IPs (`169.254.169.254`, `fd00:ec2::254`) remain strictly blocked.
4. Click the refresh icon next to **Model** to fetch and search all available models.

---

## Docker Compose

Docker remains fully supported for containerized workflows:

```bash
git clone https://github.com/davidcristianpetrea/Goliath.git
cd Goliath
cp .env.example .env
docker compose up -d --build
```

---

## Credits & License

Goliath is licensed under **AGPL-3.0** (see [LICENSE](LICENSE)) and is originally based on [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX).
