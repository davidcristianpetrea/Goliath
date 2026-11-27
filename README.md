<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="web/public/logo-dark.svg" />
  <source media="(prefers-color-scheme: light)" srcset="web/public/logo-light.svg" />
  <img src="web/public/logo-dark.svg" width="320" alt="Goliath logo" />
</picture>

**Self-hosted autonomous penetration testing — LXC-native, NVIDIA NIM & local-LLM ready, evidence-verified.**

An actively reworked, open-source (AGPL-3.0) fork of [BaaRai/ARTEX](https://github.com/BaaRai/ARTEX) (originally [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX)).

[![License](https://img.shields.io/badge/License-AGPL--3.0-101012)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-09090b)](go.mod)

[Quick Start (Proxmox LXC / No Docker)](#quick-start-proxmox-lxc--no-docker) · [NVIDIA NIM & Local Models](#nvidia-nim--local-models) · [What Goliath Improves](#what-goliath-improves) · [Docker Compose](#docker-compose)

</div>

---

## What Goliath Improves

| Area | Upstream ARTEX | Goliath |
| :--- | :--- | :--- |
| **Deployment** | Built primarily around Docker & Docker Compose | **First-class Proxmox LXC / Debian / Ubuntu installer** (`scripts/lxc-install.sh`) with zero Docker dependency, LXC-safe `systemd` unit, `goliath-ctl` CLI, and `GOLIATH_*` env aliases |
| **Runtime Tooling** | Assumes Docker image tools exist on `PATH` | **Runtime CLI tool inventory** (`agent/tool_inventory.go`) probes `PATH` and tells agents which tools exist vs. what to avoid |
| **NVIDIA NIM & Local LLMs** | Ollama regex 400 crash, `max_tokens` context overflow, local OpenAI key gate, private LAN SSRF block | **One-click provider presets** (NVIDIA NIM Cloud/Local, Ollama, vLLM, LM Studio, llama.cpp, OpenRouter, Gemini), **keyless local OpenAI**, **Allow Private/LAN** toggle (metadata IPs still blocked), `Retry-After` 429 backoff, anchored JSON Schema regex, and `/api/tags` fallback |
| **False-Positive Defense** | LLM triage locked to custom llama.cpp `/v1/systemone` endpoint; weak deterministic checks | **Deterministic FP Guard** (`agent/fp_guard.go`) catching non-executable XSS `Content-Type`s, HTML-escaped quotes, 404-only proofs, and header severity inflation + **Universal `ChatTriageClient`** working with any NIM/Ollama/OpenAI/Anthropic model |
| **Web UI & Dark Mode** | Default light theme, glare on auth panels, legacy purple branding | **Deep Matte Carbon** dark mode (`#09090b` / `#121215`) & Warm Alabaster light mode inspired by [davidpetrea.ro](https://davidpetrea.ro), bespoke **GOLIATH** architectural wordmark, `Verified only` findings filter |

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

Goliath is licensed under **AGPL-3.0** (see [LICENSE](LICENSE)) and builds upon the open-source foundation of [BaaRai/ARTEX](https://github.com/BaaRai/ARTEX) and [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX).
