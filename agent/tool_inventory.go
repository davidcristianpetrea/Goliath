package agent

import (
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ToolAvailability describes one CLI security/utility binary probed on PATH.
type ToolAvailability struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
}

// standardCLITools is the curated list of external CLI tools Goliath agents
// commonly invoke in Bash. Probing them at runtime prevents agents from
// wasting turns trying to run tools that aren't installed (e.g. minimal LXC).
var standardCLITools = []string{
	"nmap", "nuclei", "httpx", "subfinder", "katana",
	"ffuf", "dalfox", "sqlmap", "bbot", "hydra",
	"john", "ssh-audit", "curl", "python3", "node",
	"jq", "rg", "dig", "whois", "nc",
}

const toolInventoryTTL = 5 * time.Minute

var (
	toolInventoryMu    sync.Mutex
	toolInventoryCache []ToolAvailability
	toolInventoryAt    time.Time
	lookPathFn         = exec.LookPath
)

// ProbeToolInventory checks PATH for standardCLITools, caching results for 5 minutes.
func ProbeToolInventory() []ToolAvailability {
	toolInventoryMu.Lock()
	defer toolInventoryMu.Unlock()
	if len(toolInventoryCache) > 0 && time.Since(toolInventoryAt) < toolInventoryTTL {
		out := make([]ToolAvailability, len(toolInventoryCache))
		copy(out, toolInventoryCache)
		return out
	}
	out := probeToolInventoryWith(standardCLITools, lookPathFn)
	toolInventoryCache = out
	toolInventoryAt = time.Now()
	cp := make([]ToolAvailability, len(out))
	copy(cp, out)
	return cp
}

func probeToolInventoryWith(names []string, look func(string) (string, error)) []ToolAvailability {
	out := make([]ToolAvailability, 0, len(names))
	for _, name := range names {
		p, err := look(name)
		out = append(out, ToolAvailability{
			Name:      name,
			Available: err == nil && p != "",
			Path:      p,
		})
	}
	return out
}

// FormatToolInventoryBlock formats a compact prompt note listing installed and
// missing CLI tools so agents choose available alternatives on the first try.
func FormatToolInventoryBlock(items []ToolAvailability) string {
	if len(items) == 0 {
		return ""
	}
	var avail, missing []string
	for _, it := range items {
		if it.Available {
			avail = append(avail, it.Name)
		} else {
			missing = append(missing, it.Name)
		}
	}
	if len(avail) == 0 && len(missing) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n**Runtime CLI tool inventory**: ")
	if len(avail) > 0 {
		b.WriteString("Available: ")
		b.WriteString(strings.Join(avail, ", "))
	} else {
		b.WriteString("Available: none")
	}
	if len(missing) > 0 {
		b.WriteString(" | Unavailable (do not invoke): ")
		b.WriteString(strings.Join(missing, ", "))
	}
	b.WriteString(".")
	return b.String()
}

// ToolInventoryPromptBlock returns the cached runtime tool inventory block.
func ToolInventoryPromptBlock() string {
	return FormatToolInventoryBlock(ProbeToolInventory())
}
