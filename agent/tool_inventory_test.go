package agent

import (
	"errors"
	"strings"
	"testing"
)

func TestProbeToolInventoryWithAndFormat(t *testing.T) {
	mockLook := func(name string) (string, error) {
		switch name {
		case "nmap", "curl", "python3":
			return "/usr/bin/" + name, nil
		default:
			return "", errors.New("not found")
		}
	}
	items := probeToolInventoryWith([]string{"nmap", "nuclei", "curl", "bbot", "python3"}, mockLook)
	if len(items) != 5 {
		t.Fatalf("got %d items, want 5", len(items))
	}
	if !items[0].Available || items[0].Path != "/usr/bin/nmap" {
		t.Fatalf("expected nmap available, got %+v", items[0])
	}
	if items[1].Available || items[1].Path != "" {
		t.Fatalf("expected nuclei unavailable, got %+v", items[1])
	}
	block := FormatToolInventoryBlock(items)
	if !strings.Contains(block, "Available: nmap, curl, python3") {
		t.Fatalf("unexpected available list in %q", block)
	}
	if !strings.Contains(block, "Unavailable (do not invoke): nuclei, bbot") {
		t.Fatalf("unexpected unavailable list in %q", block)
	}
}
