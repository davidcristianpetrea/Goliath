package agent

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// FPGateInput carries the finding metadata and bound HTTP proof context for
// deterministic false-positive screening before marking a finding "verified".
type FPGateInput struct {
	Name        string
	VulnClass   string
	Severity    string
	Summary     string
	POELevel    int
	Quotes      []string
	ProofBodies []string // decoded response head + body strings
}

// FPGateResult summarizes deterministic false-positive signals detected on a finding.
type FPGateResult struct {
	Downgrade       bool
	RiskScore       int
	Reasons         []string
	SuggestedStatus string
}

var (
	reHTTPStatus   = regexp.MustCompile(`(?im)^HTTP/\d+(?:\.\d+)?\s+(\d{3})\b`)
	reContentType  = regexp.MustCompile(`(?im)^Content-Type:\s*([^\r\n;]+)`)
	reHTMLComment  = regexp.MustCompile(`(?i)&(?:lt|gt|quot|#x3c|#60);|\\u003[ce]`)
	reRawScriptTag = regexp.MustCompile(`(?i)<script|onerror\s*=|onload\s*=|javascript:`)
)

// AssessFalsePositiveRisk applies deterministic heuristics to catch common
// automated scanner & LLM false positives before a finding is marked verified.
func AssessFalsePositiveRisk(in FPGateInput) FPGateResult {
	var reasons []string
	score := 0

	kind := strings.ToLower(in.Name + " " + in.VulnClass + " " + in.Summary)
	sev := strings.ToLower(strings.TrimSpace(in.Severity))

	isXSS := strings.Contains(kind, "xss") || strings.Contains(kind, "cross-site scripting") || strings.Contains(kind, "cross site scripting")
	isHeaderOnly := (strings.Contains(kind, "missing header") ||
		strings.Contains(kind, "security header") ||
		strings.Contains(kind, "x-frame-options") ||
		strings.Contains(kind, "x-content-type-options") ||
		strings.Contains(kind, "strict-transport-security") ||
		strings.Contains(kind, "content-security-policy")) &&
		!strings.Contains(kind, "bypass") && !strings.Contains(kind, "injection")

	isInjectionOrAccess := isXSS ||
		strings.Contains(kind, "sql injection") || strings.Contains(kind, "sqli") ||
		strings.Contains(kind, "command injection") || strings.Contains(kind, "rce") ||
		strings.Contains(kind, "ssrf") || strings.Contains(kind, "idor") ||
		strings.Contains(kind, "auth bypass") || strings.Contains(kind, "authentication bypass")

	// 1. Check bound HTTP proof responses for non-executable Content-Type on XSS
	//    and 4xx/5xx error-page-only reflections.
	if len(in.ProofBodies) > 0 {
		allNonExecXSS := isXSS
		allErrorStatus := isInjectionOrAccess
		sawStatus := false
		sawCT := false

		for _, body := range in.ProofBodies {
			if m := reContentType.FindStringSubmatch(body); len(m) == 2 {
				sawCT = true
				ct := strings.ToLower(strings.TrimSpace(m[1]))
				if !isNonExecutableXSSContentType(ct) {
					allNonExecXSS = false
				}
			} else {
				allNonExecXSS = false
			}

			if m := reHTTPStatus.FindStringSubmatch(body); len(m) == 2 {
				sawStatus = true
				code, _ := strconv.Atoi(m[1])
				if !isBenignErrorStatus(code) {
					allErrorStatus = false
				}
			} else {
				allErrorStatus = false
			}
		}

		if isXSS && sawCT && allNonExecXSS {
			score += 60
			reasons = append(reasons, "XSS claimed on non-executable Content-Type (e.g. application/json or text/plain)")
		}
		if isInjectionOrAccess && sawStatus && allErrorStatus && !mentionsErrorDisclosure(kind) {
			score += 45
			reasons = append(reasons, "proof response only shows 400/403/404/405/502/503 error status")
		}
	}

	// 2. XSS quotes containing only HTML-escaped entities and no unescaped trigger.
	if isXSS && len(in.Quotes) > 0 {
		allEscaped := true
		sawEscaped := false
		for _, q := range in.Quotes {
			if reRawScriptTag.MatchString(q) {
				allEscaped = false
				break
			}
			if reHTMLComment.MatchString(q) {
				sawEscaped = true
			}
		}
		if sawEscaped && allEscaped {
			score += 55
			reasons = append(reasons, "XSS evidence quote appears HTML/Unicode-escaped rather than executable")
		}
	}

	// 3. Banner / version-only finding without L3 behavioral proof.
	if in.POELevel > 0 && in.POELevel < 3 && (strings.Contains(kind, "outdated") || strings.Contains(kind, "version disclosure") || strings.Contains(kind, "cve-")) {
		score += 35
		reasons = append(reasons, fmt.Sprintf("version/banner-based claim with POE L%d below L3", in.POELevel))
	}

	// 4. Over-inflated severity on missing security headers.
	if isHeaderOnly && (sev == "high" || sev == "critical") {
		score += 40
		reasons = append(reasons, "High/Critical severity assigned to missing HTTP security header")
	}

	downgrade := score >= 45
	suggested := ""
	if downgrade {
		suggested = "unverified"
	}
	return FPGateResult{
		Downgrade:       downgrade,
		RiskScore:       score,
		Reasons:         reasons,
		SuggestedStatus: suggested,
	}
}

func isNonExecutableXSSContentType(ct string) bool {
	switch {
	case ct == "application/json",
		ct == "text/plain",
		ct == "application/octet-stream",
		strings.HasPrefix(ct, "image/") && ct != "image/svg+xml",
		strings.HasPrefix(ct, "font/"),
		ct == "text/css":
		return true
	default:
		return false
	}
}

func isBenignErrorStatus(code int) bool {
	switch code {
	case 400, 403, 404, 405, 410, 502, 503:
		return true
	default:
		return false
	}
}

func mentionsErrorDisclosure(kind string) bool {
	return strings.Contains(kind, "stack trace") ||
		strings.Contains(kind, "stacktrace") ||
		strings.Contains(kind, "debug") ||
		strings.Contains(kind, "source leak") ||
		strings.Contains(kind, "sql error")
}
