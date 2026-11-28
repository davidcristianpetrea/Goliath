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
	Name           string
	VulnClass      string
	Severity       string
	Summary        string
	POELevel       int
	Quotes         []string
	ProofBodies    []string // response head + body strings
	BaselineBodies []string // optional baseline response head + body strings
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
	reACAO         = regexp.MustCompile(`(?im)^Access-Control-Allow-Origin:\s*\*`)
	reACAC         = regexp.MustCompile(`(?im)^Access-Control-Allow-Credentials:\s*true`)
	reHTMLComment  = regexp.MustCompile(`(?i)&(?:lt|gt|quot|#x3c|#60);|\\u003[ce]`)
	reRawScriptTag = regexp.MustCompile(`(?i)<script|onerror\s*=|onload\s*=|javascript:`)
	reCSPHeader    = regexp.MustCompile(`(?im)^Content-Security-Policy:`)
	reXFOHeader    = regexp.MustCompile(`(?im)^X-Frame-Options:\s*(DENY|SAMEORIGIN)`)
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

	isCORS := strings.Contains(kind, "cors") && !strings.Contains(kind, "arbitrary origin") && !strings.Contains(kind, "reflected origin")
	isDisclosureOrExposure := strings.Contains(kind, "disclosure") ||
		strings.Contains(kind, "exposed") ||
		strings.Contains(kind, "admin panel") ||
		strings.Contains(kind, "sensitive file") ||
		strings.Contains(kind, "backup file")

	isInjectionOrAccess := isXSS ||
		strings.Contains(kind, "sql injection") || strings.Contains(kind, "sqli") ||
		strings.Contains(kind, "command injection") || strings.Contains(kind, "rce") ||
		strings.Contains(kind, "ssrf") || strings.Contains(kind, "idor") ||
		strings.Contains(kind, "auth bypass") || strings.Contains(kind, "authentication bypass")

	// 1. Check bound HTTP proof responses for non-executable Content-Type on XSS,
	//    4xx/5xx error-page-only reflections, soft-404/SPA shells, and wildcard CORS.
	if len(in.ProofBodies) > 0 {
		allNonExecXSS := isXSS
		allErrorStatus := isInjectionOrAccess
		allSoft404 := isInjectionOrAccess || isDisclosureOrExposure
		sawStatus := false
		sawCT := false
		sawWildcardCORSNoCreds := false

		for _, raw := range in.ProofBodies {
			if m := reContentType.FindStringSubmatch(raw); len(m) == 2 {
				sawCT = true
				ct := strings.ToLower(strings.TrimSpace(m[1]))
				if !isNonExecutableXSSContentType(ct) {
					allNonExecXSS = false
				}
			} else {
				allNonExecXSS = false
			}

			code := 0
			if m := reHTTPStatus.FindStringSubmatch(raw); len(m) == 2 {
				sawStatus = true
				code, _ = strconv.Atoi(m[1])
				if !isBenignErrorStatus(code) {
					allErrorStatus = false
				}
			} else {
				allErrorStatus = false
			}

			bodyOnly := strings.ToLower(stripHTTPHead(raw))
			if code != 200 || !looksLikeSoft404OrSPAShell(bodyOnly) {
				allSoft404 = false
			}

			if isCORS && reACAO.MatchString(raw) && !reACAC.MatchString(raw) {
				sawWildcardCORSNoCreds = true
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
		if allSoft404 && sawStatus {
			score += 45
			reasons = append(reasons, "proof HTTP 200 response matches generic soft-404 or SPA shell")
		}
		if sawWildcardCORSNoCreds && (sev == "high" || sev == "critical") {
			score += 45
			reasons = append(reasons, "High/Critical severity claimed for wildcard CORS without credentials")
		}
	}

	// 2. Baseline-identical proof check: if baseline captures exist and every
	//    proof body is identical to a baseline body, no behavioral delta was shown.
	if isInjectionOrAccess && len(in.ProofBodies) > 0 && len(in.BaselineBodies) > 0 {
		baselineSet := make(map[string]struct{}, len(in.BaselineBodies))
		for _, b := range in.BaselineBodies {
			norm := normalizeFPBody(stripHTTPHead(b))
			if norm != "" {
				baselineSet[norm] = struct{}{}
			}
		}
		if len(baselineSet) > 0 {
			allSame := true
			for _, p := range in.ProofBodies {
				norm := normalizeFPBody(stripHTTPHead(p))
				if _, ok := baselineSet[norm]; !ok || norm == "" {
					allSame = false
					break
				}
			}
			if allSame {
				score += 50
				reasons = append(reasons, "proof response body is identical to baseline capture")
			}
		}
	}

	// 3. XSS quotes containing only HTML-escaped entities and no unescaped trigger.
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

	// 4. Banner / version-only finding without L3 behavioral proof.
	if in.POELevel > 0 && in.POELevel < 3 && (strings.Contains(kind, "outdated") || strings.Contains(kind, "version disclosure") || strings.Contains(kind, "cve-")) {
		score += 35
		reasons = append(reasons, fmt.Sprintf("version/banner-based claim with POE L%d below L3", in.POELevel))
	}

	// 5. Over-inflated severity on missing security headers.
	if isHeaderOnly && (sev == "high" || sev == "critical") {
		score += 45
		reasons = append(reasons, "High/Critical severity assigned to missing HTTP security header")
	}

	// 6. XSS claimed but response has strong CSP and X-Frame-Options.
	if isXSS && len(in.ProofBodies) > 0 {
		allCSP := true
		for _, raw := range in.ProofBodies {
			if !reCSPHeader.MatchString(raw) {
				allCSP = false
				break
			}
		}
		if allCSP {
			score += 20
			reasons = append(reasons, "XSS claimed but all responses have Content-Security-Policy")
		}
	}

	// 7. SSRF / Open Redirect with only 3xx status and no sensitive data.
	isOpenRedirect := strings.Contains(kind, "open redirect") || strings.Contains(kind, "url redirect")
	isSSRF := strings.Contains(kind, "ssrf") || strings.Contains(kind, "server-side request forgery")
	if (isOpenRedirect || isSSRF) && len(in.ProofBodies) > 0 {
		allRedirect := true
		for _, raw := range in.ProofBodies {
			if m := reHTTPStatus.FindStringSubmatch(raw); len(m) == 2 {
				code, _ := strconv.Atoi(m[1])
				if code < 300 || code >= 400 {
					allRedirect = false
					break
				}
			} else {
				allRedirect = false
				break
			}
		}
		if allRedirect && (sev == "high" || sev == "critical") {
			score += 35
			reasons = append(reasons, "SSRF/redirect with only 3xx responses rated High/Critical")
		}
	}

	// 8. Generic "information disclosure" at high severity without sensitive data indicators.
	if isDisclosureOrExposure && (sev == "high" || sev == "critical") && !strings.Contains(kind, "credential") &&
		!strings.Contains(kind, "password") && !strings.Contains(kind, "token") && !strings.Contains(kind, "api key") &&
		!strings.Contains(kind, "secret") && !strings.Contains(kind, "pii") && !strings.Contains(kind, "ssn") {
		score += 30
		reasons = append(reasons, "generic info-disclosure/exposure at High/Critical without sensitive data indicators")
	}

	// 9. Rate-limiting / brute-force findings are low-impact by default.
	isRateLimit := strings.Contains(kind, "rate limit") || strings.Contains(kind, "brute force") || strings.Contains(kind, "bruteforce")
	if isRateLimit && (sev == "high" || sev == "critical") {
		score += 40
		reasons = append(reasons, "rate-limiting/brute-force finding at High/Critical severity")
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

func stripHTTPHead(raw string) string {
	if idx := strings.Index(raw, "\r\n\r\n"); idx >= 0 {
		return raw[idx+4:]
	}
	if idx := strings.Index(raw, "\n\n"); idx >= 0 {
		return raw[idx+2:]
	}
	return raw
}

func normalizeFPBody(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func looksLikeSoft404OrSPAShell(lowerBody string) bool {
	if lowerBody == "" {
		return false
	}
	if strings.Contains(lowerBody, "404 not found") ||
		strings.Contains(lowerBody, "page not found") ||
		strings.Contains(lowerBody, "cannot get /") ||
		strings.Contains(lowerBody, "not found") && strings.Contains(lowerBody, "error") {
		return true
	}
	if len(lowerBody) < 2048 && (strings.Contains(lowerBody, `<div id="root"></div>`) ||
		strings.Contains(lowerBody, `<div id="app"></div>`) ||
		strings.Contains(lowerBody, `<div id="__next"></div>`) ||
		strings.Contains(lowerBody, `<div id="__nuxt"></div>`) ||
		strings.Contains(lowerBody, `<div id="__app"></div>`) ||
		strings.Contains(lowerBody, `<main id="app"></main>`)) {
		return true
	}
	return false
}

func isNonExecutableXSSContentType(ct string) bool {
	switch {
	case ct == "application/json",
		ct == "text/plain",
		ct == "text/csv",
		ct == "text/xml",
		ct == "application/xml",
		ct == "application/octet-stream",
		ct == "application/pdf",
		ct == "application/zip",
		strings.HasPrefix(ct, "image/") && ct != "image/svg+xml",
		strings.HasPrefix(ct, "font/"),
		strings.HasPrefix(ct, "audio/"),
		strings.HasPrefix(ct, "video/"),
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
