package agent

import (
	"strings"
	"testing"
)

func TestAssessFalsePositiveRisk_XSSNonExecutableContentType(t *testing.T) {
	res := AssessFalsePositiveRisk(FPGateInput{
		Name:      "Reflected XSS in /api/search",
		VulnClass: "XSS",
		Severity:  "high",
		POELevel:  3,
		Quotes:    []string{`{"query":"<script>alert(1)</script>"}`},
		ProofBodies: []string{
			"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{\"query\":\"<script>alert(1)</script>\"}",
		},
	})
	if !res.Downgrade || res.RiskScore < 45 {
		t.Fatalf("expected XSS on application/json to trigger downgrade, got %+v", res)
	}
}

func TestAssessFalsePositiveRisk_XSSEscapedQuote(t *testing.T) {
	res := AssessFalsePositiveRisk(FPGateInput{
		Name:      "Reflected XSS",
		VulnClass: "Cross-Site Scripting",
		Severity:  "medium",
		POELevel:  3,
		Quotes:    []string{`&lt;script&gt;alert(1)&lt;/script&gt;`},
		ProofBodies: []string{
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n&lt;script&gt;alert(1)&lt;/script&gt;",
		},
	})
	if !res.Downgrade {
		t.Fatalf("expected HTML-escaped XSS quote to trigger downgrade, got %+v", res)
	}
}

func TestAssessFalsePositiveRisk_ValidHTMLXSSPasses(t *testing.T) {
	res := AssessFalsePositiveRisk(FPGateInput{
		Name:      "Reflected XSS in q param",
		VulnClass: "XSS",
		Severity:  "high",
		POELevel:  3,
		Quotes:    []string{`<script>alert(document.domain)</script>`},
		ProofBodies: []string{
			"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<script>alert(document.domain)</script>",
		},
		BaselineBodies: []string{
			"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\nhello world",
		},
	})
	if res.Downgrade {
		t.Fatalf("expected real HTML XSS to pass FP guard, got %+v", res)
	}
}

func TestAssessFalsePositiveRisk_404ErrorPageAndHeaderInflation(t *testing.T) {
	res404 := AssessFalsePositiveRisk(FPGateInput{
		Name:      "SQL Injection on /missing",
		VulnClass: "SQLi",
		Severity:  "critical",
		POELevel:  3,
		ProofBodies: []string{
			"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\nNot Found",
		},
	})
	if !res404.Downgrade {
		t.Fatalf("expected 404-only proof for SQLi to trigger downgrade, got %+v", res404)
	}

	resHdr := AssessFalsePositiveRisk(FPGateInput{
		Name:      "Missing X-Frame-Options header",
		VulnClass: "Misconfiguration",
		Severity:  "high",
		POELevel:  3,
	})
	if !resHdr.Downgrade || len(resHdr.Reasons) == 0 || !strings.Contains(resHdr.Reasons[0], "High/Critical") {
		t.Fatalf("expected header severity inflation downgrade, got %+v", resHdr)
	}
}

func TestAssessFalsePositiveRisk_BaselineIdenticalAndSoft404AndCORS(t *testing.T) {
	resBase := AssessFalsePositiveRisk(FPGateInput{
		Name:           "IDOR on /api/profile",
		VulnClass:      "IDOR",
		Severity:       "high",
		POELevel:       3,
		ProofBodies:    []string{"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":1,\"role\":\"user\"}"},
		BaselineBodies: []string{"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":1,\"role\":\"user\"}"},
	})
	if !resBase.Downgrade {
		t.Fatalf("expected baseline-identical proof to trigger downgrade, got %+v", resBase)
	}

	resSoft := AssessFalsePositiveRisk(FPGateInput{
		Name:        "Exposed admin panel at /admin/.env",
		VulnClass:   "Information Disclosure",
		Severity:    "high",
		POELevel:    3,
		ProofBodies: []string{"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!doctype html><html><body><div id=\"root\"></div></body></html>"},
	})
	if !resSoft.Downgrade {
		t.Fatalf("expected SPA shell soft-404 to trigger downgrade, got %+v", resSoft)
	}

	resCORS := AssessFalsePositiveRisk(FPGateInput{
		Name:        "Permissive CORS wildcard",
		VulnClass:   "CORS",
		Severity:    "high",
		POELevel:    3,
		ProofBodies: []string{"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\nok"},
	})
	if !resCORS.Downgrade {
		t.Fatalf("expected wildcard CORS without credentials at high severity to trigger downgrade, got %+v", resCORS)
	}
}
