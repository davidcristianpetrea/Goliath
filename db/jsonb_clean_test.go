package db

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJsonbClean(t *testing.T) {
	// A marshaled payload carrying a NUL byte (e.g. captured HTTP/tool output).
	b, err := json.Marshal(map[string]string{"body": "ab\x00cd"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `\u0000`) {
		t.Fatalf("precondition: marshaled JSON should contain the NUL escape, got %s", b)
	}

	cleaned := jsonbClean(b)
	if strings.Contains(string(cleaned), `\u0000`) {
		t.Fatalf("jsonbClean left a NUL escape jsonb rejects: %s", cleaned)
	}

	// Result must stay valid JSON with the NUL simply dropped.
	var out map[string]string
	if err := json.Unmarshal(cleaned, &out); err != nil {
		t.Fatalf("cleaned bytes are not valid JSON: %v (%s)", err, cleaned)
	}
	if out["body"] != "abcd" {
		t.Fatalf("expected NUL stripped to \"abcd\", got %q", out["body"])
	}

	// A NUL escape typed literally in source text (doubled backslash) is preserved.
	lit := []byte(`{"body":"\\u0000"}`)
	if got := jsonbClean(lit); string(got) != string(lit) {
		t.Fatalf("literal \\\\u0000 must be untouched, got %s", got)
	}

	// No NUL escape → returned unchanged.
	plain := []byte(`{"body":"hello"}`)
	if got := jsonbClean(plain); string(got) != string(plain) {
		t.Fatalf("plain JSON must be untouched, got %s", got)
	}
}

func TestJsonbCleanSurrogates(t *testing.T) {
	// PostgreSQL jsonb rejects lone surrogates (\uD800-\uDFFF).
	input := []byte(`{"desc":"test \uD800 value \uDFFF end"}`)
	cleaned := jsonbClean(input)
	if strings.Contains(string(cleaned), `\uD800`) || strings.Contains(string(cleaned), `\uDFFF`) {
		t.Fatalf("jsonbClean left a surrogate escape jsonb rejects: %s", cleaned)
	}
	// Verify the cleaned result is still valid JSON.
	var out map[string]string
	if err := json.Unmarshal(cleaned, &out); err != nil {
		t.Fatalf("cleaned bytes are not valid JSON: %v (%s)", err, cleaned)
	}
}

func TestJsonbCleanNonASCIIEscape(t *testing.T) {
	// Non-ASCII \uXXXX escapes fail with SQL_ASCII encoding. jsonbClean should
	// replace them with raw UTF-8 bytes.
	input := []byte(`{"x":"a\u2028b\u2029c"}`)
	cleaned := jsonbClean(input)
	if strings.Contains(string(cleaned), `\u2028`) || strings.Contains(string(cleaned), `\u2029`) {
		t.Fatalf("jsonbClean left non-ASCII escapes: %s", cleaned)
	}
	// The cleaned output should contain the raw UTF-8 bytes for LS and PS.
	var out map[string]string
	if err := json.Unmarshal(cleaned, &out); err != nil {
		t.Fatalf("cleaned bytes are not valid JSON: %v (%s)", err, cleaned)
	}
	if out["x"] != "a\u2028b\u2029c" {
		t.Fatalf("expected raw UTF-8 chars, got %q", out["x"])
	}
}

func TestJsonbCleanVT(t *testing.T) {
	// Vertical tab (\u000b) is encoded by json.Marshal as \u000b.
	// It's in the ASCII control range so jsonbClean should leave it as-is
	// (ASCII range escapes work even with SQL_ASCII).
	b, _ := json.Marshal(map[string]string{"x": "a\x0bb"})
	cleaned := jsonbClean(b)
	var out map[string]string
	if err := json.Unmarshal(cleaned, &out); err != nil {
		t.Fatalf("cleaned bytes are not valid JSON: %v (%s)", err, cleaned)
	}
	if out["x"] != "a\x0bb" {
		t.Fatalf("expected VT preserved, got %q", out["x"])
	}
}

func TestJsonbCleanPreservesValidEscapes(t *testing.T) {
	// Valid ASCII-range unicode escapes should be preserved.
	input := []byte(`{"emoji":"\u0041\u0042"}`)
	cleaned := jsonbClean(input)
	if string(cleaned) != string(input) {
		t.Fatalf("valid ASCII unicode escapes should be preserved, got %s", cleaned)
	}
}
