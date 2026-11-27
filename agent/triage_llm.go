package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/Autumn-27/norma/llm"
)

// ChatTriageClient implements TriageClient using any standard chat-completions
// LLM provider (NVIDIA NIM, Ollama, OpenAI, Anthropic, vLLM, LM Studio) so
// semantic deduplication and false-positive screening work without needing a
// custom llama.cpp /v1/systemone endpoint.
type ChatTriageClient struct {
	Provider llm.Provider
	Model    string
}

// FPReviewResult is the advisory false-positive judgement returned by
// EvaluateFalsePositive.
type FPReviewResult struct {
	LikelyFP   bool    `json:"likely_fp"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// Duplicate checks whether cand is the same defect as any finding in existing
// via a compact JSON-only completion call. Fail-open on any error.
func (c *ChatTriageClient) Duplicate(ctx context.Context, cand TriageCandidate, existing []TriageCandidate) (DuplicateAnswer, error) {
	if c == nil || c.Provider == nil {
		return DuplicateAnswer{}, fmt.Errorf("triage: provider is nil")
	}
	if len(existing) == 0 || strings.TrimSpace(cand.Summary) == "" {
		return DuplicateAnswer{}, nil
	}
	state := buildDuplicateState(cand, existing)
	prompt := "Compare CANDIDATE against EXISTING findings. Decide if CANDIDATE is the same underlying defect (same root cause, endpoint, and parameter/mechanism) as one of the EXISTING findings.\n" +
		"Respond with ONLY a JSON object: {\"duplicate_of\": <integer finding id or 0 if distinct>, \"confidence\": <0.0 to 1.0>, \"reason\": \"<short reason>\"}.\n\n" +
		state

	ctx, cancel := context.WithTimeout(ctx, TriageHTTPTimeout)
	defer cancel()

	msg, _, _, err := c.Provider.Complete(ctx, llm.CompletionRequest{
		System:    []string{"You are a strict security finding deduplication judge. Output valid JSON only, no markdown fences."},
		Messages:  []llm.Message{llm.UserText(prompt)},
		MaxTokens: 256,
	})
	if err != nil {
		return DuplicateAnswer{}, err
	}
	raw := extractJSONObject(msg.Text())
	var parsed struct {
		DuplicateOf int64   `json:"duplicate_of"`
		Confidence  float64 `json:"confidence"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return DuplicateAnswer{}, fmt.Errorf("triage parse: %w", err)
	}
	ans := DuplicateAnswer{
		DuplicateOf: parsed.DuplicateOf,
		Confidence:  parsed.Confidence,
	}
	if ans.DuplicateOf > 0 {
		for _, e := range existing {
			if e.FindingID == ans.DuplicateOf {
				ans.DuplicateOfNode = e.NodeID
				break
			}
		}
		if ans.DuplicateOfNode == 0 && !containsFindingID(existing, ans.DuplicateOf) {
			return DuplicateAnswer{}, nil
		}
	}
	return ans, nil
}

// EvaluateFalsePositive asks the triage LLM whether a finding + HTTP proof
// snippet looks like a false positive. Advisory only.
func (c *ChatTriageClient) EvaluateFalsePositive(ctx context.Context, cand TriageCandidate, proofSnippet string) (FPReviewResult, error) {
	if c == nil || c.Provider == nil {
		return FPReviewResult{}, fmt.Errorf("triage: provider is nil")
	}
	snippet := clipForTriage(proofSnippet, 1800)
	prompt := fmt.Sprintf(
		"Evaluate if this reported security finding is a FALSE POSITIVE based on the proof snippet.\nFinding: %s (class=%s, severity=%s)\nSummary: %s\nProof:\n%s\n\nRespond with ONLY JSON: {\"likely_fp\": true|false, \"confidence\": 0.0..1.0, \"reason\": \"short explanation\"}",
		cand.Name, cand.VulnClass, cand.Severity, clipForTriage(cand.Summary, 400), snippet,
	)
	ctx, cancel := context.WithTimeout(ctx, TriageHTTPTimeout)
	defer cancel()

	msg, _, _, err := c.Provider.Complete(ctx, llm.CompletionRequest{
		System:    []string{"You are a senior AppSec triage reviewer. Output valid JSON only, no markdown fences."},
		Messages:  []llm.Message{llm.UserText(prompt)},
		MaxTokens: 256,
	})
	if err != nil {
		return FPReviewResult{}, err
	}
	var out FPReviewResult
	if err := json.Unmarshal([]byte(extractJSONObject(msg.Text())), &out); err != nil {
		return FPReviewResult{}, fmt.Errorf("triage fp parse: %w", err)
	}
	return out, nil
}

func containsFindingID(existing []TriageCandidate, id int64) bool {
	for _, e := range existing {
		if e.FindingID == id {
			return true
		}
	}
	return false
}

func extractJSONObject(s string) string {
	s = strings.TrimSpace(s)
	start := strings.IndexByte(s, '{')
	end := strings.LastIndexByte(s, '}')
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}

func clipForTriage(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func float64Ptr(v float64) *float64 { return &v }
