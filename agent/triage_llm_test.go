package agent

import (
	"context"
	"iter"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

type mockTriageProvider struct {
	reply string
	err   error
}

func (m mockTriageProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) {}
}

func (m mockTriageProvider) Complete(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if m.err != nil {
		return llm.Message{}, "", llm.Usage{}, m.err
	}
	return llm.Message{Role: llm.RoleAssistant, Content: llm.UserText(m.reply).Content}, "stop", llm.Usage{}, nil
}

func TestChatTriageClientDuplicate(t *testing.T) {
	c := &ChatTriageClient{
		Model:    "nvidia/llama-3.1-nemotron-70b-instruct",
		Provider: mockTriageProvider{reply: "```json\n{\"duplicate_of\": 42, \"confidence\": 0.91, \"reason\": \"same param\"}\n```"},
	}
	ans, err := c.Duplicate(context.Background(), TriageCandidate{
		Name:    "SQLi in id",
		Summary: "SQL injection on /items?id=1",
	}, []TriageCandidate{
		{FindingID: 42, NodeID: 108, Name: "SQLi id", Summary: "SQLi on /items id parameter"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ans.DuplicateOf != 42 || ans.DuplicateOfNode != 108 || ans.Confidence < 0.9 {
		t.Fatalf("unexpected answer: %+v", ans)
	}
}

func TestChatTriageClientEvaluateFP(t *testing.T) {
	c := &ChatTriageClient{
		Model:    "llama3.2",
		Provider: mockTriageProvider{reply: `{"likely_fp": true, "confidence": 0.88, "reason": "JSON content type"}`},
	}
	res, err := c.EvaluateFalsePositive(context.Background(), TriageCandidate{
		Name:      "Reflected XSS",
		VulnClass: "XSS",
		Severity:  "high",
		Summary:   "Reflected in JSON",
	}, "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{}")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.LikelyFP || res.Confidence < 0.8 {
		t.Fatalf("unexpected FP result: %+v", res)
	}
}

func TestChatTriageClientEvaluateFPFencedJSON(t *testing.T) {
	c := &ChatTriageClient{
		Model:    "mistralai/mistral-large-4-1t-a52b",
		Provider: mockTriageProvider{reply: "Here is my evaluation:\n```json\n{\"likely_fp\": false, \"confidence\": 0.92, \"reason\": \"Confirmed {braces} in response\"}\n```"},
	}
	res, err := c.EvaluateFalsePositive(context.Background(), TriageCandidate{
		Name:      "SSRF",
		VulnClass: "SSRF",
		Severity:  "high",
		Summary:   "Server-side fetch",
	}, "HTTP/1.1 200 OK\n\n{\"title\":\"internal\"}")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.LikelyFP || res.Confidence < 0.9 {
		t.Fatalf("unexpected FP result: %+v", res)
	}
}
