package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestResolutionFromProfileKeylessLocalOpenAI(t *testing.T) {
	s := &Server{}
	p := &db.LLMProfile{
		ID:      7,
		Name:    "Local NIM",
		Format:  "openai",
		BaseURL: "http://127.0.0.1:8000/v1",
		Model:   "meta/llama-3.1-70b-instruct",
		APIKey:  "",
	}
	res := s.resolutionFromProfile(p, "test")
	if res.Reason == "LLM profile has no API Key set" {
		t.Fatalf("keyless local OpenAI profile should not be rejected for missing API key: %+v", res)
	}
	if !res.Available {
		t.Fatalf("expected keyless local OpenAI profile to be available, got %+v", res)
	}

	cloud := &db.LLMProfile{
		ID:      8,
		Name:    "Cloud OpenAI",
		Format:  "openai",
		BaseURL: "https://api.openai.com/v1",
		Model:   "gpt-4o",
		APIKey:  "",
	}
	resCloud := s.resolutionFromProfile(cloud, "test")
	if resCloud.Available || resCloud.Reason != "LLM profile has no API Key set" {
		t.Fatalf("expected cloud OpenAI without API key to fail, got %+v", resCloud)
	}
}
