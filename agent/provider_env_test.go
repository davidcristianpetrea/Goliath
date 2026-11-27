package agent

import (
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// ARTEX_LLM_PROVIDER is matched regardless of case and surrounding spaces. A
// miss used to fall through to anthropic: "Ollama" then sent ANTHROPIC_API_KEY
// to the Ollama base URL.
func TestFromEnvProviderIsCaseInsensitive(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
	t.Setenv("OPENAI_API_KEY", "sk-oai")
	t.Setenv("ARTEX_LLM_BASE_URL", "")
	t.Setenv("ARTEX_LLM_MODEL", "")
	for _, tc := range []struct {
		env  string
		want llm.Format
		key  string
	}{
		{"Ollama", FormatOllama, ""},
		{" OLLAMA ", FormatOllama, ""},
		{"OpenAI", llm.FormatOpenAI, "sk-oai"},
		{"OpenAI-Responses", llm.FormatOpenAIResponses, "sk-oai"},
		{"Anthropic", llm.FormatAnthropic, "sk-ant-secret"},
	} {
		t.Setenv("ARTEX_LLM_PROVIDER", tc.env)
		c, ok := FromEnv()
		if !ok {
			t.Fatalf("%q: FromEnv returned ok=false", tc.env)
		}
		if c.Format != tc.want || c.APIKey != tc.key {
			t.Fatalf("%q: format=%v key=%q, want format=%v key=%q", tc.env, c.Format, c.APIKey, tc.want, tc.key)
		}
	}
}

func TestBedrockGatewayEnvDoesNotInheritPublicProviderKey(t *testing.T) {
	t.Setenv("ARTEX_LLM_PROVIDER", "bedrock-gateway")
	t.Setenv("ARTEX_LLM_BASE_URL", "https://gateway.example.com/bedrock")
	t.Setenv("ARTEX_LLM_MODEL", "test.model")
	t.Setenv("ANTHROPIC_API_KEY", "unrelated-anthropic-key")
	t.Setenv("ARTEX_LLM_API_KEY", "")
	if _, ok := FromEnv(); ok {
		t.Fatal("gateway inherited an unrelated key")
	}
	t.Setenv("ARTEX_LLM_API_KEY", "synthetic-gateway-token")
	t.Setenv("ARTEX_LLM_CUSTOM_HEADERS", "X-Example-Route: demo")
	c, ok := FromEnv()
	if !ok || c.Format != FormatBedrockGateway || c.APIKey != "synthetic-gateway-token" || c.CustomHeaders != "X-Example-Route: demo" {
		t.Fatal("gateway environment was not resolved")
	}
}

func TestLocalOpenAIKeylessAndNvidiaNIMNormalization(t *testing.T) {
	cLocal := ConfigFrom("openai", "meta/llama-3.1-70b-instruct", "http://127.0.0.1:8000/v1", "", "")
	if cLocal.NeedsAPIKey() {
		t.Fatal("local OpenAI-compatible endpoint should not require an API key")
	}
	if _, err := cLocal.NewProvider(); err != nil {
		t.Fatalf("local keyless OpenAI NewProvider failed: %v", err)
	}

	cLAN := ConfigFrom("openai", "qwen2.5-coder", "http://192.168.1.50:1234/v1", "", "")
	if cLAN.NeedsAPIKey() {
		t.Fatal("LAN RFC1918 OpenAI-compatible endpoint should not require an API key")
	}

	cNIM := ConfigFrom("openai", "nvidia/llama-3.1-nemotron-70b-instruct", "https://integrate.api.nvidia.com", "nvapi-test", "")
	if cNIM.BaseURL != "https://integrate.api.nvidia.com/v1" {
		t.Fatalf("NIM BaseURL = %q, want https://integrate.api.nvidia.com/v1", cNIM.BaseURL)
	}
	if !cNIM.NeedsAPIKey() {
		t.Fatal("cloud NVIDIA NIM should require an API key")
	}
}
