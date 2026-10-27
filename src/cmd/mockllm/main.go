// Mock Chat-Completions endpoint for local end-to-end runs.
//
// It answers with a fixed triage verdict so the alert -> intent -> verdict ->
// review pipeline can be exercised without a vendor account or real cost.
//
//	go run ./cmd/mockllm
//
// Then point models.yaml at http://127.0.0.1:8089 and set SOC_MODELS_CONFIG.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
)

type verdict struct {
	Verdict    string  `json:"verdict"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Rationale  string  `json:"rationale"`
	Evidence   []struct {
		Kind  string `json:"kind"`
		Ref   string `json:"ref"`
		Quote string `json:"quote"`
	} `json:"evidence"`
	Missing []string `json:"missing"`
}

// responder keeps the answer configurable so tests can exercise both the
// auto-close and the review paths with one binary.
func responder(confidence float64, severity string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		result := verdict{
			Verdict:    "true_positive",
			Severity:   severity,
			Confidence: confidence,
			Rationale:  "mock endpoint: encoded command with outbound connection",
		}
		result.Evidence = []struct {
			Kind  string `json:"kind"`
			Ref   string `json:"ref"`
			Quote string `json:"quote"`
		}{{Kind: "alert_field", Ref: "raw.event", Quote: "mock evidence"}}

		payload, _ := json.Marshal(result)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message":       map[string]any{"content": string(payload)},
				"finish_reason": "stop",
			}},
			"usage": map[string]any{"prompt_tokens": 120, "completion_tokens": 60},
		})
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8089", "listen address")
	confidence := flag.Float64("confidence", 0.95, "confidence returned in the verdict")
	severity := flag.String("severity", "low", "severity returned in the verdict")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/chat/completions", responder(*confidence, *severity))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("mock LLM listening on http://%s (confidence=%.2f severity=%s)",
		*addr, *confidence, *severity)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("mock LLM: %v", err)
		os.Exit(1)
	}
}
