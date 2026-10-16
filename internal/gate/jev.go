package gate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// jevModel is the model name sent with every request. Local nimble runs under
// Ollama and knows the model as "nimble:latest". It answers an unknown name with
// a 404. That includes "jev-latest", the name TypeSafe's hosted API uses. A
// different backend, such as openjev or the hosted API, needs its own name.
const jevModel = "nimble:latest"

// Jev is gate tier 1. It asks a local jev service how likely a note is to be
// sensitive. The service is nimble, a TypeSafe System One analog.
type Jev struct {
	base, key string
	hc        *http.Client
}

// NewJev returns a client for the service at base, for example
// "http://127.0.0.1:11434". A local service accepts any key.
func NewJev(base, key string) *Jev {
	return &Jev{base: base, key: key, hc: &http.Client{Timeout: 20 * time.Second}}
}

type jevReq struct {
	State     string                 `json:"state"`
	Model     string                 `json:"model"`
	Questions map[string]jevQuestion `json:"questions"`
}
type jevQuestion struct {
	Type         string `json:"type"`
	Instructions string `json:"instructions"`
}

// jevResp holds the part of the reply that the client reads. The service also
// sends model, usage and a type for each answer. Noul is a pointer, so that a
// missing answer differs from an answer of 0.
type jevResp struct {
	Answers map[string]struct {
		Noul *float64 `json:"noul"`
	} `json:"answers"`
}

// SensitiveProbability asks jev one noul question about the note and returns the
// answer as a probability from 0 to 1. The note goes in the state field and
// nowhere else. It is data, and it is never part of the question.
//
// The gate reads an error as "sensitive" and a probability of 0 as "safe". So
// the method returns an error, never 0, when the reply holds no probability from
// 0 to 1. A change in the reply shape then blocks notes. It does not let them
// through. The error text does not include the note.
//
// The service rejects an empty note, a note over 8194 tokens and a request body
// over 64 KiB. Each of these is an error here.
func (j *Jev) SensitiveProbability(noteText string) (float64, error) {
	body, _ := json.Marshal(jevReq{
		State: noteText, Model: jevModel,
		Questions: map[string]jevQuestion{
			"sensitive": {Type: "noul", Instructions: "Does this note contain secrets, credentials, passwords, API keys, or private personal data?"},
		},
	})
	req, err := http.NewRequest(http.MethodPost, j.base+"/v1/systemone", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+j.key)
	resp, err := j.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("jev %s: status %d", j.base, resp.StatusCode)
	}
	var out jevResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, err
	}
	a, ok := out.Answers["sensitive"]
	if !ok || a.Noul == nil {
		return 0, fmt.Errorf("jev %s: reply has no answers.sensitive.noul", j.base)
	}
	if p := *a.Noul; p < 0 || p > 1 {
		return 0, fmt.Errorf("jev %s: probability %v is not from 0 to 1", j.base, p)
	}
	return *a.Noul, nil
}
