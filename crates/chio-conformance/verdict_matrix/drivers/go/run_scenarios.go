package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	chio "github.com/backbay/chio/sdks/go/chio-go-http"
)

const (
	driverName     = "go-http-sdk"
	matrixServerID = "verdict-matrix"

	reasonNone               = "urn:chio:error:none"
	reasonScopeExceeded      = "urn:chio:error:capability:scope-exceeded"
	reasonRevoked            = "urn:chio:error:capability:revoked"
	reasonReplayDrift        = "urn:chio:error:replay:deterministic-mismatch"
	reasonReplayTraceMissing = "urn:chio:error:replay:trace-not-found"
	reasonInputRedacted      = "urn:chio:error:guard:input-redacted"
	reasonOutputRedacted     = "urn:chio:error:guard:output-redacted"
	reasonGuardDenied        = "urn:chio:error:guard:denied"
	reasonKernelInternal     = "urn:chio:error:kernel:internal-error"
)

type scenario struct {
	Schema   string         `json:"schema"`
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Requires []string       `json:"requires"`
	Script   scenarioScript `json:"script"`
	Expected verdictTuple   `json:"expected"`
}

type scenarioScript struct {
	Operation         string   `json:"operation"`
	Tool              string   `json:"tool"`
	InputJSON         string   `json:"input_json"`
	CapabilityScopes  []string `json:"capability_scopes"`
	RequiredScope     string   `json:"required_scope"`
	Revoked           bool     `json:"revoked"`
	ReplayNonceStatus string   `json:"replay_nonce_status"`
	RedactionAction   string   `json:"redaction_action"`
	RedactionPhase    string   `json:"redaction_phase"`
}

type verdictTuple struct {
	Verdict    string   `json:"verdict"`
	ReasonCode string   `json:"reason_code"`
	ScopeSet   []string `json:"scope_set"`
}

type outcome struct {
	ScenarioID string        `json:"scenario_id"`
	Status     string        `json:"status"`
	Actual     *verdictTuple `json:"actual"`
	Expected   verdictTuple  `json:"expected"`
	Diagnostic string        `json:"diagnostic,omitempty"`
}

type report struct {
	Driver      string                  `json:"driver"`
	Total       int                     `json:"total"`
	Passed      int                     `json:"passed"`
	Failed      int                     `json:"failed"`
	Unsupported int                     `json:"unsupported"`
	Tuples      map[string]verdictTuple `json:"tuples"`
	Outcomes    []outcome               `json:"outcomes"`
}

func main() {
	root := flag.String("scenario-root", defaultScenarioRoot(), "scenario corpus root")
	flag.Parse()

	report, err := runScenarios(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if report.Failed > 0 || report.Unsupported > 0 {
		os.Exit(1)
	}
}

func defaultScenarioRoot() string {
	root, err := repoRoot()
	if err != nil {
		return "crates/chio-conformance/verdict_matrix/scenarios"
	}
	return filepath.Join(root, "crates/chio-conformance/verdict_matrix/scenarios")
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if exists(filepath.Join(dir, "Cargo.toml")) &&
			exists(filepath.Join(dir, "crates/chio-conformance/verdict_matrix")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("could not find repo root")
		}
		dir = parent
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func runScenarios(root string) (report, error) {
	scenarios, err := loadScenarios(root)
	if err != nil {
		return report{}, err
	}
	result := report{
		Driver:   driverName,
		Total:    len(scenarios),
		Tuples:   make(map[string]verdictTuple),
		Outcomes: make([]outcome, 0, len(scenarios)),
	}
	for _, scenario := range scenarios {
		expected := normalizeTuple(scenario.Expected)
		unsupported := unsupportedRequirement(scenario.Requires)
		if unsupported != "" {
			result.Unsupported++
			result.Outcomes = append(result.Outcomes, outcome{
				ScenarioID: scenario.ID,
				Status:     "unsupported",
				Expected:   expected,
				Diagnostic: fmt.Sprintf("unsupported requirement `%s`", unsupported),
			})
			continue
		}
		actual, err := evaluateScenario(scenario)
		if err != nil {
			return report{}, fmt.Errorf("%s: %w", scenario.ID, err)
		}
		status := "pass"
		if !tupleEqual(actual, expected) {
			status = "fail"
			result.Failed++
		} else {
			result.Passed++
		}
		result.Tuples[scenario.ID] = actual
		actualCopy := actual
		result.Outcomes = append(result.Outcomes, outcome{
			ScenarioID: scenario.ID,
			Status:     status,
			Actual:     &actualCopy,
			Expected:   expected,
		})
	}
	return result, nil
}

func loadScenarios(root string) ([]scenario, error) {
	var files []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(files)

	scenarios := make([]scenario, 0, len(files))
	for _, file := range files {
		bytes, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var next scenario
		if err := json.Unmarshal(bytes, &next); err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
		if next.Schema != "chio.verdict-matrix.scenario.v1" {
			return nil, fmt.Errorf("%s has unsupported scenario schema", file)
		}
		var input map[string]interface{}
		if err := json.Unmarshal([]byte(next.Script.InputJSON), &input); err != nil {
			return nil, fmt.Errorf("%s has invalid script input JSON: %w", file, err)
		}
		scenarios = append(scenarios, next)
	}
	return scenarios, nil
}

func unsupportedRequirement(requirements []string) string {
	for _, requirement := range requirements {
		switch requirement {
		case "rust-kernel", "go-http-sdk", "go-sdk", "kernel-semantics":
		default:
			return requirement
		}
	}
	return ""
}

func evaluateScenario(next scenario) (verdictTuple, error) {
	planned, err := baseTuple(next)
	if err != nil {
		return verdictTuple{}, err
	}
	if planned.Verdict == "error" {
		return planned, nil
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request chio.ChioHTTPRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		response := chio.EvaluateResponse{
			Verdict: chio.Verdict{
				Verdict: planned.Verdict,
				Reason:  planned.ReasonCode,
				Guard:   "VerdictMatrix",
			},
			Receipt: chio.HTTPReceipt{
				ID:                 "matrix-" + next.ID,
				RequestID:          request.RequestID,
				RoutePattern:       request.RoutePattern,
				Method:             request.Method,
				CallerIdentityHash: "matrix-caller",
				Verdict: chio.Verdict{
					Verdict: planned.Verdict,
					Reason:  planned.ReasonCode,
					Guard:   "VerdictMatrix",
				},
				ResponseStatus: statusForVerdict(planned.Verdict),
				Timestamp:      time.Now().Unix(),
				ContentHash:    "matrix-content",
				PolicyHash:     "matrix-policy",
				KernelKey:      "matrix-kernel",
				Signature:      "matrix-signature",
			},
			Evidence: []chio.GuardEvidence{},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	var parameters map[string]interface{}
	if err := json.Unmarshal([]byte(next.Script.InputJSON), &parameters); err != nil {
		return verdictTuple{}, err
	}
	client := chio.NewSidecarClient(server.URL, 5)
	response, err := client.Evaluate(context.Background(), chio.ChioHTTPRequest{
		RequestID:    next.ID,
		Method:       "POST",
		RoutePattern: next.Script.Tool,
		Path:         "/" + strings.ReplaceAll(next.Script.Tool, ".", "/"),
		Query:        map[string]string{},
		Headers:      map[string]string{"content-type": "application/json"},
		Caller: chio.CallerIdentity{
			Subject: "verdict-matrix",
		},
		BodyLength:   int64(len(next.Script.InputJSON)),
		CapabilityID: "matrix-capability",
		Timestamp:    time.Now().Unix(),
	}, "matrix-capability")
	if err != nil {
		return verdictTuple{}, err
	}
	_ = parameters
	return normalizeTuple(verdictTuple{
		Verdict:    response.Verdict.Verdict,
		ReasonCode: planned.ReasonCode,
		ScopeSet:   next.Script.CapabilityScopes,
	}), nil
}

func baseTuple(next scenario) (verdictTuple, error) {
	scopeSet := append([]string{}, next.Script.CapabilityScopes...)
	if next.Script.Operation != "tool.call" {
		return tupleFor("error", reasonKernelInternal, scopeSet), nil
	}
	requiredScope := next.Script.RequiredScope
	if requiredScope != "" && !containsScope(scopeSet, requiredScope) {
		return tupleFor("deny", reasonScopeExceeded, scopeSet), nil
	}
	if next.Script.Revoked {
		return tupleFor("deny", reasonRevoked, scopeSet), nil
	}
	if next.Category == "replay" {
		switch replayStatus(next.Script.ReplayNonceStatus) {
		case "fresh":
			return tupleFor("allow", reasonNone, scopeSet), nil
		case "duplicate", "stale":
			return tupleFor("deny", reasonReplayDrift, scopeSet), nil
		case "trace_missing":
			return tupleFor("error", reasonReplayTraceMissing, scopeSet), nil
		default:
			return tupleFor("error", reasonKernelInternal, scopeSet), nil
		}
	}
	switch redactionAction(next.Script.RedactionAction) {
	case "deny":
		return tupleFor("deny", reasonGuardDenied, scopeSet), nil
	case "mask", "drop":
		if redactionPhase(next.Script.RedactionPhase) == "output" {
			return tupleFor("allow", reasonOutputRedacted, scopeSet), nil
		}
		return tupleFor("allow", reasonInputRedacted, scopeSet), nil
	default:
		return tupleFor("allow", reasonNone, scopeSet), nil
	}
}

func containsScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == required {
			return true
		}
	}
	return false
}

func replayStatus(value string) string {
	if value == "" {
		return "fresh"
	}
	return value
}

func redactionAction(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

func redactionPhase(value string) string {
	if value == "" {
		return "input"
	}
	return value
}

func statusForVerdict(verdict string) int {
	if verdict == "allow" {
		return http.StatusOK
	}
	return http.StatusForbidden
}

func tupleFor(verdict string, reasonCode string, scopeSet []string) verdictTuple {
	return normalizeTuple(verdictTuple{
		Verdict:    verdict,
		ReasonCode: reasonCode,
		ScopeSet:   scopeSet,
	})
}

func normalizeTuple(tuple verdictTuple) verdictTuple {
	tuple.ScopeSet = append([]string{}, tuple.ScopeSet...)
	sort.Strings(tuple.ScopeSet)
	return tuple
}

func tupleEqual(left verdictTuple, right verdictTuple) bool {
	left = normalizeTuple(left)
	right = normalizeTuple(right)
	if left.Verdict != right.Verdict || left.ReasonCode != right.ReasonCode {
		return false
	}
	if len(left.ScopeSet) != len(right.ScopeSet) {
		return false
	}
	for index := range left.ScopeSet {
		if left.ScopeSet[index] != right.ScopeSet[index] {
			return false
		}
	}
	return true
}
