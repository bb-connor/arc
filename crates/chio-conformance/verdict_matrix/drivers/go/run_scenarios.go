package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	chio "github.com/backbay/chio/sdks/go/chio-go-http"
)

const driverName = "go-http-sdk"
const matrixServerID = "verdict-matrix"

const (
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
	if report.Failed > 0 {
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
			result.Failed++
			result.Outcomes = append(result.Outcomes, outcome{
				ScenarioID: scenario.ID,
				Status:     "fail",
				Expected:   expected,
				Diagnostic: err.Error(),
			})
			continue
		}
		actual = normalizeTuple(actual)
		result.Tuples[scenario.ID] = actual
		status := "pass"
		if !tuplesEqual(actual, expected) {
			status = "fail"
			result.Failed++
		} else {
			result.Passed++
		}
		result.Outcomes = append(result.Outcomes, outcome{
			ScenarioID: scenario.ID,
			Status:     status,
			Actual:     &actual,
			Expected:   expected,
			Diagnostic: mismatchDiagnostic(actual, expected),
		})
	}
	return result, nil
}

func evaluateScenario(scenario scenario) (verdictTuple, error) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/chio/evaluate" {
			return matrixHTTPResponse(http.StatusNotFound, map[string]string{"error": "not found"}), nil
		}
		if r.Header.Get("X-Chio-Capability") == "" {
			return matrixHTTPResponse(http.StatusBadRequest, map[string]string{"error": "missing capability token"}), nil
		}
		var req chio.ChioHTTPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return matrixHTTPResponse(http.StatusBadRequest, map[string]string{"error": "invalid Chio request: " + err.Error()}), nil
		}
		tuple, err := evaluateMatrixTuple(scenario)
		if err != nil {
			tuple = verdictTuple{
				Verdict:    "error",
				ReasonCode: reasonKernelInternal,
				ScopeSet:   scenario.Script.CapabilityScopes,
			}
		}
		responseStatus := http.StatusOK
		if tuple.Verdict == "deny" {
			responseStatus = http.StatusForbidden
		}
		response := chio.EvaluateResponse{
			Verdict: chio.Verdict{
				Verdict:    tuple.Verdict,
				Reason:     reasonForWire(tuple.ReasonCode),
				Guard:      guardForReason(tuple.ReasonCode),
				HTTPStatus: responseStatus,
			},
			Receipt: chio.HTTPReceipt{
				ID:                 "verdict-matrix-" + scenario.ID,
				RequestID:          req.RequestID,
				RoutePattern:       req.RoutePattern,
				Method:             req.Method,
				CallerIdentityHash: "verdict-matrix-caller",
				SessionID:          req.SessionID,
				Verdict: chio.Verdict{
					Verdict:    tuple.Verdict,
					Reason:     reasonForWire(tuple.ReasonCode),
					Guard:      guardForReason(tuple.ReasonCode),
					HTTPStatus: responseStatus,
				},
				Evidence:       []chio.GuardEvidence{},
				ResponseStatus: responseStatus,
				Timestamp:      req.Timestamp,
				ContentHash:    "verdict-matrix-content",
				PolicyHash:     "verdict-matrix-policy",
				CapabilityID:   req.CapabilityID,
				KernelKey:      "verdict-matrix-kernel",
				Signature:      "verdict-matrix-signature",
			},
			Evidence: []chio.GuardEvidence{},
		}
		return matrixHTTPResponse(http.StatusOK, response), nil
	})

	previousTransport := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() {
		http.DefaultTransport = previousTransport
	}()

	client := chio.NewSidecarClient("http://verdict-matrix.local", 5)
	body := json.RawMessage(scenario.Script.InputJSON)
	response, err := client.Evaluate(context.Background(), chio.ChioHTTPRequest{
		RequestID:    scenario.ID,
		Method:       http.MethodPost,
		RoutePattern: scenario.Script.Tool,
		Path:         "/verdict-matrix/" + scenario.ID,
		Headers:      map[string]string{"content-type": "application/json"},
		Caller:       chio.AnonymousIdentity(),
		BodyLength:   int64(len(body)),
		SessionID:    matrixServerID,
		CapabilityID: scenario.ID,
		Timestamp:    time.Now().Unix(),
	}, capabilityToken(scenario.ID))
	if err != nil {
		return verdictTuple{}, err
	}
	return normalizeTuple(verdictTuple{
		Verdict:    response.Verdict.Verdict,
		ReasonCode: reasonFromWire(response.Verdict),
		ScopeSet:   scenario.Script.CapabilityScopes,
	}), nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func matrixHTTPResponse(status int, body any) *http.Response {
	payload, err := json.Marshal(body)
	if err != nil {
		status = http.StatusInternalServerError
		payload = []byte(`{"error":"failed to encode matrix response"}`)
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body:          io.NopCloser(bytes.NewReader(payload)),
		ContentLength: int64(len(payload)),
	}
}

func evaluateMatrixTuple(scenario scenario) (verdictTuple, error) {
	script := scenario.Script
	scopeSet := append([]string{}, script.CapabilityScopes...)
	if script.Operation != "tool.call" {
		return verdictTuple{
			Verdict:    "error",
			ReasonCode: reasonKernelInternal,
			ScopeSet:   scopeSet,
		}, nil
	}
	if scenario.Category == "revocation" && script.Revoked {
		return verdictTuple{
			Verdict:    "deny",
			ReasonCode: reasonRevoked,
			ScopeSet:   scopeSet,
		}, nil
	}
	if !hasScope(scopeSet, script.RequiredScope) {
		return verdictTuple{
			Verdict:    "deny",
			ReasonCode: reasonScopeExceeded,
			ScopeSet:   scopeSet,
		}, nil
	}
	switch scenario.Category {
	case "capability", "revocation":
		return verdictTuple{
			Verdict:    "allow",
			ReasonCode: reasonNone,
			ScopeSet:   scopeSet,
		}, nil
	case "replay":
		return replayTuple(script, scopeSet), nil
	case "redaction":
		return redactionTuple(script, scopeSet), nil
	default:
		return verdictTuple{}, fmt.Errorf("unsupported scenario category `%s`", scenario.Category)
	}
}

func replayTuple(script scenarioScript, scopeSet []string) verdictTuple {
	switch script.ReplayNonceStatus {
	case "", "fresh":
		return verdictTuple{Verdict: "allow", ReasonCode: reasonNone, ScopeSet: scopeSet}
	case "duplicate", "stale":
		return verdictTuple{Verdict: "deny", ReasonCode: reasonReplayDrift, ScopeSet: scopeSet}
	case "trace_missing":
		return verdictTuple{Verdict: "error", ReasonCode: reasonReplayTraceMissing, ScopeSet: scopeSet}
	default:
		return verdictTuple{Verdict: "error", ReasonCode: reasonKernelInternal, ScopeSet: scopeSet}
	}
}

func redactionTuple(script scenarioScript, scopeSet []string) verdictTuple {
	switch script.RedactionAction {
	case "", "none":
		return verdictTuple{Verdict: "allow", ReasonCode: reasonNone, ScopeSet: scopeSet}
	case "deny":
		return verdictTuple{Verdict: "deny", ReasonCode: reasonGuardDenied, ScopeSet: scopeSet}
	case "mask", "drop":
		if script.RedactionPhase == "output" {
			return verdictTuple{Verdict: "allow", ReasonCode: reasonOutputRedacted, ScopeSet: scopeSet}
		}
		return verdictTuple{Verdict: "allow", ReasonCode: reasonInputRedacted, ScopeSet: scopeSet}
	default:
		return verdictTuple{Verdict: "error", ReasonCode: reasonKernelInternal, ScopeSet: scopeSet}
	}
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

func capabilityToken(id string) string {
	token, err := json.Marshal(map[string]string{"id": id})
	if err != nil {
		return ""
	}
	return string(token)
}

func hasScope(scopeSet []string, requiredScope string) bool {
	if requiredScope == "" {
		return true
	}
	for _, scope := range scopeSet {
		if scope == requiredScope {
			return true
		}
	}
	return false
}

func normalizeTuple(tuple verdictTuple) verdictTuple {
	tuple.ScopeSet = append([]string{}, tuple.ScopeSet...)
	sort.Strings(tuple.ScopeSet)
	return tuple
}

func tuplesEqual(left, right verdictTuple) bool {
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

func mismatchDiagnostic(actual, expected verdictTuple) string {
	if tuplesEqual(actual, expected) {
		return ""
	}
	return fmt.Sprintf("tuple mismatch: expected %s, actual %s", formatTuple(expected), formatTuple(actual))
}

func formatTuple(tuple verdictTuple) string {
	tuple = normalizeTuple(tuple)
	bytes, err := json.Marshal(tuple)
	if err != nil {
		return fmt.Sprintf("%+v", tuple)
	}
	return string(bytes)
}

func reasonForWire(reasonCode string) string {
	if reasonCode == reasonNone {
		return ""
	}
	return reasonCode
}

func reasonFromWire(verdict chio.Verdict) string {
	if verdict.Verdict == "allow" && verdict.Reason == "" {
		return reasonNone
	}
	if verdict.Reason == "" {
		return reasonKernelInternal
	}
	return verdict.Reason
}

func guardForReason(reasonCode string) string {
	switch reasonCode {
	case reasonScopeExceeded, reasonRevoked:
		return "CapabilityGuard"
	case reasonInputRedacted, reasonOutputRedacted, reasonGuardDenied:
		return "VerdictMatrixGuard"
	case reasonReplayDrift, reasonReplayTraceMissing:
		return "ReplayGuard"
	default:
		return ""
	}
}
