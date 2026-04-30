package chio

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestVerdictMatrixGoDriverMatchesCorpus(t *testing.T) {
	root := filepath.Clean("../../..")
	driverPath := filepath.Join(
		root,
		"crates/chio-conformance/verdict_matrix/drivers/go/run_scenarios.go",
	)
	scenarioRoot := filepath.Join(
		root,
		"crates/chio-conformance/verdict_matrix/scenarios",
	)
	cmd := exec.Command(
		"go",
		"run",
		driverPath,
		"--scenario-root",
		scenarioRoot,
	)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatalf("verdict matrix driver failed: %v\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("verdict matrix driver failed: %v", err)
	}

	var report struct {
		Driver      string                    `json:"driver"`
		Total       int                       `json:"total"`
		Passed      int                       `json:"passed"`
		Failed      int                       `json:"failed"`
		Unsupported int                       `json:"unsupported"`
		Tuples      map[string]map[string]any `json:"tuples"`
		Outcomes    []struct {
			ScenarioID string `json:"scenario_id"`
			Status     string `json:"status"`
			Diagnostic string `json:"diagnostic"`
		} `json:"outcomes"`
	}
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatalf("decode verdict matrix report: %v\n%s", err, output)
	}

	if report.Driver != "go-http-sdk" {
		t.Fatalf("expected go-http-sdk driver, got %q", report.Driver)
	}
	if report.Total != 48 || report.Passed != 48 || report.Failed != 0 || report.Unsupported != 0 {
		t.Fatalf("unexpected report counts: %+v", report)
	}
	if len(report.Tuples) != 48 {
		t.Fatalf("expected 48 emitted tuples, got %d", len(report.Tuples))
	}
	if len(report.Outcomes) != 48 {
		t.Fatalf("expected 48 outcomes, got %d", len(report.Outcomes))
	}
	for _, outcome := range report.Outcomes {
		if outcome.Status != "pass" {
			t.Fatalf("verdict-matrix tuple divergence for %s: status=%s diagnostic=%s", outcome.ScenarioID, outcome.Status, outcome.Diagnostic)
		}
		if outcome.Diagnostic != "" {
			t.Fatalf("unexpected diagnostic for %s: %s", outcome.ScenarioID, outcome.Diagnostic)
		}
	}
	readExact := report.Tuples["capability-subset-001-read-exact"]
	if readExact["verdict"] != "allow" || readExact["reason_code"] != "urn:chio:error:none" {
		t.Fatalf("unexpected read-exact tuple: %+v", readExact)
	}
	missingWrite := report.Tuples["capability-subset-007-missing-write"]
	if missingWrite["verdict"] != "deny" || missingWrite["reason_code"] != "urn:chio:error:capability:scope-exceeded" {
		t.Fatalf("unexpected missing-write tuple: %+v", missingWrite)
	}
	missingTrace := report.Tuples["replay-verdict-004-missing-trace"]
	if missingTrace["verdict"] != "error" || missingTrace["reason_code"] != "urn:chio:error:replay:trace-not-found" {
		t.Fatalf("unexpected missing-trace tuple: %+v", missingTrace)
	}
	outputMask := report.Tuples["redaction-determinism-002-output-mask-read"]
	if outputMask["verdict"] != "allow" || outputMask["reason_code"] != "urn:chio:error:guard:output-redacted" {
		t.Fatalf("unexpected output-mask tuple: %+v", outputMask)
	}
}
