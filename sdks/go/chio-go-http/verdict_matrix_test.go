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
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verdict matrix driver failed: %v\n%s", err, output)
	}

	var report struct {
		Driver      string                    `json:"driver"`
		Total       int                       `json:"total"`
		Passed      int                       `json:"passed"`
		Failed      int                       `json:"failed"`
		Unsupported int                       `json:"unsupported"`
		Tuples      map[string]map[string]any `json:"tuples"`
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
		t.Fatalf("expected 48 tuples, got %d", len(report.Tuples))
	}

	readExact := report.Tuples["capability-subset-001-read-exact"]
	if readExact["verdict"] != "allow" || readExact["reason_code"] != "urn:chio:error:none" {
		t.Fatalf("unexpected read tuple: %+v", readExact)
	}
	missingWrite := report.Tuples["capability-subset-007-missing-write"]
	if missingWrite["verdict"] != "deny" ||
		missingWrite["reason_code"] != "urn:chio:error:capability:scope-exceeded" {
		t.Fatalf("unexpected missing write tuple: %+v", missingWrite)
	}
	traceMissing := report.Tuples["replay-verdict-004-missing-trace"]
	if traceMissing["verdict"] != "error" ||
		traceMissing["reason_code"] != "urn:chio:error:replay:trace-not-found" {
		t.Fatalf("unexpected trace missing tuple: %+v", traceMissing)
	}
}
