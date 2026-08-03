package chio

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestChioToolCallRequestPreservesApprovalSetAndOpaqueExtension(t *testing.T) {
	digest := strings.Repeat("0", 64)
	publicKey := strings.Repeat("1", 64)
	signature := strings.Repeat("2", 128)
	request := ChioToolCallRequest{
		Type:     "tool_call_request",
		ID:       "request-go-1",
		ServerID: "server-go-1",
		Tool:     "execute",
		Params:   json.RawMessage(`{"amount":7}`),
		ApprovalTokens: []CapabilityGovernedApprovalToken{
			{Id: "approval-a"},
			{Id: "approval-b"},
		},
		ThresholdApprovalProposal: &CapabilityThresholdApprovalProposal{
			Body: CapabilityThresholdApprovalProposalBody{
				AuthorizationCapabilityHash: digest,
				EligibleSetDigest:           digest,
				GovernedIntentHash:          digest,
				PolicyHash:                  digest,
				ProposalCreatedAt:           1,
				ProposalDeadline:            2,
				ProposalId:                  "proposal-go-1",
				RequestId:                   "request-go-1",
				Required:                    1,
				Schema:                      CapabilityThresholdApprovalProposalBodySchemaChioThresholdApprovalProposalV1,
				Subject:                     publicKey,
			},
			PolicyAuthority: publicKey,
			Signature:       signature,
		},
		SupplementalAuthorization: &CapabilitySupplementalAuthorization{
			SignedExtension: "b3BhcXVl",
		},
	}

	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	var approvals []CapabilityGovernedApprovalToken
	if err := json.Unmarshal(decoded["approval_tokens"], &approvals); err != nil {
		t.Fatalf("unmarshal approvals: %v", err)
	}
	if len(approvals) != 2 || approvals[0].Id != "approval-a" || approvals[1].Id != "approval-b" {
		t.Fatalf("approval set changed: %#v", approvals)
	}
	var supplemental CapabilitySupplementalAuthorization
	if err := json.Unmarshal(decoded["supplemental_authorization"], &supplemental); err != nil {
		t.Fatalf("unmarshal supplemental authorization: %v", err)
	}
	if supplemental.SignedExtension != "b3BhcXVl" {
		t.Fatalf("supplemental authorization changed: %#v", supplemental)
	}
}
