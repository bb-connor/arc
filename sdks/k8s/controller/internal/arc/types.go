// Package arc provides data structures and an HTTP client for interacting
// with the ARC sidecar from the Kubernetes Job controller.
//
// The controller talks to the ARC sidecar over HTTP to mint capability
// grants at Job creation, release them at Job completion, and submit
// aggregated JobReceipts to the ARC receipt store.
package arc

import "time"

// CapabilityToken is an ARC capability token minted by the sidecar.
//
// The controller treats the token as an opaque bearer value from the Job's
// point of view: it is stored on the Job as an annotation so that Pods and
// sidecars within the Job can reference it.
type CapabilityToken struct {
	// ID is the unique identifier of the capability grant.
	ID string `json:"id"`
	// Token is the opaque serialized capability token.
	Token string `json:"token"`
	// Subject is the principal the capability was minted for (the Job).
	Subject string `json:"subject"`
	// Scopes is the list of scopes granted by the capability.
	Scopes []string `json:"scopes"`
	// IssuedAt is the time the capability was issued.
	IssuedAt time.Time `json:"issued_at"`
	// ExpiresAt is the time the capability expires.
	ExpiresAt time.Time `json:"expires_at"`
}

// MintRequest requests a capability grant for a Kubernetes Job.
type MintRequest struct {
	// Subject is typically "job/<namespace>/<name>".
	Subject string `json:"subject"`
	// Scopes requested by the Job (drawn from the Job's annotations).
	Scopes []string `json:"scopes"`
	// Labels mirrors the governed Job's labels (for audit).
	Labels map[string]string `json:"labels,omitempty"`
	// TTL is an optional time-to-live for the grant.
	TTL time.Duration `json:"ttl,omitempty"`
	// JobUID is the Kubernetes UID of the Job (for idempotency).
	JobUID string `json:"job_uid"`
}

// ReleaseRequest asks the ARC sidecar to revoke an outstanding capability.
type ReleaseRequest struct {
	// CapabilityID identifies the grant to release.
	CapabilityID string `json:"capability_id"`
	// JobUID is the UID of the governed Job.
	JobUID string `json:"job_uid"`
	// Reason is a free-form reason (e.g., "completed", "failed", "deleted").
	Reason string `json:"reason"`
}

// StepReceipt is a single receipt emitted by a Pod step within a governed Job.
//
// Pods attach receipts to themselves via the ARC receipt annotation. The
// controller harvests them during reconciliation and aggregates them into a
// JobReceipt at Job completion.
type StepReceipt struct {
	// PodName is the name of the Pod that emitted the receipt.
	PodName string `json:"pod_name"`
	// Phase mirrors the Pod phase at the time the receipt was observed.
	Phase string `json:"phase"`
	// Payload is the opaque receipt bytes (base64-wrapped JSON by convention).
	Payload string `json:"payload"`
	// ObservedAt is the time the receipt was observed by the controller.
	ObservedAt time.Time `json:"observed_at"`
}

// JobReceipt is the aggregate receipt emitted when a governed Job terminates.
type JobReceipt struct {
	// JobName is the Kubernetes Job name.
	JobName string `json:"job_name"`
	// Namespace is the Job namespace.
	Namespace string `json:"namespace"`
	// JobUID is the Job UID.
	JobUID string `json:"job_uid"`
	// CapabilityID is the grant that governed the Job, if any.
	CapabilityID string `json:"capability_id,omitempty"`
	// Outcome is one of "succeeded" or "failed".
	Outcome string `json:"outcome"`
	// StartedAt is when the Job started.
	StartedAt time.Time `json:"started_at"`
	// CompletedAt is when the Job reached a terminal state.
	CompletedAt time.Time `json:"completed_at"`
	// Steps are the aggregated pod receipts.
	Steps []StepReceipt `json:"steps"`
}

// MintResponse wraps the mint endpoint response.
type MintResponse struct {
	Capability CapabilityToken `json:"capability"`
}

// ReleaseResponse wraps the release endpoint response.
type ReleaseResponse struct {
	Released bool `json:"released"`
}

// SubmitReceiptResponse wraps the submit-receipt endpoint response.
type SubmitReceiptResponse struct {
	ReceiptID string `json:"receipt_id"`
	Accepted  bool   `json:"accepted"`
}
