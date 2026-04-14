package arc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SidecarClient communicates with the ARC Rust kernel running as a
// localhost sidecar. It sends evaluation requests over HTTP and returns
// signed receipts.
type SidecarClient struct {
	baseURL string
	client  *http.Client
}

// NewSidecarClient creates a new sidecar client.
func NewSidecarClient(baseURL string, timeoutSeconds int) *SidecarClient {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 5
	}
	return &SidecarClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

// SidecarError represents an error from the ARC sidecar.
type SidecarError struct {
	Code       string
	Message    string
	StatusCode int
}

func (e *SidecarError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("arc sidecar %s (HTTP %d): %s", e.Code, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("arc sidecar %s: %s", e.Code, e.Message)
}

// Evaluate sends an HTTP request to the ARC sidecar for evaluation.
// Returns the verdict, signed receipt, and guard evidence.
func (c *SidecarClient) Evaluate(ctx context.Context, req ArcHTTPRequest) (*EvaluateResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, &SidecarError{
			Code:    ErrEvaluationFailed,
			Message: "failed to marshal request: " + err.Error(),
		}
	}

	url := c.baseURL + "/arc/evaluate"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, &SidecarError{
			Code:    ErrSidecarUnreachable,
			Message: "failed to create request: " + err.Error(),
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, &SidecarError{
			Code:    ErrSidecarUnreachable,
			Message: "failed to reach sidecar at " + c.baseURL + ": " + err.Error(),
		}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &SidecarError{
			Code:    ErrSidecarUnreachable,
			Message: "failed to read response body: " + err.Error(),
		}
	}

	if resp.StatusCode >= 400 {
		return nil, &SidecarError{
			Code:       ErrEvaluationFailed,
			Message:    "sidecar returned " + resp.Status + ": " + string(respBody),
			StatusCode: resp.StatusCode,
		}
	}

	var result EvaluateResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, &SidecarError{
			Code:    ErrEvaluationFailed,
			Message: "failed to decode response: " + err.Error(),
		}
	}

	return &result, nil
}

// VerifyReceipt asks the sidecar to verify a receipt signature.
// Returns true if valid.
func (c *SidecarClient) VerifyReceipt(ctx context.Context, receipt HTTPReceipt) (bool, error) {
	body, err := json.Marshal(receipt)
	if err != nil {
		return false, &SidecarError{
			Code:    ErrInvalidReceipt,
			Message: "failed to marshal receipt: " + err.Error(),
		}
	}

	url := c.baseURL + "/arc/verify"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, &SidecarError{
			Code:    ErrSidecarUnreachable,
			Message: "failed to create request: " + err.Error(),
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return false, &SidecarError{
			Code:    ErrSidecarUnreachable,
			Message: "failed to reach sidecar: " + err.Error(),
		}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, nil
	}
	return result.Valid, nil
}

// HealthCheck checks whether the sidecar is running.
func (c *SidecarClient) HealthCheck(ctx context.Context) (bool, error) {
	url := c.baseURL + "/arc/health"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return false, nil
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	return resp.StatusCode == http.StatusOK, nil
}
