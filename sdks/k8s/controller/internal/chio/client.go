package arc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client talks to the Chio sidecar HTTP API.
//
// The sidecar exposes three endpoints that the Job controller cares about:
//
//   - POST {base}/v1/capabilities/mint      — mint a capability grant
//   - POST {base}/v1/capabilities/release   — release a capability grant
//   - POST {base}/v1/receipts               — submit a JobReceipt
//
// The client is deliberately small: no retries, no backoff. Retry and
// backoff policy is driven by the reconciler so that it composes with
// controller-runtime's requeue semantics and its rate limiter.
type Client struct {
	baseURL      string
	controlToken string
	httpClient   *http.Client
}

// NewClient constructs a Client with a sensible default HTTP timeout.
//
// A nil httpClient falls back to a new http.Client with a 10-second timeout.
func NewClient(baseURL, controlToken string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		baseURL:      baseURL,
		controlToken: controlToken,
		httpClient:   httpClient,
	}
}

// ErrSidecarUnreachable is returned when the client cannot reach the sidecar
// at all (network error, DNS failure, connection refused, etc.).
//
// The reconciler uses this sentinel to distinguish transient transport
// failures (worth requeuing) from logical errors (bad request, etc.).
var ErrSidecarUnreachable = errors.New("arc: sidecar unreachable")

// Mint requests a capability grant for a governed Job.
func (c *Client) Mint(ctx context.Context, req MintRequest) (*CapabilityToken, error) {
	var resp MintResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/capabilities/mint", req, &resp); err != nil {
		return nil, err
	}
	return &resp.Capability, nil
}

// Release asks the sidecar to revoke a capability grant.
func (c *Client) Release(ctx context.Context, req ReleaseRequest) error {
	var resp ReleaseResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/capabilities/release", req, &resp); err != nil {
		return err
	}
	if !resp.Released {
		return fmt.Errorf("arc: sidecar refused release of capability %q", req.CapabilityID)
	}
	return nil
}

// SubmitReceipt submits the aggregated JobReceipt to the Chio receipt store.
func (c *Client) SubmitReceipt(ctx context.Context, receipt JobReceipt) (string, error) {
	var resp SubmitReceiptResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/receipts", receipt, &resp); err != nil {
		return "", err
	}
	if !resp.Accepted {
		return "", fmt.Errorf("arc: sidecar rejected receipt for job %q", receipt.JobName)
	}
	return resp.ReceiptID, nil
}

// doJSON is an internal helper that JSON-encodes body, issues the request,
// and JSON-decodes the response. A non-2xx status code is surfaced as a
// typed error carrying the response body for diagnostic purposes.
func (c *Client) doJSON(ctx context.Context, method, path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("arc: marshal %s body: %w", path, err)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("arc: build request %s: %w", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.controlToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.controlToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSidecarUnreachable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("arc: read response from %s: %w", url, err)
	}

	if resp.StatusCode >= 500 {
		// Treat 5xx as transient/unreachable so the reconciler requeues.
		return fmt.Errorf("%w: status=%d body=%s", ErrSidecarUnreachable, resp.StatusCode, string(respBody))
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("arc: %s returned %d: %s", url, resp.StatusCode, string(respBody))
	}

	if out == nil || len(respBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("arc: decode response from %s: %w", url, err)
	}
	return nil
}
