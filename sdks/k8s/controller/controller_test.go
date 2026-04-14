package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// buildAdmissionReview creates an AdmissionReview with a pod having the given annotations.
func buildAdmissionReview(t *testing.T, annotations map[string]string) []byte {
	t.Helper()

	pod := PodSpec{
		APIVersion: "v1",
		Kind:       "Pod",
		Metadata: Metadata{
			Name:        "test-pod",
			Namespace:   "default",
			Annotations: annotations,
		},
	}
	pod.Spec.Containers = []Container{
		{
			Name:  "app",
			Image: "myapp:latest",
		},
	}

	podBytes, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("failed to marshal pod: %v", err)
	}

	review := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: AdmissionRequest{
			UID: "test-uid-001",
			Kind: GroupKind{
				Group:   "",
				Version: "v1",
				Kind:    "Pod",
			},
			Namespace: "default",
			Name:      "test-pod",
			Object:    RawObject{Raw: podBytes},
		},
	}

	reviewBytes, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("failed to marshal review: %v", err)
	}
	return reviewBytes
}

func TestValidate_RejectWithoutCapability(t *testing.T) {
	body := buildAdmissionReview(t, map[string]string{})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if review.Response == nil {
		t.Fatal("expected response")
	}
	if review.Response.Allowed {
		t.Fatal("expected pod to be rejected without capability token")
	}
	if review.Response.UID != "test-uid-001" {
		t.Fatalf("expected UID test-uid-001, got %s", review.Response.UID)
	}
}

func TestValidate_AllowWithCapability(t *testing.T) {
	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: "cap-token-abc123",
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !review.Response.Allowed {
		t.Fatal("expected pod to be allowed with capability token")
	}
}

func TestValidate_AllowExempt(t *testing.T) {
	body := buildAdmissionReview(t, map[string]string{
		AnnotationExempt: "true",
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !review.Response.Allowed {
		t.Fatal("expected exempt pod to be allowed")
	}
}

func TestValidate_RejectInvalidScopes(t *testing.T) {
	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: "cap-token-abc123",
		AnnotationRequiredScopes:  "read,,write",
	})

	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if review.Response.Allowed {
		t.Fatal("expected pod to be rejected with invalid scopes")
	}
}

func TestMutate_NoInjectionWithoutAnnotation(t *testing.T) {
	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: "cap-token-abc123",
	})

	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleMutate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !review.Response.Allowed {
		t.Fatal("expected allowed response")
	}
	if review.Response.Patch != nil {
		t.Fatal("expected no patch when injection not requested")
	}
}

func TestMutate_InjectSidecar(t *testing.T) {
	body := buildAdmissionReview(t, map[string]string{
		AnnotationCapabilityToken: "cap-token-abc123",
		AnnotationInject:          "true",
		AnnotationUpstream:        "http://127.0.0.1:3000",
		AnnotationSpecPath:        "/etc/arc/openapi.yaml",
	})

	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleMutate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !review.Response.Allowed {
		t.Fatal("expected allowed response with injection")
	}
	if review.Response.PatchType == nil || *review.Response.PatchType != "JSONPatch" {
		t.Fatal("expected JSONPatch patch type")
	}
	if review.Response.Patch == nil {
		t.Fatal("expected patch data")
	}

	// Verify patch content.
	var patches []PatchOperation
	if err := json.Unmarshal(review.Response.Patch, &patches); err != nil {
		t.Fatalf("failed to parse patch: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch operation, got %d", len(patches))
	}
	if patches[0].Op != "add" {
		t.Fatalf("expected add operation, got %s", patches[0].Op)
	}
	if patches[0].Path != "/spec/containers/-" {
		t.Fatalf("expected path /spec/containers/-, got %s", patches[0].Path)
	}

	// Verify sidecar container.
	containerBytes, err := json.Marshal(patches[0].Value)
	if err != nil {
		t.Fatalf("failed to marshal container: %v", err)
	}
	var container Container
	if err := json.Unmarshal(containerBytes, &container); err != nil {
		t.Fatalf("failed to unmarshal container: %v", err)
	}
	if container.Name != "arc-sidecar" {
		t.Fatalf("expected container name arc-sidecar, got %s", container.Name)
	}
	if container.Image != DefaultSidecarImage {
		t.Fatalf("expected image %s, got %s", DefaultSidecarImage, container.Image)
	}
}

func TestMutate_CustomSidecarImage(t *testing.T) {
	body := buildAdmissionReview(t, map[string]string{
		AnnotationInject:       "true",
		AnnotationSidecarImage: "myregistry/arc:v1.0",
	})

	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handleMutate(rec, req)

	var review AdmissionReview
	if err := json.NewDecoder(rec.Body).Decode(&review); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	var patches []PatchOperation
	if err := json.Unmarshal(review.Response.Patch, &patches); err != nil {
		t.Fatalf("failed to parse patch: %v", err)
	}

	containerBytes, _ := json.Marshal(patches[0].Value)
	var container Container
	_ = json.Unmarshal(containerBytes, &container)

	if container.Image != "myregistry/arc:v1.0" {
		t.Fatalf("expected custom image, got %s", container.Image)
	}
}

func TestHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handleHealthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestBuildSidecarContainer_Defaults(t *testing.T) {
	container := buildSidecarContainer(map[string]string{})

	if container.Name != "arc-sidecar" {
		t.Fatalf("expected arc-sidecar, got %s", container.Name)
	}
	if container.Image != DefaultSidecarImage {
		t.Fatalf("expected default image, got %s", container.Image)
	}
	if len(container.Ports) != 1 || container.Ports[0].ContainerPort != 9090 {
		t.Fatal("expected port 9090")
	}
	if container.ReadinessProbe == nil {
		t.Fatal("expected readiness probe")
	}
}

func TestBuildSidecarContainer_WithAnnotations(t *testing.T) {
	annotations := map[string]string{
		AnnotationSidecarImage: "custom:v2",
		AnnotationUpstream:     "http://127.0.0.1:5000",
		AnnotationSpecPath:     "/app/spec.yaml",
		AnnotationReceiptStore: "sqlite:///data/receipts.db",
	}

	container := buildSidecarContainer(annotations)

	if container.Image != "custom:v2" {
		t.Fatalf("expected custom:v2, got %s", container.Image)
	}

	// Verify args contain upstream, spec, and receipt-store.
	argsStr := ""
	for _, arg := range container.Args {
		argsStr += arg + " "
	}
	if !contains(container.Args, "--upstream") {
		t.Fatal("expected --upstream in args")
	}
	if !contains(container.Args, "--spec") {
		t.Fatal("expected --spec in args")
	}
	if !contains(container.Args, "--receipt-store") {
		t.Fatal("expected --receipt-store in args")
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
