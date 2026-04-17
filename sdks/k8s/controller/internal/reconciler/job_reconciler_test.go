package reconciler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	arcapi "github.com/backbay/arc-k8s-controller/internal/arc"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("add clientgo scheme: %v", err)
	}
	if err := batchv1.AddToScheme(s); err != nil {
		t.Fatalf("add batchv1: %v", err)
	}
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	return s
}

// stubArcClient is an in-memory implementation of the ArcClient interface
// used for unit tests. It records calls and can be configured to fail.
type stubArcClient struct {
	mu            sync.Mutex
	mintCalls     int
	releaseCalls  int
	receiptCalls  int
	mintErr       error
	releaseErr    error
	receiptErr    error
	lastMint      arcapi.MintRequest
	lastRelease   arcapi.ReleaseRequest
	lastReceipt   arcapi.JobReceipt
	nextCapID     string
	nextReceiptID string
}

func (s *stubArcClient) Mint(_ context.Context, req arcapi.MintRequest) (*arcapi.CapabilityToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mintCalls++
	s.lastMint = req
	if s.mintErr != nil {
		return nil, s.mintErr
	}
	id := s.nextCapID
	if id == "" {
		id = fmt.Sprintf("cap-%d", s.mintCalls)
	}
	return &arcapi.CapabilityToken{
		ID:        id,
		Token:     "token-" + id,
		Issuer:    "issuer-test",
		Subject:   req.Subject,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
		Signature: "signature-test",
	}, nil
}

func (s *stubArcClient) Release(_ context.Context, req arcapi.ReleaseRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releaseCalls++
	s.lastRelease = req
	return s.releaseErr
}

func (s *stubArcClient) SubmitReceipt(_ context.Context, receipt arcapi.JobReceipt) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receiptCalls++
	s.lastReceipt = receipt
	if s.receiptErr != nil {
		return "", s.receiptErr
	}
	id := s.nextReceiptID
	if id == "" {
		id = fmt.Sprintf("rcpt-%d", s.receiptCalls)
	}
	return id, nil
}

func (s *stubArcClient) counts() (mint, release, receipt int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mintCalls, s.releaseCalls, s.receiptCalls
}

func governedJob() *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo",
			Namespace: "default",
			UID:       types.UID("job-uid-1"),
			Labels: map[string]string{
				LabelGoverned: "true",
			},
			Annotations: map[string]string{
				AnnotationScopes: "tools:search, tools:fetch",
			},
		},
	}
}

func ungovernedJob() *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo-ungov",
			Namespace: "default",
			UID:       types.UID("job-uid-2"),
		},
	}
}

func completedJob(base *batchv1.Job) *batchv1.Job {
	j := base.DeepCopy()
	j.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
	}
	now := metav1.NewTime(time.Now().UTC())
	j.Status.CompletionTime = &now
	j.Status.StartTime = &now
	return j
}

func failedJob(base *batchv1.Job) *batchv1.Job {
	j := base.DeepCopy()
	j.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
	}
	now := metav1.NewTime(time.Now().UTC())
	j.Status.StartTime = &now
	return j
}

func reconcileUntilStable(t *testing.T, r *JobReconciler, key types.NamespacedName) {
	t.Helper()
	// Reconcile a bounded number of times, exiting as soon as we get an empty
	// result with no requeue. This exercises idempotency.
	for i := 0; i < 10; i++ {
		res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
		if err != nil {
			t.Fatalf("reconcile returned error on iteration %d: %v", i, err)
		}
		if res.Requeue || res.RequeueAfter > 0 {
			continue
		}
		// Reconcile once more to confirm stability; if it still returns empty,
		// we are done.
		res2, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
		if err != nil {
			t.Fatalf("second reconcile error: %v", err)
		}
		if !res2.Requeue && res2.RequeueAfter == 0 {
			return
		}
	}
	t.Fatalf("reconcile did not stabilize")
}

func buildReconciler(t *testing.T, arc *stubArcClient, objs ...client.Object) (*JobReconciler, client.Client) {
	t.Helper()
	s := newScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&batchv1.Job{}).
		Build()
	r := NewJobReconciler(c, s, arc, record.NewFakeRecorder(32))
	// Shorten retry to keep tests fast.
	r.Retry = RetryPolicy{BaseDelay: 1 * time.Millisecond, MaxDelay: 2 * time.Millisecond, MaxAttempts: 3}
	return r, c
}

// Test (a): governed Job at creation mints a grant.
func TestReconcile_NewGovernedJob_MintsGrant(t *testing.T) {
	arc := &stubArcClient{nextCapID: "cap-abc"}
	job := governedJob()
	r, c := buildReconciler(t, arc, job)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}

	reconcileUntilStable(t, r, key)

	var got batchv1.Job
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get job: %v", err)
	}

	if got.Annotations[AnnotationCapabilityID] != "cap-abc" {
		t.Fatalf("expected capability-id annotation, got %q", got.Annotations[AnnotationCapabilityID])
	}
	if got.Annotations[AnnotationCapabilityToken] != "" {
		t.Fatalf("expected no top-level capability-token annotation, got %q", got.Annotations[AnnotationCapabilityToken])
	}
	if got.Spec.Template.Annotations[AnnotationCapabilityToken] != "token-cap-abc" {
		t.Fatalf("expected pod-template capability-token annotation, got %q", got.Spec.Template.Annotations[AnnotationCapabilityToken])
	}
	if _, err := time.Parse(time.RFC3339, got.Annotations[AnnotationCapabilityExpiresAt]); err != nil {
		t.Fatalf("invalid expires-at annotation %q: %v", got.Annotations[AnnotationCapabilityExpiresAt], err)
	}
	if !containsFinalizer(&got, FinalizerName) {
		t.Fatalf("expected finalizer %q on job", FinalizerName)
	}

	mint, release, receipt := arc.counts()
	if mint != 1 {
		t.Fatalf("expected exactly 1 mint call, got %d", mint)
	}
	if release != 0 || receipt != 0 {
		t.Fatalf("expected no release/receipt calls yet, got release=%d receipt=%d", release, receipt)
	}
	if len(arc.lastMint.Scopes) != 2 || arc.lastMint.Scopes[0] != "tools:search" {
		t.Fatalf("unexpected mint scopes: %#v", arc.lastMint.Scopes)
	}
}

// Test (b): completed governed Job releases grant and emits receipt.
func TestReconcile_CompletedJob_ReleasesAndEmitsReceipt(t *testing.T) {
	arc := &stubArcClient{nextCapID: "cap-ok", nextReceiptID: "rcpt-ok"}
	job := governedJob()
	// Pre-set: the mint has already happened.
	job.Annotations[AnnotationCapabilityID] = "cap-ok"
	job.Spec.Template.Annotations = map[string]string{AnnotationCapabilityToken: "token-cap-ok"}
	job.Annotations[AnnotationCapabilityExpiresAt] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	job.Finalizers = []string{FinalizerName}
	// Mark complete.
	job.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
	}
	now := metav1.NewTime(time.Now().UTC())
	job.Status.StartTime = &now
	job.Status.CompletionTime = &now

	// Add a pod owned by the job with a receipt annotation.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo-xyz",
			Namespace: job.Namespace,
			UID:       types.UID("pod-1"),
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Job", UID: job.UID, Name: job.Name, APIVersion: "batch/v1"},
			},
			Annotations: map[string]string{
				PodAnnotationReceipt: `{"step":"search","ok":true}`,
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
	}

	r, _ := buildReconciler(t, arc, job, pod)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}
	reconcileUntilStable(t, r, key)

	mint, release, receipt := arc.counts()
	if mint != 0 {
		t.Fatalf("expected no new mint (already present), got %d", mint)
	}
	if release != 1 {
		t.Fatalf("expected 1 release call, got %d", release)
	}
	if receipt != 1 {
		t.Fatalf("expected 1 receipt submission, got %d", receipt)
	}
	if arc.lastRelease.Reason != "succeeded" {
		t.Fatalf("expected release reason=succeeded, got %q", arc.lastRelease.Reason)
	}
	if arc.lastReceipt.Outcome != "succeeded" {
		t.Fatalf("expected receipt outcome=succeeded, got %q", arc.lastReceipt.Outcome)
	}
	if len(arc.lastReceipt.Steps) != 1 {
		t.Fatalf("expected 1 step receipt, got %d", len(arc.lastReceipt.Steps))
	}
	if arc.lastReceipt.Steps[0].PodName != "demo-xyz" {
		t.Fatalf("unexpected step pod name: %q", arc.lastReceipt.Steps[0].PodName)
	}
}

// Test (c): failed governed Job releases grant and emits receipt with
// outcome=failed.
func TestReconcile_FailedJob_ReleasesAndEmitsReceipt(t *testing.T) {
	arc := &stubArcClient{}
	job := governedJob()
	job.Annotations[AnnotationCapabilityID] = "cap-fail"
	job.Spec.Template.Annotations = map[string]string{AnnotationCapabilityToken: "token-cap-fail"}
	job.Annotations[AnnotationCapabilityExpiresAt] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	job.Finalizers = []string{FinalizerName}
	job.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobFailed, Status: corev1.ConditionTrue},
	}
	now := metav1.NewTime(time.Now().UTC())
	job.Status.StartTime = &now

	r, _ := buildReconciler(t, arc, job)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}
	reconcileUntilStable(t, r, key)

	_, release, receipt := arc.counts()
	if release != 1 {
		t.Fatalf("expected 1 release call, got %d", release)
	}
	if receipt != 1 {
		t.Fatalf("expected 1 receipt submission, got %d", receipt)
	}
	if arc.lastRelease.Reason != "failed" {
		t.Fatalf("expected release reason=failed, got %q", arc.lastRelease.Reason)
	}
	if arc.lastReceipt.Outcome != "failed" {
		t.Fatalf("expected receipt outcome=failed, got %q", arc.lastReceipt.Outcome)
	}
}

// Test (d): Jobs without the governed label are ignored entirely.
func TestReconcile_UngovernedJob_Ignored(t *testing.T) {
	arc := &stubArcClient{}
	job := ungovernedJob()
	r, c := buildReconciler(t, arc, job)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("reconcile returned error: %v", err)
	}
	if res.Requeue || res.RequeueAfter > 0 {
		t.Fatalf("unexpected requeue for ungoverned job: %#v", res)
	}

	var got batchv1.Job
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get job: %v", err)
	}
	if got.Annotations[AnnotationCapabilityID] != "" {
		t.Fatalf("ungoverned job should not have capability annotation, got %q",
			got.Annotations[AnnotationCapabilityID])
	}
	if containsFinalizer(&got, FinalizerName) {
		t.Fatalf("ungoverned job should not carry the finalizer")
	}

	mint, release, receipt := arc.counts()
	if mint != 0 || release != 0 || receipt != 0 {
		t.Fatalf("expected no arc calls for ungoverned job, got mint=%d release=%d receipt=%d",
			mint, release, receipt)
	}
}

// Fail-closed: if sidecar is unreachable during mint, requeue, don't proceed.
func TestReconcile_SidecarUnreachable_Requeues(t *testing.T) {
	arc := &stubArcClient{mintErr: fmt.Errorf("%w: connection refused", arcapi.ErrSidecarUnreachable)}
	job := governedJob()
	r, c := buildReconciler(t, arc, job)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}

	// First reconcile adds the finalizer; the call may or may not requeue.
	// The key assertion is that after at most a couple of reconciles, the
	// job has no capability annotation and the mint failure triggered a
	// requeue.
	var lastRes ctrl.Result
	for i := 0; i < 3; i++ {
		res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
		if err != nil {
			t.Fatalf("reconcile error: %v", err)
		}
		lastRes = res
	}

	if lastRes.RequeueAfter == 0 && !lastRes.Requeue {
		t.Fatalf("expected requeue on sidecar unreachable, got %#v", lastRes)
	}

	var got batchv1.Job
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("get job: %v", err)
	}
	if got.Annotations[AnnotationCapabilityID] != "" {
		t.Fatalf("expected no capability annotation after unreachable sidecar, got %q",
			got.Annotations[AnnotationCapabilityID])
	}
}

// Idempotency: reconciling a completed job twice must not cause duplicate
// release or receipt submission.
func TestReconcile_Idempotent(t *testing.T) {
	arc := &stubArcClient{}
	job := completedJob(governedJob())
	job.Annotations[AnnotationCapabilityID] = "cap-idem"
	job.Spec.Template.Annotations = map[string]string{AnnotationCapabilityToken: "token-cap-idem"}
	job.Annotations[AnnotationCapabilityExpiresAt] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	job.Finalizers = []string{FinalizerName}

	r, _ := buildReconciler(t, arc, job)
	key := types.NamespacedName{Namespace: job.Namespace, Name: job.Name}

	// Run reconcile several times; we expect only 1 release + 1 receipt.
	for i := 0; i < 5; i++ {
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatalf("iter %d: reconcile error: %v", i, err)
		}
	}

	_, release, receipt := arc.counts()
	if release != 1 {
		t.Fatalf("expected exactly 1 release, got %d", release)
	}
	if receipt != 1 {
		t.Fatalf("expected exactly 1 receipt submission, got %d", receipt)
	}
}

// Integration-ish test: drive the real arc.Client against an httptest server.
func TestArcClient_EndToEndViaHTTPStub(t *testing.T) {
	var mintCount, releaseCount, receiptCount int32

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/capabilities/mint", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&mintCount, 1)
		var req arcapi.MintRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := arcapi.MintResponse{Capability: arcapi.CapabilityToken{
			ID:        "server-cap",
			Issuer:    "issuer-server",
			Subject:   req.Subject,
			IssuedAt:  time.Now().UTC(),
			ExpiresAt: time.Now().Add(time.Hour).UTC(),
			Signature: "signature-server",
		}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/capabilities/release", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&releaseCount, 1)
		_ = json.NewEncoder(w).Encode(arcapi.ReleaseResponse{Released: true})
	})
	mux.HandleFunc("/v1/receipts", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&receiptCount, 1)
		_ = json.NewEncoder(w).Encode(arcapi.SubmitReceiptResponse{ReceiptID: "rcpt-server", Accepted: true})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := arcapi.NewClient(srv.URL, "", srv.Client())

	ctx := context.Background()
	cap, err := client.Mint(ctx, arcapi.MintRequest{Subject: "job/default/demo", Scopes: []string{"tools:search"}, JobUID: "u"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if cap.ID != "server-cap" {
		t.Fatalf("unexpected cap id: %q", cap.ID)
	}
	if err := client.Release(ctx, arcapi.ReleaseRequest{CapabilityID: cap.ID, JobUID: "u", Reason: "succeeded"}); err != nil {
		t.Fatalf("release: %v", err)
	}
	rid, err := client.SubmitReceipt(ctx, arcapi.JobReceipt{JobName: "demo", Namespace: "default", JobUID: "u", Outcome: "succeeded"})
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if rid != "rcpt-server" {
		t.Fatalf("unexpected receipt id: %q", rid)
	}
	if atomic.LoadInt32(&mintCount) != 1 || atomic.LoadInt32(&releaseCount) != 1 || atomic.LoadInt32(&receiptCount) != 1 {
		t.Fatalf("unexpected call counts: mint=%d release=%d receipt=%d",
			mintCount, releaseCount, receiptCount)
	}
}

// 5xx responses from the sidecar should be reported as ErrSidecarUnreachable.
func TestArcClient_ServerError_IsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	client := arcapi.NewClient(srv.URL, "", srv.Client())
	_, err := client.Mint(context.Background(), arcapi.MintRequest{Subject: "job/x/y", JobUID: "u"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !isUnreachable(err) {
		t.Fatalf("expected ErrSidecarUnreachable, got %v", err)
	}
}

func TestArcClient_SendsControlBearerToken(t *testing.T) {
	var authHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		resp := arcapi.MintResponse{Capability: arcapi.CapabilityToken{
			ID:        "server-cap",
			Issuer:    "issuer-server",
			Subject:   "job/default/demo",
			IssuedAt:  time.Now().UTC(),
			ExpiresAt: time.Now().Add(time.Hour).UTC(),
			Signature: "signature-server",
		}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := arcapi.NewClient(srv.URL, "cluster-control-token", srv.Client())
	if _, err := client.Mint(
		context.Background(),
		arcapi.MintRequest{Subject: "job/default/demo", JobUID: "u"},
	); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if authHeader != "Bearer cluster-control-token" {
		t.Fatalf("expected bearer auth header, got %q", authHeader)
	}
}

// Receipt aggregation: backoff grows with retries.
func TestBackoff_GrowsExponentially(t *testing.T) {
	arc := &stubArcClient{}
	r, _ := buildReconciler(t, arc)
	r.Retry = RetryPolicy{BaseDelay: 1 * time.Millisecond, MaxDelay: 16 * time.Millisecond, MaxAttempts: 5}

	uid := types.UID("u")
	var last time.Duration
	for i := 0; i < 5; i++ {
		d := r.backoffFor(uid, retryPhaseReceipt)
		if d < last && d != r.Retry.MaxDelay {
			t.Fatalf("backoff decreased at iteration %d: %v -> %v", i, last, d)
		}
		last = d
	}
	if !r.attemptExceeded(uid, retryPhaseReceipt) {
		t.Fatalf("expected attemptExceeded to be true after MaxAttempts")
	}
	// Release phase has an independent budget.
	if r.attemptExceeded(uid, retryPhaseRelease) {
		t.Fatalf("release phase should not share the receipt budget")
	}
}

func containsFinalizer(job *batchv1.Job, name string) bool {
	for _, f := range job.Finalizers {
		if f == name {
			return true
		}
	}
	return false
}

func isUnreachable(err error) bool {
	return err != nil && (err == arcapi.ErrSidecarUnreachable || errorsIs(err, arcapi.ErrSidecarUnreachable))
}

// errorsIs is a local wrapper so test code compiles without re-importing
// errors in both directions.
func errorsIs(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := e.(unwrapper)
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
