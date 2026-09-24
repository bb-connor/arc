package chio

// Caller wire decoders preserve the signed representation and reject malformed
// domains. They do not authenticate signatures, executor pins, or durable claims.

import (
	"bytes"
	"fmt"
	"unicode/utf8"
)

const callerMaxSafeInteger int64 = 9007199254740991

func checkCallerPositiveIntegers(values ...int64) error {
	for _, value := range values {
		if value < 1 || value > callerMaxSafeInteger {
			return fmt.Errorf("caller integer outside the positive interoperable domain")
		}
	}
	return nil
}

func (a *KernelCallerDispatchAuthorization) UnmarshalJSON(data []byte) error {
	// Bound raw input as well as the native canonical-encoding limit.
	if len(data) > 32768 {
		return fmt.Errorf("caller dispatch authorization exceeds 32 KiB")
	}
	type wire KernelCallerDispatchAuthorization
	var decoded wire
	if err := decodeProtocolObject(data, &decoded); err != nil {
		return err
	}
	body := decoded.Authorization
	commit := body.Committed.DispatchCommit
	if body.Schema != "chio.caller-dispatch-authorization.v1" {
		return fmt.Errorf("invalid caller dispatch authorization domain")
	}
	if err := checkCallerPositiveIntegers(body.Executor.KeyEpoch, body.NotBeforeUnixMs,
		body.ExpiresAtUnixMs, commit.CommittedVersion, commit.CoordinatorLeaseEpoch,
		commit.StoreFence.OwnerEpoch, commit.ProviderAttempt.TransportKeyEpoch); err != nil {
		return err
	}
	*a = KernelCallerDispatchAuthorization(decoded)
	return nil
}

func (r *KernelCallerDeliveryReport) UnmarshalJSON(data []byte) error {
	type wire KernelCallerDeliveryReport
	var decoded wire
	if err := decodeProtocolObject(data, &decoded); err != nil {
		return err
	}
	body := decoded.Report
	if body.Schema != "chio.caller-delivery-report.v1" {
		return fmt.Errorf("invalid caller delivery report domain")
	}
	if err := checkCallerPositiveIntegers(body.Executor.KeyEpoch,
		body.ExecutionStartedAtUnixMs, body.CompletedAtUnixMs); err != nil {
		return err
	}
	// The generated raw union must be either explicit null or the exact cost
	// object. Validate before replacing the receiver or retaining opaque bytes.
	cost := body.RealizedCost.union
	if !bytes.Equal(bytes.TrimSpace(cost), []byte("null")) {
		var amount KernelCallerDeliveryReportReportRealizedCost1
		if err := decodeProtocolObject(cost, &amount); err != nil {
			return err
		}
		if amount.Units < 0 || amount.Units > callerMaxSafeInteger ||
			utf8.RuneCountInString(amount.Currency) < 1 || utf8.RuneCountInString(amount.Currency) > 64 {
			return fmt.Errorf("invalid caller realized cost domain")
		}
	}
	*r = KernelCallerDeliveryReport(decoded)
	return nil
}
