/**
 * Typealias shims that keep the legacy `io.backbay.chio.*` imports
 * working for one release after the SDK moved to the new module.
 * Remove in 0.2.0.
 */
@file:JvmName("ChioSdkAliases")

package io.backbay.chio

typealias AuthMethod = io.backbay.chio.sdk.AuthMethod
typealias CallerIdentity = io.backbay.chio.sdk.CallerIdentity
typealias Verdict = io.backbay.chio.sdk.Verdict
typealias GuardEvidence = io.backbay.chio.sdk.GuardEvidence
typealias HttpReceipt = io.backbay.chio.sdk.HttpReceipt
typealias ChioHttpRequest = io.backbay.chio.sdk.ChioHttpRequest
typealias EvaluateResponse = io.backbay.chio.sdk.EvaluateResponse
typealias ChioPassthrough = io.backbay.chio.sdk.ChioPassthrough
typealias ChioErrorResponse = io.backbay.chio.sdk.ChioErrorResponse
typealias ChioErrorCodes = io.backbay.chio.sdk.ChioErrorCodes
