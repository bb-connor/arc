import Foundation

import chio_kernel_mobile
public typealias VerifiedCapability = chio_kernel_mobile.CapabilityVerificationRecord
public typealias PortablePassportMetadata = chio_kernel_mobile.PortablePassportMetadata

public enum ChioBindingError: Error, Equatable {
    case bindingUnavailable
}

public struct ChioKernel {
    public init() {}

    public func evaluate(requestJson: String) throws -> String {
        return try chio_kernel_mobile.evaluate(requestJson: requestJson)
    }

    public func signReceipt(bodyJson: String, canonicalContentHex: String, signingSeedHex: String) throws -> String {
        return try chio_kernel_mobile.signReceipt(
            bodyJson: bodyJson,
            canonicalContentHex: canonicalContentHex,
            signingSeedHex: signingSeedHex
        )
    }

    public func verifyCapability(
        tokenJson: String,
        authorityPubHex: String
    ) throws -> VerifiedCapability {
        return try chio_kernel_mobile.verifyCapability(
            tokenJson: tokenJson,
            authorityPubHex: authorityPubHex
        )
    }

    public func verifyPassport(
        envelopeJson: String,
        issuerPubHex: String,
        nowSecs: Int64
    ) throws -> PortablePassportMetadata {
        return try chio_kernel_mobile.verifyPassport(
            envelopeJson: envelopeJson,
            issuerPubHex: issuerPubHex,
            nowSecs: nowSecs
        )
    }

    public func attestAppAttest(keyId: String, challengeHex: String) throws -> String {
        return try chio_kernel_mobile.attestAppAttest(
            keyId: keyId,
            challengeHex: challengeHex
        )
    }

    public func attestPlayIntegrity(nonceHex: String) throws -> String {
        return try chio_kernel_mobile.attestPlayIntegrity(nonceHex: nonceHex)
    }

    /// Inspect envelope shape only; this does not verify device integrity or authorize a call.
    public func inspectMobileReceiptEnvelopes(
        receiptJson: String,
        evidenceJson: String
    ) throws -> String {
        return try chio_kernel_mobile.inspectMobileReceiptEnvelopes(
            receiptJson: receiptJson,
            evidenceJson: evidenceJson
        )
    }
}
