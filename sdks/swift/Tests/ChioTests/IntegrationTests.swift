import Foundation
import XCTest
@testable import Chio

final class IntegrationTests: XCTestCase {
    func testAppAttestChallengeCallsBundledRustKernel() throws {
        let kernel = ChioKernel()
        let raw = try kernel.attestAppAttest(keyId: "app-key", challengeHex: "01020304")
        let result = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any]
        )
        XCTAssertEqual(result["schema"] as? String, "chio.mobile.app-attest.challenge.v1")
        XCTAssertEqual(result["key_id"] as? String, "app-key")
        XCTAssertEqual(result["challenge_hex"] as? String, "01020304")
    }

    func testReceiptInspectionStaysNonAuthoritative() throws {
        let kernel = ChioKernel()
        let raw = try kernel.inspectMobileReceiptEnvelopes(
            receiptJson: #"{"schema":"chio.mobile.receipt.v1","receipt_id":"sdk-test"}"#,
            evidenceJson: #"{"schema":"chio.mobile.attestation-evidence.v1","platform":"app_attest"}"#
        )
        let result = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any]
        )
        XCTAssertEqual(result["schema"] as? String, "chio.mobile.receipt-inspection.v1")
        XCTAssertEqual(result["status"] as? String, "shape_only")
        XCTAssertEqual(result["authoritative"] as? Bool, false)
        XCTAssertEqual(result["authorized"] as? Bool, false)
    }

    func testReceiptInspectionRejectsInvalidEnvelope() throws {
        XCTAssertThrowsError(
            try ChioKernel().inspectMobileReceiptEnvelopes(receiptJson: "{}", evidenceJson: "{}")
        ) { error in
            XCTAssertFalse(error is ChioBindingError, "the bundled Rust binding must be available")
        }
    }
}
