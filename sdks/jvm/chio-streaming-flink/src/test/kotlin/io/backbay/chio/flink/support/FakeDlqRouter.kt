package io.backbay.chio.flink.support

import io.backbay.chio.sdk.ChioReceipt
import io.backbay.chio.sdk.DlqRecord
import io.backbay.chio.sdk.DlqRouter
import java.io.Serializable
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Records every buildRecord call for assertions while still producing
 * wire-canonical DLQ records via the real DlqRouter.
 */
class FakeDlqRouter(
    private val delegate: DlqRouter = DlqRouter(defaultTopic = "chio-dlq"),
) : Serializable {
    @Transient
    val records: MutableList<DlqRecord> = CopyOnWriteArrayList()

    fun asRouter(): DlqRouter = delegate

    fun buildRecord(
        sourceTopic: String,
        requestId: String,
        receipt: ChioReceipt,
    ): DlqRecord {
        val record =
            delegate.buildRecord(
                sourceTopic = sourceTopic,
                requestId = requestId,
                receipt = receipt,
            )
        records.add(record)
        return record
    }

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}
