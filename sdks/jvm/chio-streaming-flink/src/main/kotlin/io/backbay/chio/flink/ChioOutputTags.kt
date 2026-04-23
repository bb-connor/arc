/**
 * Receipt / DLQ side-output tag constants. Names MUST be wire-stable.
 * Mirrors RECEIPT_TAG_NAME / DLQ_TAG_NAME / _receipt_tag / _dlq_tag in
 * chio_streaming/flink.py:75-139.
 *
 * Factory methods are lazy because OutputTag<ByteArray> requires the
 * Flink classpath (compileOnly dependency in this module); call them
 * only from operator code that runs after open() completes.
 */
package io.backbay.chio.flink

import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.streaming.api.datastream.DataStream
import org.apache.flink.util.OutputTag

object ChioOutputTags {
    const val RECEIPT_TAG_NAME: String = "chio-receipt"
    const val DLQ_TAG_NAME: String = "chio-dlq"

    @JvmStatic
    fun receiptTag(): OutputTag<ByteArray> = OutputTag(RECEIPT_TAG_NAME, TypeInformation.of(ByteArray::class.java))

    @JvmStatic
    fun dlqTag(): OutputTag<ByteArray> = OutputTag(DLQ_TAG_NAME, TypeInformation.of(ByteArray::class.java))

    // DataStream import keeps IDEs happy when users build the split
    // output pipeline; unused at module scope but documents intent.
    @Suppress("unused")
    private val dataStreamClass: Class<DataStream<*>> = DataStream::class.java
}
