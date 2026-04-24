/**
 * Asynchronous Chio evaluator. Wraps the blocking ChioClient on an
 * executor sized to config.maxInFlight, completing exactly one
 * EvaluationResult per input element. Mirrors the Python
 * ChioAsyncEvaluateFunction.
 *
 * Flink's AsyncFunction has no Context, so side outputs are NOT
 * available from this operator. Chain a ChioVerdictSplitFunction
 * downstream to recover the receipt / DLQ side outputs.
 */
package io.backbay.chio.flink

import io.backbay.chio.sdk.errors.ChioError
import org.apache.flink.api.common.functions.OpenContext
import org.apache.flink.streaming.api.functions.async.ResultFuture
import org.apache.flink.streaming.api.functions.async.RichAsyncFunction
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class ChioAsyncEvaluateFunction<IN>(
    private val config: ChioFlinkConfig<IN>,
) : RichAsyncFunction<IN, EvaluationResult<IN>>() {
    @Transient
    private var evaluator: ChioFlinkEvaluator<IN>? = null

    @Transient
    private var executor: ExecutorService? = null

    fun config(): ChioFlinkConfig<IN> = config

    override fun open(openContext: OpenContext) {
        super.open(openContext)
        val ev = ChioFlinkEvaluator(config)
        ev.bind(runtimeContext)
        evaluator = ev
        executor =
            Executors.newFixedThreadPool(
                maxOf(1, config.maxInFlight),
                NamedThreadFactory("chio-async-evaluate"),
            )
    }

    override fun close() {
        try {
            // Drain in-flight workers before closing the underlying client; on JDK 21+
            // ChioClient.close() actually shuts down the HTTP client and would race
            // with workers still inside evaluateToolCall(). Bounded wait keeps Flink
            // teardown from hanging if a worker is genuinely wedged.
            executor?.shutdownNow()?.also {
                executor?.awaitTermination(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            }
        } finally {
            evaluator?.shutdown()
            evaluator = null
            executor = null
            super.close()
        }
    }

    override fun asyncInvoke(
        value: IN,
        resultFuture: ResultFuture<EvaluationResult<IN>>,
    ) {
        val ev =
            evaluator ?: run {
                resultFuture.completeExceptionally(
                    IllegalStateException("ChioAsyncEvaluateFunction.asyncInvoke called before open()"),
                )
                return
            }
        val exec =
            executor ?: run {
                resultFuture.completeExceptionally(
                    IllegalStateException("ChioAsyncEvaluateFunction has no executor; open() not called"),
                )
                return
            }
        exec.execute {
            try {
                val outcome = ev.evaluate(value)
                val result =
                    EvaluationResult(
                        allowed = outcome.allowed,
                        element = outcome.element,
                        receiptBytes = outcome.receiptBytes,
                        dlqBytes = outcome.dlqBytes,
                    )
                resultFuture.complete(listOf(result))
            } catch (err: ChioError) {
                resultFuture.completeExceptionally(err)
            } catch (err: RuntimeException) {
                resultFuture.completeExceptionally(err)
            }
        }
    }

    private class NamedThreadFactory(
        private val prefix: String,
    ) : ThreadFactory {
        private val count = AtomicInteger(0)

        override fun newThread(r: Runnable): Thread {
            val t = Thread(r, "$prefix-${count.incrementAndGet()}")
            t.isDaemon = true
            return t
        }
    }

    companion object {
        private const val serialVersionUID: Long = 1L
        private const val SHUTDOWN_TIMEOUT_SECONDS: Long = 10
    }
}
