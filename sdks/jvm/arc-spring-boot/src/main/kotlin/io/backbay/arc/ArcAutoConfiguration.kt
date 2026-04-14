/**
 * Spring Boot auto-configuration for ARC protection.
 *
 * Automatically registers the ARC servlet filter as a bean when the
 * spring-boot-starter is on the classpath. Configuration is read from
 * application.properties/yaml under the `arc` prefix.
 *
 * Usage in application.properties:
 *   arc.sidecar-url=http://127.0.0.1:9090
 *   arc.timeout-seconds=5
 *   arc.on-sidecar-error=deny
 */
package io.backbay.arc

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/** Configuration properties for the ARC filter. */
@ConfigurationProperties(prefix = "arc")
data class ArcProperties(
    /** Base URL of the ARC sidecar kernel. */
    val sidecarUrl: String = System.getenv("ARC_SIDECAR_URL") ?: "http://127.0.0.1:9090",

    /** HTTP timeout for sidecar calls in seconds. */
    val timeoutSeconds: Long = 5,

    /** Behavior when sidecar is unreachable: "deny" (fail-closed) or "allow" (fail-open). */
    val onSidecarError: String = "deny",

    /** Whether ARC protection is enabled. Defaults to true. */
    val enabled: Boolean = true,

    /** URL patterns to protect. Defaults to all ("/*"). */
    val urlPatterns: List<String> = listOf("/*"),

    /** Filter order. Lower values run first. */
    val filterOrder: Int = 1,
)

/** Spring Boot auto-configuration for ARC protection. */
@Configuration
@EnableConfigurationProperties(ArcProperties::class)
@ConditionalOnClass(ArcFilter::class)
@ConditionalOnProperty(prefix = "arc", name = ["enabled"], havingValue = "true", matchIfMissing = true)
open class ArcAutoConfiguration {

    @Bean
    open fun arcFilterRegistration(properties: ArcProperties): FilterRegistrationBean<ArcFilter> {
        val config = ArcFilterConfig(
            sidecarUrl = properties.sidecarUrl,
            timeoutSeconds = properties.timeoutSeconds,
            onSidecarError = properties.onSidecarError,
        )

        val filter = ArcFilter(config)
        val registration = FilterRegistrationBean(filter)
        registration.urlPatterns = properties.urlPatterns
        registration.order = properties.filterOrder
        registration.setName("arcFilter")
        return registration
    }
}
