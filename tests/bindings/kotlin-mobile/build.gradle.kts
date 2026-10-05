plugins {
    kotlin("jvm") version "1.9.24"
    application
}

repositories { mavenCentral() }
dependencies { implementation("net.java.dev.jna:jna:5.14.0") }
kotlin { jvmToolchain(21) }

layout.buildDirectory.set(file(providers.gradleProperty("chioKotlinBuildDir").get()))
kotlin.sourceSets.named("main") {
    kotlin.srcDir(providers.environmentVariable("CHIO_KOTLIN_NATIVE_SOURCE").get())
}
application { mainClass.set("QualificationKt") }
tasks.named<JavaExec>("run") {
    systemProperty("jna.library.path", providers.environmentVariable("CHIO_KOTLIN_NATIVE_LIB_DIR").get())
}
