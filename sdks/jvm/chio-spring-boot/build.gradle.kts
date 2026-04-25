plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.spring)
    alias(libs.plugins.springBoot) apply false
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    api(project(":chio-sdk-jvm"))
    implementation(platform(libs.springBoot.bom))
    implementation(libs.springBoot.starter.web)
    implementation(libs.kotlin.reflect)

    testImplementation(platform(libs.springBoot.bom))
    testImplementation(libs.springBoot.starter.test)
    testImplementation(libs.kotlin.test.junit5)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        freeCompilerArgs.add("-Xjsr305=strict")
        freeCompilerArgs.add("-Xannotation-default-target=param-property")
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}
