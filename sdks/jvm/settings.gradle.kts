pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_PROJECT)
    repositories { mavenCentral() }
    versionCatalogs {
        create("libs") {
            from(files("gradle/chio.versions.toml"))
        }
    }
}

rootProject.name = "chio-jvm"

include(":chio-sdk-jvm")
include(":chio-spring-boot")
include(":chio-streaming-flink")
