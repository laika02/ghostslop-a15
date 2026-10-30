import java.security.MessageDigest

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.ghostlock.bootstrap"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.ghostlock.bootstrap"
        minSdk = 30
        targetSdk = 35
        versionCode = 32
        versionName = "0.9.23"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

val repoRoot = rootProject.projectDir.parentFile
val payloadSources = mapOf(
    "ghostlock-a15" to repoRoot.resolve("ghostlock-a15"),
    "g4d" to repoRoot.resolve("g4d"),
    "g4sh" to repoRoot.resolve("g4sh"),
    "g4d-su" to repoRoot.resolve("g4d-su"),
    "g4su" to repoRoot.resolve("g4su"),
    "g4mount" to repoRoot.resolve("g4mount"),
    "g4exec" to repoRoot.resolve("g4exec"),
    "defex-exec.sh" to repoRoot.resolve("scripts/defex-exec.sh"),
)
val payloadHashes = mapOf(
    "ghostlock-a15" to "392b205b05c6eda39f4ecc401109859a38b7d585ff90912e85fdf5861a8a0617",
    "g4d" to "9664ec30c732f39ea8978cfbe3add7c3a68459ea1c3cb5b324ac6d306238dab5",
    "g4sh" to "ffd2dbf559967b6219b2c02481f0f402f919477e644a1d4e8548bdda751a1326",
    "g4d-su" to "d3ae0d0bfba8beb0aabd101d56d01f82484ab227bfe2111f15cd939f777249aa",
    "g4su" to "90ad28ac750f300682bb30290fe2fa0ec2aa6cff32ac210268fbb1b7c8e8544b",
    "g4mount" to "8dbbb8ccee5629079eadb6b1d2f561068675a7ba81bab53613d08ac87c1c6b06",
    "g4exec" to "d431fb90b3525f5667a69105391caf44cb51cf6e91ec708f98343575366254fa",
    "defex-exec.sh" to "aa8169c254a7f6d8dd52949b25a7a17d37c59e2586849ea9a4a327461026b53d",
)
val generatedPayload = layout.buildDirectory.dir("generated/payloadAssets")
val preparePayload = tasks.register("preparePayloadAssets") {
    inputs.files(payloadSources.values)
    outputs.dir(generatedPayload)

    doLast {
        val outputDir = generatedPayload.get().asFile
        outputDir.deleteRecursively()
        outputDir.mkdirs()

        payloadHashes.forEach { (name, expectedHash) ->
            val source = payloadSources.getValue(name)
            if (!source.isFile) {
                throw GradleException("Missing local payload $source. Build the GhostSlop native targets first.")
            }
            val actualHash = MessageDigest.getInstance("SHA-256")
                .digest(source.readBytes())
                .joinToString("") { "%02x".format(it) }
            if (actualHash != expectedHash) {
                throw GradleException("Refusing unpinned $name payload: expected $expectedHash, found $actualHash")
            }
            val payloadDir = outputDir.resolve("payload").apply { mkdirs() }
            source.copyTo(payloadDir.resolve(name), overwrite = true)
        }
    }
}

android.sourceSets.getByName("main").assets.srcDir(generatedPayload)
tasks.named("preBuild").configure { dependsOn(preparePayload) }

dependencies {
    implementation(project(":adb-kt"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
}
