/*
 * Pond
 * Copyright (C) 2026 @deepcodecreate
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import java.security.SecureRandom
import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

val releaseKeystore = file("release.keystore")
val keystoreProps = file("keystore.properties")

if (!releaseKeystore.exists() || !keystoreProps.exists()) {
    runCatching {
        val random = SecureRandom()
        val alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
        val password = (1..24).map { alphabet[random.nextInt(alphabet.length)] }.joinToString("")
        releaseKeystore.delete()
        val keytool = File(System.getProperty("java.home"), "bin/keytool").absolutePath
        val process = ProcessBuilder(
            keytool, "-genkeypair", "-v",
            "-keystore", releaseKeystore.absolutePath,
            "-alias", "pond",
            "-keyalg", "RSA", "-keysize", "4096", "-validity", "36500",
            "-storepass", password, "-keypass", password,
            "-dname", "CN=Pond, OU=Pond, O=Pond, C=US",
        ).redirectErrorStream(true).start()
        process.inputStream.readBytes()
        check(process.waitFor() == 0 && releaseKeystore.exists())
        keystoreProps.writeText("storeFile=release.keystore\nalias=pond\npassword=$password\n")
    }
}

val signingProps = Properties().apply {
    if (keystoreProps.exists()) keystoreProps.inputStream().use { load(it) }
}

android {
    namespace = "com.pond.inspector"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.pond.inspector"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (signingProps.getProperty("password") != null) {
            create("release") {
                storeFile = file(signingProps.getProperty("storeFile", "release.keystore"))
                storePassword = signingProps.getProperty("password")
                keyAlias = signingProps.getProperty("alias", "pond")
                keyPassword = signingProps.getProperty("password")
            }
        }
    }

    buildTypes {
        release {
            signingConfigs.findByName("release")?.let { signingConfig = it }
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        freeCompilerArgs.addAll(
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api",
            "-opt-in=androidx.compose.material3.windowsizeclass.ExperimentalMaterial3WindowSizeClassApi",
            "-opt-in=androidx.compose.foundation.layout.ExperimentalLayoutApi",
            "-opt-in=androidx.compose.foundation.ExperimentalFoundationApi",
            "-opt-in=androidx.compose.animation.ExperimentalAnimationApi",
        )
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.9.2")
    implementation("androidx.navigation:navigation-compose:2.9.0")
    implementation("androidx.datastore:datastore-preferences:1.1.7")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.1")

    implementation("androidx.compose.ui:ui:1.9.4")
    implementation("androidx.compose.ui:ui-graphics:1.9.4")
    implementation("androidx.compose.ui:ui-tooling-preview:1.9.4")
    implementation("androidx.compose.foundation:foundation:1.9.4")
    implementation("androidx.compose.animation:animation:1.9.4")
    implementation("androidx.compose.material3:material3:1.4.0")
    implementation("androidx.compose.material3:material3-window-size-class:1.4.0")
    implementation("androidx.compose.material:material-icons-extended:1.7.8")
    implementation("androidx.graphics:graphics-shapes:1.0.1")
    implementation("androidx.window:window:1.4.0")
    implementation("androidx.profileinstaller:profileinstaller:1.4.1")

    debugImplementation("androidx.compose.ui:ui-tooling:1.9.4")
    debugImplementation("androidx.compose.ui:ui-test-manifest:1.9.4")

    testImplementation("junit:junit:4.13.2")
}
