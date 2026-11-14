package com.pond.inspector.scan

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.pond.inspector.logic.AttestationParser
import com.pond.inspector.logic.KeyDescription
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

object Attestation {
    data class CertRow(
        val subject: String,
        val issuer: String,
        val serialHex: String,
        val sigAlg: String,
        val notAfter: String,
        val notBefore: String = "",
        val keyInfo: String = "",
    )

    data class Result(
        val error: String? = null,
        val hardware: Boolean = false,
        val levelName: String = "unknown",
        val strongBox: Boolean = false,
        val chain: List<CertRow> = emptyList(),
        val desc: KeyDescription? = null,
        val extensionPresent: Boolean = false,
        val challengeOk: Boolean? = null,
        val chainSigOk: Boolean = false,
        val chainDatesOk: Boolean = false,
        val rootSelfSigned: Boolean = false,
        val rootKind: String = "none",
        val googleRoot: Boolean = false,
        val appBound: Boolean? = null,
        val serials: List<String> = emptyList(),
        val keystoreWorks: Boolean = false,
        val attempts: List<String> = emptyList(),
        val mode: String = "",
    )

    private const val GOOGLE_RSA_ROOT_SERIAL = "f1c172a699eaf51d"

    private var cached: Pair<Long, Result>? = null

    @Synchronized
    fun read(context: android.content.Context): Result {
        val now = System.currentTimeMillis()
        cached?.let { (at, value) -> if (now - at < 30_000) return value }
        val fresh = try {
            generate(context)
        } catch (error: Exception) {
            Result(error = error.javaClass.simpleName + ": " + (error.message ?: ""))
        }
        cached = System.currentTimeMillis() to fresh
        return fresh
    }

    private fun name(cert: X509Certificate, issuer: Boolean): String {
        val dn = (if (issuer) cert.issuerX500Principal else cert.subjectX500Principal).name
        return dn.take(96)
    }

    private fun date(d: Date): String {
        val f = SimpleDateFormat("yyyy-MM-dd", Locale.US)
        f.timeZone = TimeZone.getTimeZone("UTC")
        return f.format(d)
    }

    private fun cause(error: Throwable): String {
        val parts = mutableListOf<String>()
        var current: Throwable? = error
        var depth = 0
        while (current != null && depth < 4) {
            parts += current.javaClass.simpleName + (current.message?.let { ": " + it.take(140) } ?: "")
            current = current.cause
            depth++
        }
        return parts.joinToString(" <- ")
    }

    private fun keyInfoText(cert: X509Certificate): String = try {
        when (val key = cert.publicKey) {
            is ECPublicKey -> "EC " + key.params.order.bitLength()
            is RSAPublicKey -> "RSA " + key.modulus.bitLength()
            else -> key.algorithm
        }
    } catch (_: Exception) {
        ""
    }

    private fun generate(context: android.content.Context): Result {
        val failures = mutableListOf<String>()
        for (mode in listOf("ec", "ec-verify", "rsa")) {
            try {
                return generateWith(context, mode, failures.toList())
            } catch (error: Throwable) {
                failures += "$mode: " + cause(error)
            }
        }
        var plainWorks = false
        var plainHardware = false
        var plainLevel = "unknown"
        val alias = "pond_plain_" + UUID.randomUUID().toString()
        try {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            generator.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .build(),
            )
            generator.generateKeyPair()
            plainWorks = true
            try {
                val key = store.getKey(alias, null)
                val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
                @Suppress("DEPRECATION")
                plainHardware = info.isInsideSecureHardware
                plainLevel = if (plainHardware) "hardware" else "software"
                if (Build.VERSION.SDK_INT >= 31) {
                    plainLevel = when (info.securityLevel) {
                        KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
                        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "trusted environment"
                        KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                        else -> plainLevel
                    }
                    plainHardware = info.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE
                }
            } catch (_: Exception) {
            }
            try {
                store.deleteEntry(alias)
            } catch (_: Exception) {
            }
        } catch (error: Throwable) {
            failures += "plain: " + cause(error)
        }
        return Result(
            error = failures.joinToString("\n").ifBlank { "attestation unavailable" },
            hardware = plainHardware,
            levelName = plainLevel,
            keystoreWorks = plainWorks,
            attempts = failures,
        )
    }

    @Suppress("DEPRECATION")
    private fun generateWith(context: android.content.Context, mode: String, earlier: List<String>): Result {
        val alias = "pond_" + UUID.randomUUID().toString()
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val challenge = ByteArray(24).also { SecureRandom().nextBytes(it) }
        try {
            val rsa = mode == "rsa"
            val builder = KeyGenParameterSpec.Builder(
                alias,
                if (mode == "ec-verify") KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY else KeyProperties.PURPOSE_SIGN,
            ).setAttestationChallenge(challenge)
            if (rsa) {
                builder.setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setKeySize(2048)
            } else {
                builder.setDigests(KeyProperties.DIGEST_SHA256)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            }
            val generator = KeyPairGenerator.getInstance(
                if (rsa) KeyProperties.KEY_ALGORITHM_RSA else KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore",
            )
            generator.initialize(builder.build())
            generator.generateKeyPair()
            val certs = store.getCertificateChain(alias).orEmpty().filterIsInstance<X509Certificate>()
            val leaf = certs.firstOrNull()
            val extension = leaf?.getExtensionValue(AttestationParser.OID)
            val desc = extension?.let { AttestationParser.parse(it) }

            var hardware = false
            var levelName = "unknown"
            try {
                val privateKey = store.getKey(alias, null) ?: throw IllegalStateException("keystore returned no private key")
                val info = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
                    .getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
                val level = if (Build.VERSION.SDK_INT >= 31) info.securityLevel else -1
                levelName = when (level) {
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "trusted environment"
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                    KeyProperties.SECURITY_LEVEL_UNKNOWN -> "unknown"
                    else -> if (info.isInsideSecureHardware) "hardware" else "software"
                }
                hardware = info.isInsideSecureHardware ||
                    level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                    level == KeyProperties.SECURITY_LEVEL_STRONGBOX
            } catch (_: Exception) {
                val attestedLevel = desc?.keymasterLevel
                if (attestedLevel != null) {
                    hardware = attestedLevel >= 1
                    levelName = if (attestedLevel >= 2) "strongbox" else if (attestedLevel == 1) "trusted environment" else "software"
                }
            }

            var sigOk = certs.isNotEmpty()
            for (i in 0 until certs.size - 1) {
                try {
                    certs[i].verify(certs[i + 1].publicKey)
                } catch (_: Exception) {
                    sigOk = false
                }
            }
            val root = certs.lastOrNull()
            val selfSigned = root != null && try {
                root.verify(root.publicKey)
                root.subjectX500Principal == root.issuerX500Principal
            } catch (_: Exception) {
                false
            }
            val datesOk = certs.isNotEmpty() && certs.all {
                try {
                    it.checkValidity()
                    true
                } catch (_: Exception) {
                    false
                }
            }
            val serial = root?.serialNumber?.toString(16).orEmpty()
            val serialMatch = serial == GOOGLE_RSA_ROOT_SERIAL
            val named = root != null && selfSigned &&
                root.subjectX500Principal.name.contains("Google", ignoreCase = true)
            val google = serialMatch || named
            val kind = when {
                root == null -> "none"
                serialMatch -> "Google hardware attestation root (serial match)"
                named -> "Google-named self-signed root (not pinned)"
                else -> "unknown root"
            }
            val challengeOk = desc?.let { it.challenge.contentEquals(challenge) }
            val appBound = desc?.let { d ->
                if (d.packages.isEmpty()) null else context.packageName in d.packages
            }

            var strongBox = false
            if (Build.VERSION.SDK_INT >= 28) {
                val strongAlias = alias + "_sb"
                try {
                    val g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                    g.initialize(
                        KeyGenParameterSpec.Builder(strongAlias, KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setIsStrongBoxBacked(true)
                            .build(),
                    )
                    g.generateKeyPair()
                    strongBox = true
                } catch (_: Throwable) {
                    strongBox = false
                } finally {
                    try {
                        store.deleteEntry(strongAlias)
                    } catch (_: Exception) {
                    }
                }
            }

            return Result(
                hardware = hardware,
                levelName = levelName,
                strongBox = strongBox,
                chain = certs.map {
                    CertRow(
                        name(it, false), name(it, true), it.serialNumber.toString(16), it.sigAlgName,
                        date(it.notAfter), date(it.notBefore), keyInfoText(it),
                    )
                },
                desc = desc,
                extensionPresent = extension != null,
                challengeOk = challengeOk,
                chainSigOk = sigOk,
                chainDatesOk = datesOk,
                rootSelfSigned = selfSigned,
                rootKind = kind,
                googleRoot = google,
                appBound = appBound,
                serials = certs.map { it.serialNumber.toString(16) },
                keystoreWorks = true,
                attempts = earlier,
                mode = mode,
            )
        } finally {
            try {
                store.deleteEntry(alias)
            } catch (_: Exception) {
            }
        }
    }
}
