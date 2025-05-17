package net.nikomitk.pqc.benchmark

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import java.security.Security
import java.security.Signature
import kotlin.time.Duration
import kotlin.time.measureTime

fun main() {
    Security.addProvider(BouncyCastleProvider())
    Security.addProvider(BouncyCastlePQCProvider())
    val strings = arrayOf<String>("Hello World", "Test123", "SLH-DSA ist cooler als ML-DSA", "SigniereMich")
    doBenchmark(securityLevel = 1, strings = strings)

}

fun doBenchmark(securityLevel: Int = 1, strings: Array<String> = arrayOf("Hello World")) {
    val algorithms = arrayOf("ECDSA", "RSA", "MLDSA", "SLHDSA", "DILITHIUM", "SPHINCSPlus")


    for (algorithm in algorithms) {
        val signature = SignatureUtil.generateSignature(algorithm, securityLevel)
        val time = benchAlgorithm(signature, strings)
        println("$algorithm total time: $time")
    }
}

fun benchAlgorithm(signature: Signature, strings: Array<String>): Duration {
    var totalTime = Duration.ZERO
    for (s in strings) {
        val message = s.toByteArray()
        signature.update(message, 0, message.size)
        totalTime += measureTime { signature.sign() }
    }
    return totalTime
}