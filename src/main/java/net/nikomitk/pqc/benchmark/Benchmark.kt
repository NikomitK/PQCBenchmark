package net.nikomitk.pqc.benchmark

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import java.security.Security
import java.security.Signature
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.measureTime

val results = ArrayList< SignatureUtil.Result>()

fun main() {
    // Register Bouncy Castle providers
    Security.addProvider(BouncyCastleProvider())
    Security.addProvider(BouncyCastlePQCProvider())

    // Number of test repetitions
    val repetitions = 50

    // Security level of the signature
    val securityLevel = SignatureUtil.SecurityLevel.entries

    // Signature schemes to benchmark
    val algorithms = SignatureUtil.Algorithm.entries

    println("Starting benchmark with $repetitions repetitions and security level $securityLevel. \nAlgorithms: $algorithms")

    // generate random byte arrays for testing
    val strings = arrayListOf<ByteArray>()
    repeat(repetitions, {
        strings.add(Random.nextBytes(10))
    })
    for (level in securityLevel) {
        doBenchmark(level, strings, algorithms)
    }
}

fun doBenchmark(
    securityLevel: SignatureUtil.SecurityLevel = SignatureUtil.SecurityLevel.LOW,
    strings: ArrayList<ByteArray>,
    algorithms: List<SignatureUtil.Algorithm>
) {

    for (algorithm in algorithms) {
        val signature = SignatureUtil.generateSignature(algorithm, securityLevel)
        val time = benchAlgorithm(signature, strings)
        println("$algorithm-${securityLevel.value} total time: $time")
        results.add(SignatureUtil.Result(algorithm.value, securityLevel, time))
    }
}

fun benchAlgorithm(signature: Signature, strings: ArrayList<ByteArray>): Duration {
    var totalTime = Duration.ZERO
    for (s in strings) {

        signature.update(s, 0, s.size)
        totalTime += measureTime { signature.sign() }
    }
    return totalTime
}