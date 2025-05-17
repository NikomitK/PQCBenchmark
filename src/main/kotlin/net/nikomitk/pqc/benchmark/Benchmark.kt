package net.nikomitk.pqc.benchmark

import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import java.security.Security
import java.security.Signature
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.measureTime

fun main(args: Array<String>) {
    val parser = ArgParser("benchmark")
    val repetitions by parser.option(
        ArgType.Int,
        shortName = "r",
        description = "Number of test repetitions"
    ).default(50)

    val securityLevel by parser.option(
        type = ArgType.Choice<SecurityLevel>(),
        shortName = "s",
        description = "Security level of the signature"
    ).default(SecurityLevel.LOW)

    parser.parse(args)


    Security.addProvider(BouncyCastleProvider())
    Security.addProvider(BouncyCastlePQCProvider())
    val strings = arrayListOf<ByteArray>()
    repeat(repetitions, {
        strings.add(Random.nextBytes(10))
    })
    doBenchmark(securityLevel.value, strings)
}

fun doBenchmark(securityLevel: Int = 1, strings: ArrayList<ByteArray>) {
    val algorithms = arrayOf("ECDSA", "RSA", "MLDSA", "SLHDSA", "DILITHIUM", "SPHINCSPlus")


    for (algorithm in algorithms) {
        val signature = SignatureUtil.generateSignature(algorithm, securityLevel)
        val time = benchAlgorithm(signature, strings)
        println("$algorithm total time: $time")
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