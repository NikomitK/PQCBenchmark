package net.nikomitk.pqc.benchmark

import kotlinx.cli.ArgParser
import kotlinx.cli.ArgType
import kotlinx.cli.default
import kotlinx.cli.multiple
import org.apache.commons.csv.CSVFormat
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider
import java.io.PrintWriter
import java.io.Writer
import java.security.Security
import java.security.Signature
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.measureTime

val results = ArrayList<Result>()

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
    ).multiple().default(SecurityLevel.entries)

    val algorithms by parser.option(
        type = ArgType.Choice<Algorithm>(),
        shortName = "a",
        description = "Algorithms to benchmark"
    ).multiple().default(Algorithm.entries)

    parser.parse(args)

    println("Starting benchmark with $repetitions repetitions and security level $securityLevel. \nAlgorithms: $algorithms")


    Security.addProvider(BouncyCastleProvider())
    Security.addProvider(BouncyCastlePQCProvider())
    val strings = arrayListOf<ByteArray>()
    repeat(repetitions, {
        strings.add(Random.nextBytes(10))
    })
    for (level in securityLevel) {
        doBenchmark(level, strings, algorithms)
    }
    PrintWriter(System.out).writeCsv(results)
}

fun doBenchmark(
    securityLevel: SecurityLevel = SecurityLevel.LOW,
    strings: ArrayList<ByteArray>,
    algorithms: List<Algorithm>
) {

    for (algorithm in algorithms) {
        val signature = SignatureUtil.generateSignature(algorithm, securityLevel)
        val time = benchAlgorithm(signature, strings)
        println("$algorithm-${securityLevel.value} total time: $time")
        results.add(Result(algorithm.value, securityLevel, time))
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

fun Writer.writeCsv(results: List<Result>) {
    CSVFormat.DEFAULT.print(this).apply {
        printRecord("Algorithm", "Security Level (bits)", "Time (µs")
        for (result in results) {
            printRecord(result.algorithm, result.securityLevel.value, result.time.inWholeMicroseconds)
        }
    }.flush()
}