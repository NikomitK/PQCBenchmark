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
    doBenchmark()
//    val strings = arrayOf<String>("Hello World", "Test123", "SLH-DSA ist cooler als ML-DSA", "SigniereMich")

}

fun doBenchmark(securityLevel: Int = 1, strings: Array<String> = arrayOf("Hello World")) {
    val ecdsaSignature = SignatureUtil.createECDSASignature()
    val rsaSignature = SignatureUtil.createRSASignature()
    val mldsaSignature = SignatureUtil.createMLDSASignature()
    val slhdsaSignature = SignatureUtil.createSLHDSASignature()

    val ecdsaTime = benchAlgorithm(ecdsaSignature, strings)
    val rsaTime = benchAlgorithm(rsaSignature, strings)
    val mldsaTime = benchAlgorithm(mldsaSignature, strings)
    val slhdsaTime = benchAlgorithm(slhdsaSignature, strings)
    println("ECDSA total time: $ecdsaTime")
    println("RSA total time: $rsaTime")
    println("MLDSA total time: $mldsaTime")
    println("SLHDSA total time: $slhdsaTime")
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