package net.nikomitk.pqc.benchmark

import kotlin.time.Duration
import kotlin.time.measureTime

fun main() {
    val strings = arrayOf<String>("Hello World", "Test123", "SLH-DSA ist cooler als ML-DSA", "SigniereMich")
    val securityLevel = 1
    val slhdsaSigner = Util.createSLHDSASigner(securityLevel)
    val mldsaSigner = Util.createMLDSASigner(securityLevel)
    val rsaSigner = Util.createRSASigner(securityLevel)
    val ecdsaSigner = Util.createECDSASigner()


    var slhdsaTotalTime = Duration.ZERO;
    for (s in strings) {
        val message = s.toByteArray()
        slhdsaTotalTime += measureTime { Util.signMessage(slhdsaSigner, message) }

    }
    println("SLHDSA total time: $slhdsaTotalTime")

    var mldsaTotalTime = Duration.ZERO;
    for (s in strings) {
        val message = s.toByteArray()
        mldsaSigner.update(message, 0, message.size);
        mldsaTotalTime += measureTime { Util.signMessage2(mldsaSigner, message) }
    }
    println("MLDSA total time: $mldsaTotalTime")

    var rsaTotalTime = Duration.ZERO;
    for (s in strings) {
        val message = s.toByteArray()
        rsaSigner.update(message, 0, message.size);
        rsaTotalTime += measureTime { Util.signMessage2(rsaSigner, message) }
    }
    println("RSA total time: $rsaTotalTime")

    var ecdsaTotalTime = Duration.ZERO;
    for (s in strings) {
        val message = s.toByteArray()
        ecdsaSigner.update(message, 0, message.size);
        ecdsaTotalTime += measureTime { Util.signMessage2(ecdsaSigner, message) }
    }
    println("ECDSA total time: $ecdsaTotalTime")

}