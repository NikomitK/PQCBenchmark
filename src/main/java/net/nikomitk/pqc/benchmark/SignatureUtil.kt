package net.nikomitk.pqc.benchmark

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.RSAKeyGenParameterSpec

object SignatureUtil {

    fun createECDSASignature(): Signature {
        val ecdsa = createGenericSignature("ECDSA", ECNamedCurveGenParameterSpec("P-256"))
        return ecdsa
    }

    fun createRSASignature(): Signature {
        val rsa = createGenericSignature("RSA", RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
        return rsa
    }

    fun createMLDSASignature(): Signature {
        val mldsa = createGenericSignature("MLDSA", MLDSAParameterSpec.ml_dsa_44)
        return mldsa
    }

    fun createSLHDSASignature(): Signature {
        val slhdsa = createGenericSignature("SPHINCSPlus", SPHINCSPlusParameterSpec.shake_128f)
        return slhdsa
    }

    fun createGenericSignature(algorithm: String, paramSpecs: AlgorithmParameterSpec): Signature {
        val keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC")
        keyPairGenerator.initialize(paramSpecs)
        val keyPair = keyPairGenerator.generateKeyPair()
        val signature = Signature.getInstance(algorithm)
        signature.initSign(keyPair.private)
        return signature
    }
}