package net.nikomitk.pqc.benchmark

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.RSAKeyGenParameterSpec

object SignatureUtil {

    fun generateSignature(algorithm: String, securityLevel: Int = 1): Signature = when(algorithm) {
        "ECDSA" -> createECDSASignature(securityLevel)
        "RSA" -> createRSASignature(securityLevel)
        "MLDSA" -> createMLDSASignature(securityLevel)
        "DILITHIUM" -> createDilithiumSignature(securityLevel)
        "SLHDSA" -> createSLHDSASignature(securityLevel)
        "SPHINCSPlus" -> createSPHINCSPlusSignature(securityLevel)
        else -> throw IllegalArgumentException("Unsupported algorithm: $algorithm")
    }

    fun createECDSASignature(securityLevel: Int = 1): Signature {
        val paramSpec = when(securityLevel) {
            1 -> ECNamedCurveGenParameterSpec("P-256")
            2 -> ECNamedCurveGenParameterSpec("P-384")
            3 -> ECNamedCurveGenParameterSpec("P-521")
            else -> throw IllegalArgumentException("Invalid security level: $securityLevel")
        }
        val ecdsa = createGenericSignature("ECDSA", paramSpec)
        return ecdsa
    }

    fun createRSASignature(securityLevel: Int = 1): Signature {
        val paramSpec = when(securityLevel) {
            1 -> RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)
            2 -> RSAKeyGenParameterSpec(7680, RSAKeyGenParameterSpec.F4)
            3 -> RSAKeyGenParameterSpec(15360, RSAKeyGenParameterSpec.F4)
            else -> throw IllegalArgumentException("Invalid security level: $securityLevel")
        }
        val rsa = createGenericSignature("RSA", paramSpec)
        return rsa
    }

    fun createMLDSASignature(securityLevel: Int = 1): Signature {
        val paramSpec = when(securityLevel) {
            1 -> MLDSAParameterSpec.ml_dsa_44
            2 -> MLDSAParameterSpec.ml_dsa_65
            3 -> MLDSAParameterSpec.ml_dsa_87
            else -> throw IllegalArgumentException("Invalid security level: $securityLevel")
        }
        val mldsa = createGenericSignature("MLDSA", paramSpec)
        return mldsa
    }

    fun createDilithiumSignature(securityLevel: Int = 1): Signature {
        val paramSpec = when(securityLevel) {
            1 -> DilithiumParameterSpec.dilithium2
            2 -> DilithiumParameterSpec.dilithium3
            3 -> DilithiumParameterSpec.dilithium5
            else -> throw IllegalArgumentException("Invalid security level: $securityLevel")
        }
        val dilithium = createGenericSignature("DILITHIUM", paramSpec)
        return dilithium
    }

    fun createSLHDSASignature(securityLevel: Int = 1): Signature {
        val paramSpec = when(securityLevel) {
            1 -> SLHDSAParameterSpec.slh_dsa_sha2_128f
            2 -> SLHDSAParameterSpec.slh_dsa_sha2_192f
            3 -> SLHDSAParameterSpec.slh_dsa_sha2_256f
            else -> throw IllegalArgumentException("Invalid security level: $securityLevel")
        }
        val slhdsa = createGenericSignature("SLH-DSA", paramSpec)
        return slhdsa
    }

    fun createSPHINCSPlusSignature(securityLevel: Int = 1): Signature {
        val paramSpec = when(securityLevel) {
            1 -> SPHINCSPlusParameterSpec.shake_128s
            2 -> SPHINCSPlusParameterSpec.shake_192s
            3 -> SPHINCSPlusParameterSpec.shake_256s
            else -> throw IllegalArgumentException("Invalid security level: $securityLevel")
        }
        val sphincsPlus = createGenericSignature("SPHINCSPlus", paramSpec)
        return sphincsPlus
    }

    private fun createGenericSignature(algorithm: String, paramSpecs: AlgorithmParameterSpec): Signature {
        val keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC")
        keyPairGenerator.initialize(paramSpecs)
        val keyPair = keyPairGenerator.generateKeyPair()
        val signature = Signature.getInstance(algorithm)
        signature.initSign(keyPair.private)
        return signature
    }
}