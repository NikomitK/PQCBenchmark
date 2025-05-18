package net.nikomitk.pqc.benchmark

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.RSAKeyGenParameterSpec

object SignatureUtil {

    fun generateSignature(algorithm: Algorithm, securityLevel: SecurityLevel = SecurityLevel.LOW): Signature = when(algorithm) {
        Algorithm.ECDSA -> createECDSASignature(securityLevel)
        Algorithm.RSA -> createRSASignature(securityLevel)
        Algorithm.DILITHIUM -> createDilithiumSignature(securityLevel)
        Algorithm.SPHINCSPlusFast -> createSPHINCSPlusFastSignature(securityLevel)
        Algorithm.SPHINCSPlusSimple -> createSPHINCSPlusSimpleSignature(securityLevel)
    }

    fun createECDSASignature(securityLevel: SecurityLevel = SecurityLevel.LOW): Signature {
        val paramSpec = when(securityLevel) {
            SecurityLevel.LOW -> ECNamedCurveGenParameterSpec("P-256")
            SecurityLevel.MEDIUM -> ECNamedCurveGenParameterSpec("P-384")
            SecurityLevel.HIGH -> ECNamedCurveGenParameterSpec("P-521")
            else -> throw IllegalArgumentException("Invalid security level: $securityLevel")
        }
        val ecdsa = createGenericSignature("ECDSA", paramSpec)
        return ecdsa
    }

    fun createRSASignature(securityLevel: SecurityLevel = SecurityLevel.LOW): Signature {
        val paramSpec = when(securityLevel) {
            SecurityLevel.LOW -> RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)
            SecurityLevel.MEDIUM -> RSAKeyGenParameterSpec(7680, RSAKeyGenParameterSpec.F4)
            SecurityLevel.HIGH -> RSAKeyGenParameterSpec(15360, RSAKeyGenParameterSpec.F4)
            else -> throw IllegalArgumentException("Invalid security level: $securityLevel")
        }
        val rsa = createGenericSignature("RSA", paramSpec)
        return rsa
    }

    fun createMLDSASignature(securityLevel: SecurityLevel = SecurityLevel.LOW): Signature {
        val paramSpec = when(securityLevel) {
            SecurityLevel.LOW -> MLDSAParameterSpec.ml_dsa_44
            SecurityLevel.MEDIUM -> MLDSAParameterSpec.ml_dsa_65
            SecurityLevel.HIGH -> MLDSAParameterSpec.ml_dsa_87
            else -> throw IllegalArgumentException("Invalid security level: $securityLevel")
        }
        val mldsa = createGenericSignature("MLDSA", paramSpec)
        return mldsa
    }

    fun createDilithiumSignature(securityLevel: SecurityLevel = SecurityLevel.LOW): Signature {
        val paramSpec = when(securityLevel) {
            SecurityLevel.LOW -> DilithiumParameterSpec.dilithium2
            SecurityLevel.MEDIUM -> DilithiumParameterSpec.dilithium3
            SecurityLevel.HIGH -> DilithiumParameterSpec.dilithium5
            else -> throw IllegalArgumentException("Invalid security level: $securityLevel")
        }
        val dilithium = createGenericSignature("DILITHIUM", paramSpec)
        return dilithium
    }

    fun createSPHINCSPlusFastSignature(securityLevel: SecurityLevel = SecurityLevel.LOW): Signature {
        val paramSpec = when(securityLevel) {
            SecurityLevel.LOW -> SPHINCSPlusParameterSpec.shake_128f
            SecurityLevel.MEDIUM -> SPHINCSPlusParameterSpec.shake_192f
            SecurityLevel.HIGH -> SPHINCSPlusParameterSpec.shake_256f
            else -> throw IllegalArgumentException("Invalid security level: $securityLevel")
        }
        val sphincsPlus = createGenericSignature("SPHINCSPlus", paramSpec)
        return sphincsPlus
    }

    fun createSPHINCSPlusSimpleSignature(securityLevel: SecurityLevel = SecurityLevel.LOW): Signature {
        val paramSpec = when(securityLevel) {
            SecurityLevel.LOW -> SPHINCSPlusParameterSpec.shake_128s
            SecurityLevel.MEDIUM -> SPHINCSPlusParameterSpec.shake_192s
            SecurityLevel.HIGH -> SPHINCSPlusParameterSpec.shake_256s
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