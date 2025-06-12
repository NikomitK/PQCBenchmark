package net.nikomitk.pqc.benchmark

import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.RSAKeyGenParameterSpec

object SignatureUtil {

  enum class Algorithm(val value: String) {
    ECDSA("ECDSA"),
    RSA("RSA"),
    DILITHIUM("DILITHIUM"),
    SPHINCSPlusFast("SPHINCS+-fast"),
    SPHINCSPlusSimple("SPHINCS+-simple");
  }

  enum class SecurityLevel(val value: Int) {
    LOW(128),
    MEDIUM(192),
    HIGH(256),
  }

  fun generateSignature(algorithm: Algorithm, securityLevel: SecurityLevel = SecurityLevel.LOW): Signature =
    when (algorithm) {
      Algorithm.ECDSA -> createECDSASignature(securityLevel)
      Algorithm.RSA -> createRSASignature(securityLevel)
      Algorithm.DILITHIUM -> createDilithiumSignature(securityLevel)
      Algorithm.SPHINCSPlusFast -> createSPHINCSPlusFastSignature(securityLevel)
      Algorithm.SPHINCSPlusSimple -> createSPHINCSPlusSimpleSignature(securityLevel)
    }

  fun createECDSASignature(securityLevel: SecurityLevel = SecurityLevel.LOW): Signature {
    val paramSpec = when (securityLevel) {
      SecurityLevel.LOW -> ECNamedCurveGenParameterSpec("P-256")
      SecurityLevel.MEDIUM -> ECNamedCurveGenParameterSpec("P-384")
      SecurityLevel.HIGH -> ECNamedCurveGenParameterSpec("P-521")
    }
    val ecdsa = createGenericSignature("ECDSA", paramSpec)
    return ecdsa
  }

  fun createRSASignature(securityLevel: SecurityLevel = SecurityLevel.LOW): Signature {
    val paramSpec = when (securityLevel) {
      SecurityLevel.LOW -> RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4)
      SecurityLevel.MEDIUM -> RSAKeyGenParameterSpec(7680, RSAKeyGenParameterSpec.F4)
      SecurityLevel.HIGH -> RSAKeyGenParameterSpec(15360, RSAKeyGenParameterSpec.F4)
    }
    val rsa = createGenericSignature("RSA", paramSpec)
    return rsa
  }

  fun createDilithiumSignature(securityLevel: SecurityLevel = SecurityLevel.LOW): Signature {
    val paramSpec = when (securityLevel) {
      SecurityLevel.LOW -> DilithiumParameterSpec.dilithium2
      SecurityLevel.MEDIUM -> DilithiumParameterSpec.dilithium3
      SecurityLevel.HIGH -> DilithiumParameterSpec.dilithium5
    }
    val dilithium = createGenericSignature("DILITHIUM", paramSpec)
    return dilithium
  }

  fun createSPHINCSPlusFastSignature(securityLevel: SecurityLevel = SecurityLevel.LOW): Signature {
    val paramSpec = when (securityLevel) {
      SecurityLevel.LOW -> SPHINCSPlusParameterSpec.sha2_128f
      SecurityLevel.MEDIUM -> SPHINCSPlusParameterSpec.sha2_192f
      SecurityLevel.HIGH -> SPHINCSPlusParameterSpec.sha2_256f
    }
    val sphincsPlus = createGenericSignature("SPHINCSPlus", paramSpec)
    return sphincsPlus
  }

  fun createSPHINCSPlusSimpleSignature(securityLevel: SecurityLevel = SecurityLevel.LOW): Signature {
    val paramSpec = when (securityLevel) {
      SecurityLevel.LOW -> SPHINCSPlusParameterSpec.sha2_128s
      SecurityLevel.MEDIUM -> SPHINCSPlusParameterSpec.sha2_192s
      SecurityLevel.HIGH -> SPHINCSPlusParameterSpec.sha2_256s
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