package net.nikomitk.pqc.benchmark;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

public class JSignatureUtil {

    public static Signature generateSignature(Algorithm algorithm, SecurityLevel securityLevel) {
        return switch (algorithm) {
            case ECDSA -> createECDSASignature(securityLevel);
            case RSA -> createRSASignature(securityLevel);
            case DILITHIUM -> createDilithiumSignature(securityLevel);
            case SPHINCSPlusFast -> createSPHINCSPlusFastSignature(securityLevel);
            case SPHINCSPlusSimple -> createSPHINCSPlusSimpleSignature(securityLevel);
        };
    }

    public static Signature generateSignature(Algorithm algorithm) {
        return generateSignature(algorithm, SecurityLevel.LOW);
    }

    public static Signature createECDSASignature(SecurityLevel securityLevel) {
        ECNamedCurveGenParameterSpec paramSpec = switch (securityLevel) {
            case LOW -> new ECNamedCurveGenParameterSpec("P-256");
            case MEDIUM -> new ECNamedCurveGenParameterSpec("P-384");
            case HIGH -> new ECNamedCurveGenParameterSpec("P-521");
        };
        return createGenericSignature("ECDSA", paramSpec);
    }

    public static Signature createECDSASignature() {
        return createECDSASignature(SecurityLevel.LOW);
    }

    public static Signature createRSASignature(SecurityLevel securityLevel) {
        RSAKeyGenParameterSpec paramSpec = switch (securityLevel) {
            case LOW -> new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4);
            case MEDIUM -> new RSAKeyGenParameterSpec(7680, RSAKeyGenParameterSpec.F4);
            case HIGH -> new RSAKeyGenParameterSpec(15360, RSAKeyGenParameterSpec.F4);
        };
        return createGenericSignature("RSA", paramSpec);
    }

    public static Signature createRSASignature() {
        return createRSASignature(SecurityLevel.LOW);
    }

    public static Signature createMLDSASignature(SecurityLevel securityLevel) {
        MLDSAParameterSpec paramSpec = switch (securityLevel) {
            case LOW -> MLDSAParameterSpec.ml_dsa_44;
            case MEDIUM -> MLDSAParameterSpec.ml_dsa_65;
            case HIGH -> MLDSAParameterSpec.ml_dsa_87;
        };
        return createGenericSignature("MLDSA", paramSpec);
    }

    public static Signature createMLDSASignature() {
        return createMLDSASignature(SecurityLevel.LOW);
    }

    public static Signature createDilithiumSignature(SecurityLevel securityLevel) {
        DilithiumParameterSpec paramSpec = switch (securityLevel) {
            case LOW -> DilithiumParameterSpec.dilithium2;
            case MEDIUM -> DilithiumParameterSpec.dilithium3;
            case HIGH -> DilithiumParameterSpec.dilithium5;
        };
        return createGenericSignature("DILITHIUM", paramSpec);
    }

    public static Signature createDilithiumSignature() {
        return createDilithiumSignature(SecurityLevel.LOW);
    }

    public static Signature createSPHINCSPlusFastSignature(SecurityLevel securityLevel) {
        SPHINCSPlusParameterSpec paramSpec = switch (securityLevel) {
            case LOW -> SPHINCSPlusParameterSpec.sha2_128f;
            case MEDIUM -> SPHINCSPlusParameterSpec.sha2_192f;
            case HIGH -> SPHINCSPlusParameterSpec.sha2_256f;
        };
        return createGenericSignature("SPHINCSPlus", paramSpec);
    }

    public static Signature createSPHINCSPlusFastSignature() {
        return createSPHINCSPlusFastSignature(SecurityLevel.LOW);
    }

    public static Signature createSPHINCSPlusSimpleSignature(SecurityLevel securityLevel) {
        SPHINCSPlusParameterSpec paramSpec = switch (securityLevel) {
            case LOW -> SPHINCSPlusParameterSpec.sha2_128s;
            case MEDIUM -> SPHINCSPlusParameterSpec.sha2_192s;
            case HIGH -> SPHINCSPlusParameterSpec.sha2_256s;
        };
        return createGenericSignature("SPHINCSPlus", paramSpec);
    }

    public static Signature createSPHINCSPlusSimpleSignature() {
        return createSPHINCSPlusSimpleSignature(SecurityLevel.LOW);
    }

    private static Signature createGenericSignature(String algorithm, AlgorithmParameterSpec paramSpecs) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC");
            keyPairGenerator.initialize(paramSpecs);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(keyPair.getPrivate());
            return signature;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            throw new RuntimeException("Error creating signature for " + algorithm, e);
        }
    }
}