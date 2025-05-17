package net.nikomitk.pqc.benchmark;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

public class JSignatureUtil {
    public static Signature generateSignature(String algorithm, int securityLevel) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {

        return switch (algorithm) {
            case "ECDSA" -> createECDSASignature(securityLevel);
            case "RSA" -> createRSASignature(securityLevel);
            case "MLDSA" -> createMLDSASignature(securityLevel);
            case "DILITHIUM" -> createDilithiumSignature(securityLevel);
            case "SLHDSA" -> createSLHDSASignature(securityLevel);
            case "SPHINCSPlus" -> createSPHINCSPlusSignature(securityLevel);
            default -> throw new IllegalArgumentException("Unsupported algorithm: $algorithm");
        };
    }

    public static Signature createECDSASignature(int securityLevel) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        var paramSpec = switch(securityLevel) {
            case 1 -> new ECNamedCurveGenParameterSpec("P-256");
            case 2 -> new ECNamedCurveGenParameterSpec("P-384");
            case 3 -> new ECNamedCurveGenParameterSpec("P-521");
            default -> throw new IllegalArgumentException("Invalid security level: $securityLevel");
        };
        var ecdsa = createGenericSignature("ECDSA", paramSpec);
        return ecdsa;
    }

    public static Signature createRSASignature(int securityLevel) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        var paramSpec = switch(securityLevel) {
            case 1 -> new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4);
            case 2 -> new RSAKeyGenParameterSpec(7680, RSAKeyGenParameterSpec.F4);
            case 3 -> new RSAKeyGenParameterSpec(15360, RSAKeyGenParameterSpec.F4);
            default -> throw new IllegalArgumentException("Invalid security level: $securityLevel");
        };
        var rsa = createGenericSignature("RSA", paramSpec);
        return rsa;
    }

    public static Signature createMLDSASignature(int securityLevel) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        var paramSpec = switch(securityLevel) {
            case 1 -> MLDSAParameterSpec.ml_dsa_44;
            case 2 -> MLDSAParameterSpec.ml_dsa_65;
            case 3 -> MLDSAParameterSpec.ml_dsa_87;
            default -> throw new IllegalArgumentException("Invalid security level: $securityLevel");
        };
        var mldsa = createGenericSignature("MLDSA", paramSpec);
        return mldsa;
    }

    public static Signature createDilithiumSignature(int securityLevel) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        var paramSpec = switch(securityLevel) {
            case 1 -> DilithiumParameterSpec.dilithium2;
            case 2 -> DilithiumParameterSpec.dilithium3;
            case 3 -> DilithiumParameterSpec.dilithium5;
            default -> throw new IllegalArgumentException("Invalid security level: $securityLevel");
        };
        var dilithium = createGenericSignature("DILITHIUM", paramSpec);
        return dilithium;
    }

    public static Signature createSLHDSASignature(int securityLevel) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        var paramSpec = switch(securityLevel) {
            case 1 -> SLHDSAParameterSpec.slh_dsa_sha2_128f;
            case 2 -> SLHDSAParameterSpec.slh_dsa_sha2_192f;
            case 3 -> SLHDSAParameterSpec.slh_dsa_sha2_256f;
            default -> throw new IllegalArgumentException("Invalid security level: $securityLevel");
        };
        var slhdsa = createGenericSignature("SLH-DSA", paramSpec);
        return slhdsa;
    }

    public static Signature createSPHINCSPlusSignature(int securityLevel) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        var paramSpec = switch(securityLevel) {
            case 1 -> SPHINCSPlusParameterSpec.shake_128s;
            case 2 -> SPHINCSPlusParameterSpec.shake_192s;
            case 3 -> SPHINCSPlusParameterSpec.shake_256s;
            default -> throw new IllegalArgumentException("Invalid security level: $securityLevel");
        };
        var sphincsPlus = createGenericSignature("SPHINCSPlus", paramSpec);
        return sphincsPlus;
    }

    private static Signature createGenericSignature(String algorithm, AlgorithmParameterSpec paramSpecs) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        var keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC");
        keyPairGenerator.initialize(paramSpecs);
        var keyPair = keyPairGenerator.generateKeyPair();
        var signature = Signature.getInstance(algorithm);
        signature.initSign(keyPair.getPrivate());
        return signature;
    }
}
