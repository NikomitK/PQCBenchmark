package net.nikomitk.pqc.benchmark;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.mldsa.HashMLDSASigner;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Util {

    public static byte[] signMessage(MessageSigner signer, byte[] message) {

        return signer.generateSignature(message);
    }

    public static byte[] signMessage2(Signer signer, byte[] message) throws CryptoException {
        //signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    public static MessageSigner createSLHDSASigner(int securityLevel) {
        // Create a new SLHDSA signer with the specified security level
        SLHDSAParameters params = switch (securityLevel) {
            case 1 -> SLHDSAParameters.sha2_128f;
            case 2 -> SLHDSAParameters.sha2_192s;
            case 3 -> SLHDSAParameters.sha2_256s;
            default -> throw new IllegalArgumentException("Invalid security level: " + securityLevel);
        };
        SLHDSAKeyGenerationParameters genParams = new SLHDSAKeyGenerationParameters(new SecureRandom(), params);
        SLHDSAKeyPairGenerator keyPairGenerator = new SLHDSAKeyPairGenerator();
        keyPairGenerator.init(genParams);
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        SLHDSASigner signer = new SLHDSASigner();
        signer.init(true, keyPair.getPrivate());
        return signer;
    }


    public static Signer createMLDSASigner(int securityLevel) {
        // Create a new MLDSA signer with the specified security level
        MLDSAParameters params = switch (securityLevel) {
            case 1 -> MLDSAParameters.ml_dsa_44_with_sha512;
            case 2 -> MLDSAParameters.ml_dsa_65;
            case 3 -> MLDSAParameters.ml_dsa_87;
            default -> throw new IllegalArgumentException("Invalid security level: " + securityLevel);
        };
        MLDSAKeyGenerationParameters genParams = new MLDSAKeyGenerationParameters(new SecureRandom(), params);
        MLDSAKeyPairGenerator keyPairGenerator = new MLDSAKeyPairGenerator();
        keyPairGenerator.init(genParams);
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        HashMLDSASigner signer = new HashMLDSASigner();
        signer.init(true, keyPair.getPrivate());
        return signer;
    }

    public static Signer createRSASigner(int securityLevel) {

        int strength = switch (securityLevel) {
            case 1 -> 2048;
            case 2 -> 3072;
            case 3 -> 4096;
            default -> throw new IllegalArgumentException("Invalid security level: " + securityLevel);
        };
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        keyPairGenerator.init(new RSAKeyGenerationParameters(new BigInteger(Base64.decode("EQ==")), new SecureRandom(), strength, 100));
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSADigestSigner signer = new RSADigestSigner(new SHA3Digest());
        signer.init(true, keyPair.getPrivate());
        return signer;
    }

    public static Signer createECDSASigner() {

        Ed25519KeyGenerationParameters genParams = new Ed25519KeyGenerationParameters(new SecureRandom());
        Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
        keyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, keyPair.getPrivate());

        return signer;
    }

}
