package net.nikomitk.pqc.benchmark

enum class Algorithm(val value: String) {
    ECDSA("ECDSA"),
    RSA("RSA"),
    DILITHIUM("DILITHIUM"),
    SPHINCSPlusFast("SPHINCSPlus-f"),
    SPHINCSPlusSimple("SPHINCSPlus-s");
}