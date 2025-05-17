package net.nikomitk.pqc.benchmark

enum class SecurityLevel(value: Int) {
    LOW(1),
    MEDIUM(2),
    HIGH(3);

    val value = value
        get() = field
}