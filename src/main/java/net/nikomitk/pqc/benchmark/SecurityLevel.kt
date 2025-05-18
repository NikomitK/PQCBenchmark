package net.nikomitk.pqc.benchmark

enum class SecurityLevel(value: Int) {
    LOW(128),
    MEDIUM(192),
    HIGH(256),
    ALL(0);

    val value = value
        get() = field
}