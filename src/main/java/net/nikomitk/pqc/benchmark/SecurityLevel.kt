package net.nikomitk.pqc.benchmark

enum class SecurityLevel(val value: Int) {
    LOW(128),
    MEDIUM(192),
    HIGH(256),
}