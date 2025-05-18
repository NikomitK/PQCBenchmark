package net.nikomitk.pqc.benchmark

import kotlin.time.Duration

data class Result(val algorithm: String, val securityLevel: SecurityLevel, val time: Duration)
