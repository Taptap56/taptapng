package com.taptap.x.core

/**
 * Minimal Base64 (standard + URL-safe) decoder, written by hand so
 * [LinkParser] stays pure Kotlin: no android.util.Base64 (unavailable
 * in JVM unit tests) and no java.util.Base64 (API 26+, minSdk is 24).
 * Decoding is lenient: whitespace is ignored, missing padding is
 * tolerated.
 */
object Base64Util {

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun decode(input: String): ByteArray? {
        val clean = input.trim()
            .replace('-', '+')
            .replace('_', '/')
            .filter { it != '\n' && it != '\r' && it != ' ' && it != '\t' }
        if (clean.isEmpty()) return ByteArray(0)
        val padded = clean.padEnd(((clean.length + 3) / 4) * 4, '=')
        val out = ByteArray((padded.length * 3) / 4)
        var outPos = 0
        var i = 0
        while (i < padded.length) {
            val c0 = value(padded[i]); val c1 = value(padded[i + 1])
            val c2 = if (padded[i + 2] == '=') 0 else value(padded[i + 2])
            val c3 = if (padded[i + 3] == '=') 0 else value(padded[i + 3])
            if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0) return null
            val triple = (c0 shl 18) or (c1 shl 12) or (c2 shl 6) or c3
            out[outPos++] = ((triple shr 16) and 0xFF).toByte()
            if (padded[i + 2] != '=') out[outPos++] = ((triple shr 8) and 0xFF).toByte()
            if (padded[i + 3] != '=') out[outPos++] = (triple and 0xFF).toByte()
            i += 4
        }
        return out.copyOf(outPos)
    }

    fun decodeToString(input: String): String? =
        decode(input)?.let { String(it, Charsets.UTF_8) }

    fun encode(input: ByteArray): String {
        val sb = StringBuilder()
        var i = 0
        while (i < input.size) {
            val b0 = input[i].toInt() and 0xFF
            val b1 = if (i + 1 < input.size) input[i + 1].toInt() and 0xFF else 0
            val b2 = if (i + 2 < input.size) input[i + 2].toInt() and 0xFF else 0
            val triple = (b0 shl 16) or (b1 shl 8) or b2
            sb.append(ALPHABET[(triple shr 18) and 0x3F])
            sb.append(ALPHABET[(triple shr 12) and 0x3F])
            sb.append(if (i + 1 < input.size) ALPHABET[(triple shr 6) and 0x3F] else '=')
            sb.append(if (i + 2 < input.size) ALPHABET[triple and 0x3F] else '=')
            i += 3
        }
        return sb.toString()
    }

    fun encodeUrlSafe(input: ByteArray): String =
        encode(input).trimEnd('=').replace('+', '-').replace('/', '_')

    private fun value(c: Char): Int = when (c) {
        in 'A'..'Z' -> c - 'A'
        in 'a'..'z' -> c - 'a' + 26
        in '0'..'9' -> c - '0' + 52
        '+' -> 62
        '/' -> 63
        else -> -1
    }
}
