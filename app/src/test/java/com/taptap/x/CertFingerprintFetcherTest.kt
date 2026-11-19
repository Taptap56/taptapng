package com.taptap.x

import com.taptap.x.core.CertFingerprintFetcher
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Unit tests for CertFingerprintFetcher's IP-literal check (SNI must
 * be a DNS name, never an IP). The live TLS dial itself is NOT unit
 * tested — it needs a real server and is verified on the phone.
 */
class CertFingerprintFetcherTest {

    @Test
    fun `ipv4 literals are detected`() {
        assertTrue(CertFingerprintFetcher.isIpLiteral("1.2.3.4"))
        assertTrue(CertFingerprintFetcher.isIpLiteral("104.17.3.81"))
    }

    @Test
    fun `ipv6 literals are detected`() {
        assertTrue(CertFingerprintFetcher.isIpLiteral("::1"))
        assertTrue(CertFingerprintFetcher.isIpLiteral("2001:db8::1"))
        assertTrue(CertFingerprintFetcher.isIpLiteral("[2001:db8::1]"))
    }

    @Test
    fun `hostnames are not ip literals`() {
        assertFalse(CertFingerprintFetcher.isIpLiteral("example.com"))
        assertFalse(CertFingerprintFetcher.isIpLiteral("support.zoom.us"))
        assertFalse(CertFingerprintFetcher.isIpLiteral(""))
    }
}
