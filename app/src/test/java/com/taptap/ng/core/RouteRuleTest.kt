package com.taptap.ng.core

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetAddress

class RouteRuleTest {

    private fun addr(text: String): InetAddress = InetAddress.getByName(text)

    @Test
    fun `domain matches exactly and case insensitively`() {
        val rule = RouteRule(type = RouteRuleType.DOMAIN, pattern = "Example.COM")
        assertTrue(rule.matches("example.com", null))
        assertTrue(rule.matches("EXAMPLE.COM", null))
        assertFalse(rule.matches("sub.example.com", null))
        assertFalse(rule.matches("other.com", null))
        assertFalse(rule.matches(null, null))
    }

    @Test
    fun `domain suffix matches the domain and its subdomains only`() {
        val rule = RouteRule(type = RouteRuleType.DOMAIN_SUFFIX, pattern = "example.com")
        assertTrue(rule.matches("example.com", null))
        assertTrue(rule.matches("sub.example.com", null))
        assertTrue(rule.matches("a.b.example.com", null))
        assertFalse(rule.matches("badexample.com", null))
        assertFalse(rule.matches("example.com.evil.com", null))
        assertFalse(rule.matches(null, null))
    }

    @Test
    fun `domain keyword matches a substring case insensitively`() {
        val rule = RouteRule(type = RouteRuleType.DOMAIN_KEYWORD, pattern = "Ads")
        assertTrue(rule.matches("ads.example.com", null))
        assertTrue(rule.matches("my-ads-tracker.net", null))
        assertFalse(rule.matches("example.com", null))
        assertFalse(rule.matches(null, null))
    }

    @Test
    fun `empty pattern never matches domain rules`() {
        assertFalse(RouteRule(type = RouteRuleType.DOMAIN, pattern = "").matches("example.com", null))
        assertFalse(RouteRule(type = RouteRuleType.DOMAIN_SUFFIX, pattern = "  ").matches("example.com", null))
        assertFalse(RouteRule(type = RouteRuleType.DOMAIN_KEYWORD, pattern = "").matches("example.com", null))
    }

    @Test
    fun `pattern is normalised to lowercase and trimmed`() {
        val rule = RouteRule(type = RouteRuleType.DOMAIN, pattern = "  EXAMPLE.com ")
        assertEqualsNormalized(rule)
        assertTrue(rule.matches("example.com", null))
    }

    private fun assertEqualsNormalized(rule: RouteRule) {
        org.junit.jupiter.api.Assertions.assertEquals("example.com", rule.normalizedPattern)
    }

    @Test
    fun `ipv4 cidr matches inside the range only`() {
        val rule = RouteRule(type = RouteRuleType.IP_CIDR, pattern = "192.168.1.0/24")
        assertTrue(rule.matches(null, addr("192.168.1.1")))
        assertTrue(rule.matches(null, addr("192.168.1.254")))
        assertFalse(rule.matches(null, addr("192.168.2.1")))
        assertFalse(rule.matches(null, addr("10.0.0.1")))
        assertFalse(rule.matches(null, null))
    }

    @Test
    fun `ipv4 cidr slash 32 matches one host and slash 0 matches all`() {
        assertTrue(
            RouteRule(type = RouteRuleType.IP_CIDR, pattern = "10.0.0.5/32")
                .matches(null, addr("10.0.0.5"))
        )
        assertFalse(
            RouteRule(type = RouteRuleType.IP_CIDR, pattern = "10.0.0.5/32")
                .matches(null, addr("10.0.0.6"))
        )
        assertTrue(
            RouteRule(type = RouteRuleType.IP_CIDR, pattern = "0.0.0.0/0")
                .matches(null, addr("203.0.113.9"))
        )
    }

    @Test
    fun `ipv6 cidr matches inside the range only`() {
        val rule = RouteRule(type = RouteRuleType.IP_CIDR, pattern = "2001:db8::/32")
        assertTrue(rule.matches(null, addr("2001:db8::1")))
        assertTrue(rule.matches(null, addr("2001:db8:ffff::1")))
        assertFalse(rule.matches(null, addr("2001:db9::1")))
    }

    @Test
    fun `cidr with family mismatch never matches`() {
        // IPv6 address against an IPv4 CIDR (and vice versa).
        assertFalse(
            RouteRule(type = RouteRuleType.IP_CIDR, pattern = "192.168.0.0/16")
                .matches(null, addr("2001:db8::1"))
        )
        assertFalse(
            RouteRule(type = RouteRuleType.IP_CIDR, pattern = "2001:db8::/32")
                .matches(null, addr("192.168.0.1"))
        )
    }

    @Test
    fun `unparseable cidr never matches and is invalid`() {
        assertFalse(RouteRule.isValidCidr("not-a-cidr"))
        assertFalse(RouteRule.isValidCidr("192.168.0.0/33"))
        assertFalse(RouteRule.isValidCidr("192.168.0.0/-1"))
        assertFalse(RouteRule.isValidCidr("192.168.0.0"))
        assertFalse(RouteRule.isValidCidr("999.999.0.0/24"))
        assertTrue(RouteRule.isValidCidr("192.168.0.0/24"))
        assertTrue(RouteRule.isValidCidr("2001:db8::/32"))
        assertFalse(
            RouteRule(type = RouteRuleType.IP_CIDR, pattern = "not-a-cidr")
                .matches(null, addr("192.168.0.1"))
        )
    }

    @Test
    fun `final always matches even with no host and no ip`() {
        val rule = RouteRule(type = RouteRuleType.FINAL, pattern = "")
        assertTrue(rule.matches(null, null))
        assertTrue(rule.matches("anything.example", addr("1.2.3.4")))
    }
}
