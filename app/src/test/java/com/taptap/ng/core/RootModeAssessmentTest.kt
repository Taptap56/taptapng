package com.taptap.ng.core

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootModeAssessmentTest {

    @Test
    fun `root mode is not feasible in v105`() {
        assertFalse(
            RootModeAssessment.FEASIBLE_IN_V105,
            "root mode must stay unimplemented — see RootModeAssessment",
        )
    }

    @Test
    fun `assessment names the blocking work`() {
        assertTrue(RootModeAssessment.requiredChanges.isNotEmpty())
        assertTrue(RootModeAssessment.blockingReasons.isNotEmpty())
        val all = (RootModeAssessment.requiredChanges + RootModeAssessment.blockingReasons)
            .joinToString(" ")
        assertTrue(all.contains("iptables"), "assessment must name iptables: $all")
        assertTrue(all.contains("VpnService"), "assessment must name VpnService: $all")
        assertTrue(
            all.contains("TUN") || all.contains("forwarder"),
            "assessment must name the TUN/forwarder rewrite: $all",
        )
    }
}
