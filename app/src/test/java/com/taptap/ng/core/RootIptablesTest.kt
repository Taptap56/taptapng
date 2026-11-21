package com.taptap.ng.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootIptablesTest {

    private val cfg = RootIptables.Config(appUid = 10123)

    @Test
    fun `install creates chains before jumps and owner return before chain jump`() {
        val cmds = RootIptables.installCommands(cfg)
        val createLocal = cmds.indexOf("iptables -t nat -N TAPTAPNG")
        val ownerReturn = cmds.indexOf(
            "iptables -t nat -A OUTPUT -m owner --uid-owner 10123 -j RETURN",
        )
        val jumpLocal = cmds.indexOf("iptables -t nat -A OUTPUT -j TAPTAPNG")
        val firstChainRule = cmds.indexOfFirst { it.startsWith("iptables -t nat -A TAPTAPNG ") }
        assertTrue(createLocal >= 0 && ownerReturn > createLocal, "rantai dibuat dulu: $cmds")
        assertTrue(jumpLocal > ownerReturn, "owner RETURN sebelum jump ke rantai: $cmds")
        assertTrue(firstChainRule > jumpLocal, "isi rantai sesudah jump rule: $cmds")
    }

    @Test
    fun `install redirects 80 and 443 to different local ports plus dns 53`() {
        val cmds = RootIptables.installCommands(cfg)
        assertTrue(
            cmds.contains(
                "iptables -t nat -A TAPTAPNG -p tcp --dport 80 -j REDIRECT --to-ports 18080",
            ),
        )
        assertTrue(
            cmds.contains(
                "iptables -t nat -A TAPTAPNG -p tcp --dport 443 -j REDIRECT --to-ports 18081",
            ),
        )
        assertTrue(
            cmds.contains(
                "iptables -t nat -A TAPTAPNG -p udp --dport 53 -j REDIRECT --to-ports 18053",
            ),
        )
    }

    @Test
    fun `install bypasses lan and ends local chain with return`() {
        val cmds = RootIptables.installCommands(cfg)
        for (range in RootIptables.LAN_RANGES) {
            assertTrue(
                cmds.contains("iptables -t nat -A TAPTAPNG -d $range -j RETURN"),
                "LAN $range harus di-RETURN: $cmds",
            )
        }
        val lastLocal = cmds.lastIndexOf("iptables -t nat -A TAPTAPNG -j RETURN")
        val firstTether = cmds.indexOf("iptables -t nat -N TAPTAPNG_TETH")
        assertTrue(lastLocal in 0..<firstTether, "RETURN penutup sebelum rantai tether: $cmds")
    }

    @Test
    fun `install covers every aosp tether range in prerouting and returns tether destinations`() {
        val cmds = RootIptables.installCommands(cfg)
        for (range in RootIptables.TETHER_RANGES) {
            assertTrue(
                cmds.contains("iptables -t nat -A PREROUTING -s $range -j TAPTAPNG_TETH"),
                "tether $range harus di-PREROUTING: $cmds",
            )
            assertTrue(
                cmds.contains("iptables -t nat -A TAPTAPNG_TETH -d $range -j RETURN"),
                "tujuan tether $range harus di-RETURN: $cmds",
            )
        }
        assertTrue(
            cmds.contains(
                "iptables -t nat -A TAPTAPNG_TETH -p tcp --dport 443 -j REDIRECT --to-ports 18081",
            ),
        )
    }

    @Test
    fun `tether ranges are the aosp dhcp defaults`() {
        assertEquals(
            listOf(
                "192.168.42.0/24", "192.168.43.0/24", "192.168.44.0/24",
                "192.168.45.0/24", "192.168.46.0/24", "192.168.47.0/24",
                "192.168.48.0/24", "192.168.49.0/24",
            ),
            RootIptables.TETHER_RANGES,
        )
    }

    @Test
    fun `bypass lan off removes lan returns from the local chain`() {
        val cmds = RootIptables.installCommands(cfg.copy(bypassLan = false))
        assertFalse(
            cmds.any { it.startsWith("iptables -t nat -A TAPTAPNG -d ") },
            "tanpa bypass LAN tidak ada RETURN tujuan: $cmds",
        )
    }

    @Test
    fun `cleanup deletes jumps before flushing chains and never adds rules`() {
        val cmds = RootIptables.cleanupCommands(cfg)
        assertFalse(cmds.any { it.contains(" -A ") }, "cleanup tidak boleh -A: $cmds")
        val delPrerouting = cmds.indexOfFirst { it.contains("-D PREROUTING") }
        val delOutput = cmds.indexOfFirst { it.contains("-D OUTPUT") }
        val flushLocal = cmds.indexOf("iptables -t nat -F TAPTAPNG")
        val deleteLocal = cmds.indexOf("iptables -t nat -X TAPTAPNG")
        val deleteTether = cmds.indexOf("iptables -t nat -X TAPTAPNG_TETH")
        assertTrue(delPrerouting >= 0 && delOutput > delPrerouting)
        assertTrue(flushLocal > delOutput && deleteLocal > flushLocal)
        assertTrue(deleteTether > deleteLocal)
        assertTrue(
            cmds.contains("iptables -t nat -D OUTPUT -m owner --uid-owner 10123 -j RETURN"),
        )
    }

    @Test
    fun `cleanup only touches taptapng chains`() {
        val cmds = RootIptables.cleanupCommands(cfg)
        assertTrue(cmds.all { RootIptables.isOwnedCommand(it) }, "cleanup: $cmds")
        assertFalse(RootIptables.isOwnedCommand("iptables -t nat -F DOCKER"))
        assertFalse(RootIptables.isOwnedCommand("iptables -t nat -F"))
        assertTrue(RootIptables.isOwnedCommand("iptables -t nat -N TAPTAPNG"))
    }
}
