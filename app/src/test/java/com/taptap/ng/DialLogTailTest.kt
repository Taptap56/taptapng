package com.taptap.ng

import com.taptap.ng.core.DialLog
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * v1.0.31 (battery, H4): DialLog menyimpan baris SPEED terbaru
 * saat ditulis (tanpa salinan ring) dan melayani tail berbasis
 * sekuens (hanya baris baru). Tes-tes ini GAGAL pada kode lama
 * (tidak ada latestSpeedLine / linesSince).
 */
class DialLogTailTest {

    @Test
    fun `baris SPEED terbaru tercache tanpa lines()`() {
        DialLog.clear()
        try {
            DialLog.log("DIAL", "mulai konek")
            assertNull(DialLog.latestSpeedLine())
            DialLog.log("SPEED", "SPEED example.com:443 down=0.50MB 1.23MB/s tls+net=10ms")
            DialLog.log("DIAL", "baris lain sesudahnya")
            val cached = DialLog.latestSpeedLine()
            assertTrue(cached != null, "SPEED tidak tercache")
            assertTrue(cached!!.contains("1.23MB/s"), cached)
            assertTrue(cached.contains("SPEED "), cached)
            // Baris non-SPEED sesudahnya tidak menimpa cache.
            DialLog.log("SPEED", "SPEED other:443 down=0.10MB 0.42MB/s tls+net=1ms")
            assertTrue(DialLog.latestSpeedLine()!!.contains("0.42MB/s"))
            DialLog.clear()
            assertNull(DialLog.latestSpeedLine(), "clear harus mengosongkan cache SPEED")
        } finally {
            DialLog.clear()
        }
    }

    @Test
    fun `linesSince hanya mengembalikan baris baru sejak sekuens`() {
        DialLog.clear()
        try {
            DialLog.log("A", "baris 1")
            DialLog.log("A", "baris 2")
            DialLog.log("A", "baris 3")
            val seq = DialLog.currentSequence()
            DialLog.log("A", "baris 4")
            DialLog.log("A", "baris 5")
            val (newSeq, fresh) = DialLog.linesSince(seq)
            assertEquals(2, fresh.size)
            assertTrue(fresh[0].contains("baris 4"), fresh[0])
            assertTrue(fresh[1].contains("baris 5"), fresh[1])
            assertEquals(DialLog.currentSequence(), newSeq)
            // Tidak ada yang baru: kosong.
            val (_, none) = DialLog.linesSince(newSeq)
            assertEquals(0, none.size)
            // -1 = snapshot seluruh ring.
            val (_, all) = DialLog.linesSince(-1L)
            assertEquals(5, all.size)
        } finally {
            DialLog.clear()
        }
    }

    @Test
    fun `linesSince sesudah clear hanya mengembalikan baris sesudah clear`() {
        DialLog.clear()
        try {
            DialLog.log("A", "lama 1")
            DialLog.log("A", "lama 2")
            val seqBeforeClear = DialLog.currentSequence()
            DialLog.clear()
            DialLog.log("A", "baru 1")
            val (_, fresh) = DialLog.linesSince(seqBeforeClear)
            assertEquals(1, fresh.size)
            assertTrue(fresh[0].contains("baru 1"), fresh[0])
        } finally {
            DialLog.clear()
        }
    }

    @Test
    fun `linesSince dengan baris duplikat mengembalikan keduanya`() {
        DialLog.clear()
        try {
            DialLog.log("A", "sama")
            DialLog.log("A", "sama")
            val (_, all) = DialLog.linesSince(-1L)
            assertEquals(2, all.size)
        } finally {
            DialLog.clear()
        }
    }
}
