package com.taptap.x.ui.log

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.MenuItem
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.taptap.x.R
import com.taptap.x.TaptapXApp
import com.taptap.x.core.DialLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Log screen with Views, mirroring v2rayNG's LogcatActivity in
 * miniature: the app's own logcat output (no READ_LOGS permission
 * is needed for the app's own UID), with refresh / copy / clear.
 */
class LogActivity : AppCompatActivity() {

    private lateinit var logText: TextView

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(TaptapXApp.wrapLocale(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_log)
        logText = findViewById(R.id.log_text)

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finish() }
        toolbar.setOnMenuItemClickListener { item -> onToolbarMenu(item) }

        loadLog()
    }

    private fun onToolbarMenu(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.action_refresh -> {
                loadLog()
                return true
            }
            R.id.action_copy -> {
                val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(
                    ClipData.newPlainText("TaptapX log", logText.text.toString())
                )
                Toast.makeText(this, R.string.toast_copied, Toast.LENGTH_SHORT).show()
                return true
            }
            R.id.action_clear -> {
                lifecycleScope.launch(Dispatchers.IO) {
                    runCatching { Runtime.getRuntime().exec(arrayOf("logcat", "-c")) }
                    loadLog()
                }
                return true
            }
        }
        return false
    }

    private fun loadLog() {
        lifecycleScope.launch(Dispatchers.IO) {
            val output = runCatching {
                val process = Runtime.getRuntime()
                    .exec(arrayOf("logcat", "-d", "-t", "300"))
                process.inputStream.bufferedReader().readText()
            }.getOrElse { "Failed to read logcat: ${it.message}" }
            withContext(Dispatchers.Main) {
                // v1.0.6, fix E: the in-app dial log first — it
                // survives `logcat -c` and rotation, and it is the
                // only place that shows every dial stage. The logcat
                // dump follows with the DialLog lines filtered out
                // (they are already above, via the logcat sink).
                val dialLines = DialLog.lines()
                val logcatLines = output.lines()
                    .filterNot { it.contains(DialLog.TAG) }
                val text = buildString {
                    if (dialLines.isNotEmpty()) {
                        append("— ${DialLog.TAG} (in-app) —\n")
                        dialLines.forEach { append(it).append('\n') }
                        append('\n')
                    }
                    append(logcatLines.joinToString("\n"))
                }
                logText.text = text.ifBlank { getString(R.string.log_empty) }
            }
        }
    }
}
