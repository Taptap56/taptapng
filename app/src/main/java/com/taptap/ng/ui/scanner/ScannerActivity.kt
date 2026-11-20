package com.taptap.ng.ui.scanner

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.hardware.Camera
import android.os.Bundle
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.taptap.ng.R
import com.taptap.ng.TaptapNGApp
import java.util.concurrent.Executors

/**
 * QR scanner for config import. Deliberately NOT CameraX: CameraX
 * would add megabytes of libraries against the small-APK goal.
 * Instead the framework Camera1 API (deprecated but present on all
 * supported devices) feeds frames to ZXing core (~200 KB), the same
 * decoder v2rayNG uses. Tradeoff: Camera1 needs manual preview-size
 * and orientation handling, and no longer receives new features;
 * it is kept because it is the lightest working scanner.
 */
class ScannerActivity : AppCompatActivity(), SurfaceHolder.Callback, Camera.PreviewCallback {

    companion object {
        const val EXTRA_TEXT = "text"
    }

    private lateinit var surfaceView: SurfaceView
    private var camera: Camera? = null
    private var decoding = false
    private var resultDelivered = false
    private val decodeExecutor = Executors.newSingleThreadExecutor()

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            startCameraIfReady()
        } else {
            Toast.makeText(this, R.string.toast_qr_no_camera, Toast.LENGTH_SHORT).show()
            finish()
        }
    }

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(TaptapNGApp.wrapLocale(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scanner)
        surfaceView = findViewById(R.id.preview)
        surfaceView.holder.addCallback(this)
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            startCameraIfReady()
        } else {
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    override fun onPause() {
        super.onPause()
        stopCamera()
    }

    override fun onDestroy() {
        super.onDestroy()
        decodeExecutor.shutdownNow()
    }

    private fun startCameraIfReady() {
        if (!surfaceView.holder.surface.isValid) return
        if (camera != null) return
        try {
            val cam = Camera.open()
            val params = cam.parameters
            // Largest preview size at most 1280 wide (decode cost).
            val best = params.supportedPreviewSizes
                ?.filter { it.width <= 1280 }
                ?.maxByOrNull { it.width * it.height }
                ?: params.previewSize
            params.setPreviewSize(best.width, best.height)
            params.focusMode = Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE
                .takeIf { params.supportedFocusModes?.contains(it) == true }
                ?: params.focusMode
            cam.parameters = params
            cam.setDisplayOrientation(90)
            cam.setPreviewDisplay(surfaceView.holder)
            cam.setPreviewCallback(this)
            cam.startPreview()
            camera = cam
        } catch (_: Exception) {
            Toast.makeText(this, R.string.toast_qr_no_camera, Toast.LENGTH_SHORT).show()
            finish()
        }
    }

    private fun stopCamera() {
        camera?.let {
            runCatching {
                it.setPreviewCallback(null)
                it.stopPreview()
                it.release()
            }
        }
        camera = null
    }

    override fun surfaceCreated(holder: SurfaceHolder) {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            startCameraIfReady()
        }
    }

    override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) = Unit
    override fun surfaceDestroyed(holder: SurfaceHolder) = Unit

    override fun onPreviewFrame(data: ByteArray?, camera: Camera?) {
        if (data == null || camera == null || decoding || resultDelivered) return
        decoding = true
        val size = camera.parameters.previewSize
        decodeExecutor.execute {
            try {
                val source = PlanarYUVLuminanceSource(
                    data, size.width, size.height, 0, 0, size.width, size.height, false
                )
                val bitmap = BinaryBitmap(HybridBinarizer(source))
                val hints = mapOf(
                    DecodeHintType.TRY_HARDER to true,
                    DecodeHintType.POSSIBLE_FORMATS to
                        listOf(com.google.zxing.BarcodeFormat.QR_CODE),
                )
                val result = MultiFormatReader().apply { setHints(hints) }.decode(bitmap)
                resultDelivered = true
                runOnUiThread {
                    setResult(
                        Activity.RESULT_OK,
                        Intent().putExtra(EXTRA_TEXT, result.text)
                    )
                    finish()
                }
            } catch (_: Exception) {
                // No QR in this frame — try the next one.
            } finally {
                decoding = false
            }
        }
    }
}
