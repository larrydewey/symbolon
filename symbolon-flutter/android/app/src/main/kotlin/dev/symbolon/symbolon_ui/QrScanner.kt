package dev.symbolon.symbolon_ui

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.util.Size
import android.view.Surface
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

// The QR scanner behind lib/pages/scan_page.dart: the platform camera
// (Camera2) and ZXing's decoder, in this process. Frames go nowhere else
// and nothing here uses the network.
class QrScanner(private val activity: Activity, engine: FlutterEngine) : MethodChannel.MethodCallHandler {
    private val channel = MethodChannel(engine.dartExecutor.binaryMessenger, "symbolon/scanner")
    private val textures = engine.renderer
    private val main = Handler(Looper.getMainLooper())
    private var session: Session? = null
    private var waiting: MethodChannel.Result? = null   // a start, until the user answers the permission prompt

    init {
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "start" -> start(result)
            "stop" -> {
                stop()
                result.success(null)
            }
            "rotation" -> result.success(displayRotation())
            else -> result.notImplemented()
        }
    }

    private fun start(result: MethodChannel.Result) {
        stop()
        if (activity.checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            open(result)
        } else {
            waiting = result
            activity.requestPermissions(arrayOf(Manifest.permission.CAMERA), PERMISSION_REQUEST)
        }
    }

    // From the activity's onRequestPermissionsResult.
    fun onPermission(requestCode: Int, granted: Boolean) {
        if (requestCode != PERMISSION_REQUEST) return
        val result = waiting ?: return
        waiting = null
        if (granted) open(result) else result.error(PERMISSION_DENIED, "Camera permission denied.", null)
    }

    private fun stop() {
        waiting?.error(STOPPED, "The scanner was closed.", null)
        waiting = null
        session?.close()
        session = null
    }

    private fun open(result: MethodChannel.Result) {
        val manager = activity.getSystemService(Context.CAMERA_SERVICE) as CameraManager
        val id = try {
            backCamera(manager)
        } catch (e: Exception) {
            null
        }
        if (id == null) return result.error(UNAVAILABLE, "This device has no camera to scan with.", null)
        val s = Session(manager, id, result)
        session = s
        s.open()
    }

    private fun backCamera(manager: CameraManager): String? {
        val ids = manager.cameraIdList
        return ids.firstOrNull { manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK }
            ?: ids.firstOrNull()
    }

    // Quarter turns the display is away from the device's natural orientation.
    @Suppress("DEPRECATION")
    private fun displayRotation() = when (activity.windowManager.defaultDisplay.rotation) {
        Surface.ROTATION_90 -> 1
        Surface.ROTATION_180 -> 2
        Surface.ROTATION_270 -> 3
        else -> 0
    }

    // One opening of the camera. Its camera callbacks and frames run on its
    // own thread; it talks to Dart from the main thread, and only while it
    // is still the current session.
    private inner class Session(
        private val manager: CameraManager,
        private val id: String,
        private var result: MethodChannel.Result?,
    ) {
        private val thread = HandlerThread("symbolon-qr").apply { start() }
        private val handler = Handler(thread.looper)
        private val entry = textures.createSurfaceTexture()
        private val luma = Luma()
        private var reader: ImageReader? = null
        private var camera: CameraDevice? = null
        private var capture: CameraCaptureSession? = null
        private var preview: Surface? = null
        private var closed = false

        @SuppressLint("MissingPermission") // start() has the permission before it gets here
        fun open() {
            try {
                val characteristics = manager.getCameraCharacteristics(id)
                val size = chooseSize(characteristics)
                val orientation = characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 0
                val texture: SurfaceTexture = entry.surfaceTexture()
                texture.setDefaultBufferSize(size.width, size.height)
                preview = Surface(texture)
                reader = ImageReader.newInstance(size.width, size.height, ImageFormat.YUV_420_888, 2).apply {
                    setOnImageAvailableListener({ frame(it) }, handler)
                }
                // The texture shows the frame upright for the device's natural orientation.
                val turned = orientation % 180 != 0
                val info = mapOf(
                    "texture" to entry.id(),
                    "width" to (if (turned) size.height else size.width),
                    "height" to (if (turned) size.width else size.height),
                    "rotation" to displayRotation(),
                )
                manager.openCamera(id, object : CameraDevice.StateCallback() {
                    override fun onOpened(device: CameraDevice) {
                        camera = device
                        configure(device, characteristics, info)
                    }
                    override fun onDisconnected(device: CameraDevice) {
                        camera = device
                        fail()
                    }
                    override fun onError(device: CameraDevice, error: Int) {
                        camera = device
                        fail()
                    }
                }, handler)
            } catch (e: Exception) {
                fail()
            }
        }

        @Suppress("DEPRECATION") // createCaptureSession(SessionConfiguration) needs API 28
        private fun configure(device: CameraDevice, characteristics: CameraCharacteristics, info: Map<String, Any>) {
            try {
                device.createCaptureSession(listOf(preview!!, reader!!.surface), object : CameraCaptureSession.StateCallback() {
                    override fun onConfigured(s: CameraCaptureSession) {
                        capture = s
                        try {
                            val request = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW)
                            request.addTarget(preview!!)
                            request.addTarget(reader!!.surface)
                            val modes = characteristics.get(CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES) ?: intArrayOf()
                            if (CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE in modes) {
                                request.set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                            }
                            s.setRepeatingRequest(request.build(), null, handler)
                            main.post {
                                result?.success(info)
                                result = null
                            }
                        } catch (e: Exception) {
                            fail()
                        }
                    }
                    override fun onConfigureFailed(s: CameraCaptureSession) = fail()
                }, handler)
            } catch (e: Exception) {
                fail()
            }
        }

        // The camera went away (another app took it, or an error): the
        // start's result if that is still open, else a call to Dart, which
        // tries again when the app next resumes.
        private fun fail() {
            main.post {
                if (closed) return@post
                val r = result
                result = null
                close()
                if (session === this) session = null
                if (r != null) r.error(UNAVAILABLE, "The camera could not be opened.", null)
                else channel.invokeMethod("stopped", null)
            }
        }

        private fun frame(reader: ImageReader) {
            val text = reader.acquireLatestImage()?.use { image ->
                val plane = image.planes[0]
                luma.decode(plane.buffer, plane.rowStride, image.width, image.height)
            } ?: return
            main.post {
                if (!closed) channel.invokeMethod("seen", text)
            }
        }

        // On the main thread. The camera thread does the closing, so no
        // frame is being read when the reader goes.
        fun close() {
            if (closed) return
            closed = true
            result?.error(STOPPED, "The scanner was closed.", null)
            result = null
            handler.post {
                capture?.close()
                camera?.close()
                reader?.close()
                preview?.release()
                thread.quitSafely()
                main.post { entry.release() }
            }
        }
    }

    companion object {
        private const val PERMISSION_REQUEST = 4701
        private const val PERMISSION_DENIED = "permission"
        private const val UNAVAILABLE = "unavailable"
        private const val STOPPED = "stopped"

        // The smallest frame of at least 720p (enough for a code on a
        // screen across a table, little enough to decode quickly), else the
        // largest there is.
        private fun chooseSize(characteristics: CameraCharacteristics): Size {
            val map = characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)!!
            val previews = map.getOutputSizes(SurfaceTexture::class.java).toSet()
            val sizes = map.getOutputSizes(ImageFormat.YUV_420_888).filter { it in previews }.sortedBy { it.width * it.height }
            return sizes.firstOrNull { maxOf(it.width, it.height) >= 1280 && minOf(it.width, it.height) >= 720 } ?: sizes.last()
        }
    }
}

// ZXing's QR decoder over a frame's luminance plane. One per camera thread.
private class Luma {
    private val reader = QRCodeReader()
    private val hints = mapOf(DecodeHintType.TRY_HARDER to true, DecodeHintType.CHARACTER_SET to "UTF-8")
    private var bytes = ByteArray(0)

    fun decode(plane: java.nio.ByteBuffer, rowStride: Int, width: Int, height: Int): String? {
        if (bytes.size != width * height) bytes = ByteArray(width * height)
        for (row in 0 until height) {
            plane.position(row * rowStride)
            plane.get(bytes, row * width, width)
        }
        val source = PlanarYUVLuminanceSource(bytes, width, height, 0, 0, width, height, false)
        // Light on dark as well: a code on a screen in a dark theme.
        return decode(source) ?: decode(source.invert())
    }

    private fun decode(source: LuminanceSource): String? = try {
        reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
    } catch (e: ReaderException) {
        null
    } finally {
        reader.reset()
    }
}
