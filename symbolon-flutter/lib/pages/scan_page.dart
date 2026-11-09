import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../home_link.dart';

/// The camera, until it sees a code [accepts] takes (a Symbolon Home
/// pairing code unless given); returns its text. The camera and the decoder
/// are on the device (android/.../QrScanner.kt); nothing leaves it.
class ScanPage extends StatefulWidget {
  final bool Function(String text) accepts;
  final String title;
  final String hint;        // what to point at
  final String wrong;       // a code that is not one
  const ScanPage({super.key, this.accepts = _homeCode, this.title = 'Scan your Symbolon Home code',
      this.hint = 'Point the camera at the code your box shows.', this.wrong = 'That code is not a Symbolon Home code.'});

  static bool _homeCode(String t) => HomeLink.parse(t) != null;

  /// The channel to the scanner.
  static const camera = MethodChannel('symbolon/scanner');

  @override
  State<ScanPage> createState() => _ScanPageState();
}

class _ScanPageState extends State<ScanPage> with WidgetsBindingObserver {
  bool done = false;
  String? other;     // a code was seen that is not a pairing code
  int? texture;      // the camera's picture, once it runs
  Size size = Size.zero;
  int rotation = 0;  // quarter turns of the display from the device's natural orientation
  bool starting = false;
  String? failure;   // why there is no camera

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    ScanPage.camera.setMethodCallHandler(fromCamera);
    start();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    ScanPage.camera.setMethodCallHandler(null);
    stop();
    super.dispose();
  }

  Future<void> start() async {
    starting = true;
    try {
      final m = await ScanPage.camera.invokeMapMethod<String, Object?>('start');
      if (!mounted) return;
      setState(() {
        texture = m!['texture'] as int;
        size = Size((m['width'] as int).toDouble(), (m['height'] as int).toDouble());
        rotation = m['rotation'] as int;
      });
    } on PlatformException catch (e) {
      if (mounted && e.code != 'stopped') setState(() => failure = e.message ?? 'The camera could not be opened.');
    } on MissingPluginException {
      if (mounted) setState(() => failure = 'Scanning is not supported on this device.');
    } finally {
      starting = false;
    }
  }

  Future<void> stop() async {
    try {
      await ScanPage.camera.invokeMethod<void>('stop');
    } on MissingPluginException {
      // Nothing was started.
    }
  }

  Future<void> fromCamera(MethodCall call) async {
    switch (call.method) {
      case 'seen':
        seen(call.arguments as String);
      case 'stopped':
        if (mounted) setState(() => texture = null);
    }
  }

  void seen(String text) {
    if (!mounted) return;
    if (widget.accepts(text)) {
      if (done) return;
      done = true;
      Navigator.of(context).pop(text);
      return;
    }
    if (text.isNotEmpty && other == null) setState(() => other = text);
  }

  // The camera is for the app in front.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.inactive && texture != null) {
      setState(() => texture = null);
      stop();
    } else if (state == AppLifecycleState.resumed && texture == null && failure == null && !starting && !done) {
      start();
    }
  }

  @override
  void didChangeMetrics() {
    if (texture == null) return;
    ScanPage.camera.invokeMethod<int>('rotation').then((r) {
      if (mounted && r != null && r != rotation) setState(() => rotation = r);
    });
  }

  Widget picture() {
    final t = texture;
    if (failure != null) {
      return Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Padding(padding: EdgeInsets.only(bottom: 16), child: Icon(Icons.error, color: Colors.white)),
          Text(failure!, style: const TextStyle(color: Colors.white)),
        ]),
      );
    }
    if (t == null) return const SizedBox.shrink();
    return SizedBox.expand(
      child: FittedBox(
        fit: BoxFit.cover,
        clipBehavior: Clip.hardEdge,
        child: RotatedBox(
          quarterTurns: -rotation,
          child: SizedBox(width: size.width, height: size.height, child: Texture(textureId: t)),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.title)),
      body: Stack(children: [
        ColoredBox(color: Colors.black, child: SizedBox.expand(child: picture())),
        Align(
          alignment: Alignment.bottomCenter,
          child: Container(
            width: double.infinity,
            color: Colors.black54,
            padding: const EdgeInsets.all(16),
            child: Text(
              other == null ? widget.hint : widget.wrong,
              style: const TextStyle(color: Colors.white),
              textAlign: TextAlign.center,
            ),
          ),
        ),
      ]),
    );
  }
}
