import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../home_link.dart';

/// The camera, until it sees a code [accepts] takes (a Symbolon Home
/// pairing code unless given); returns its text.
class ScanPage extends StatefulWidget {
  final bool Function(String text) accepts;
  final String title;
  final String hint;        // what to point at
  final String wrong;       // a code that is not one
  const ScanPage({super.key, this.accepts = _homeCode, this.title = 'Scan your Symbolon Home code',
      this.hint = 'Point the camera at the code your box shows.', this.wrong = 'That code is not a Symbolon Home code.'});

  static bool _homeCode(String t) => HomeLink.parse(t) != null;

  @override
  State<ScanPage> createState() => _ScanPageState();
}

class _ScanPageState extends State<ScanPage> {
  final camera = MobileScannerController(formats: const [BarcodeFormat.qrCode]);
  bool done = false;
  String? other;     // a code was seen that is not a pairing code

  @override
  void dispose() {
    camera.dispose();
    super.dispose();
  }

  void seen(BarcodeCapture c) {
    for (final b in c.barcodes) {
      final text = b.rawValue ?? '';
      if (widget.accepts(text)) {
        if (done) return;
        done = true;
        Navigator.of(context).pop(text);
        return;
      }
      if (text.isNotEmpty && other == null) setState(() => other = text);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.title)),
      body: Stack(children: [
        MobileScanner(controller: camera, onDetect: seen),
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
