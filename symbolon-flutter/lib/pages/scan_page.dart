import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../home_link.dart';

/// The camera, until it sees a Symbolon Home pairing code; returns its text.
class ScanPage extends StatefulWidget {
  const ScanPage({super.key});

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
      if (HomeLink.parse(text) != null) {
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
      appBar: AppBar(title: const Text('Scan your Symbolon Home code')),
      body: Stack(children: [
        MobileScanner(controller: camera, onDetect: seen),
        Align(
          alignment: Alignment.bottomCenter,
          child: Container(
            width: double.infinity,
            color: Colors.black54,
            padding: const EdgeInsets.all(16),
            child: Text(
              other == null ? 'Point the camera at the code your box shows.' : 'That code is not a Symbolon Home code.',
              style: const TextStyle(color: Colors.white),
              textAlign: TextAlign.center,
            ),
          ),
        ),
      ]),
    );
  }
}
