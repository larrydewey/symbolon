// A QR code for a text (the qr package encodes it; this paints the modules
// with a quiet zone, dark on white whatever the theme, so phones read it).

import 'package:flutter/material.dart';
import 'package:qr/qr.dart';

class QrView extends StatelessWidget {
  final String data;
  final double size;
  const QrView(this.data, {super.key, this.size = 260});

  @override
  Widget build(BuildContext context) {
    final img = QrImage(QrCode(payload: QrPayload.fromString(data), errorCorrectLevel: QrErrorCorrectLevel.medium));
    return Semantics(
      label: 'QR code',
      child: SizedBox(width: size, height: size, child: CustomPaint(painter: _QrPainter(img))),
    );
  }
}

class _QrPainter extends CustomPainter {
  final QrImage img;
  _QrPainter(this.img);

  @override
  void paint(Canvas canvas, Size s) {
    final n = img.moduleCount + 8;        // four modules of quiet zone each side
    final m = s.width / n;
    canvas.drawRect(Offset.zero & s, Paint()..color = Colors.white);
    final dark = Paint()..color = Colors.black;
    for (var r = 0; r < img.moduleCount; r++) {
      for (var c = 0; c < img.moduleCount; c++) {
        if (img.isDark(r, c)) canvas.drawRect(Rect.fromLTWH((c + 4) * m, (r + 4) * m, m + 0.5, m + 0.5), dark);
      }
    }
  }

  @override
  bool shouldRepaint(_QrPainter old) => old.img != img;
}
