// A payment card drawn as the card itself: the network's colours, a chip,
// the number in the network's grouping, the holder and the expiry. The
// network is shown by name only (no network's logo is reproduced).

import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'validate.dart' show cardBrand;

/// The look of one card network: its gradient and how its name is set.
class _Network {
  final List<Color> colors;
  final String mark;
  final FontStyle style;
  final double size;
  const _Network(this.colors, this.mark, {this.style = FontStyle.normal, this.size = 20});
}

_Network _network(String brand) => switch (brand) {
      'Visa' => const _Network([Color(0xFF1A1F71), Color(0xFF2B4BB0)], 'VISA', style: FontStyle.italic, size: 26),
      'Mastercard' => const _Network([Color(0xFF1B1B1F), Color(0xFF4A2C2A)], 'mastercard', size: 18),
      'American Express' => const _Network([Color(0xFF006FCF), Color(0xFF5FA8E3)], 'AMERICAN\nEXPRESS', size: 13),
      'Discover' => const _Network([Color(0xFF23272F), Color(0xFFE87722)], 'DISCOVER', size: 18),
      'JCB' => const _Network([Color(0xFF0B4EA2), Color(0xFF2E9E48)], 'JCB', style: FontStyle.italic, size: 24),
      'Diners Club' => const _Network([Color(0xFF004A97), Color(0xFF7A8CA3)], 'Diners Club', size: 16),
      _ => const _Network([Color(0xFF37474F), Color(0xFF607D8B)], '', size: 18),
    };

/// The digits in the network's grouping: 4-6-5 for American Express,
/// 4-6-4 for Diners Club's 14 digits, else groups of four.
String groupCardNumber(String digits) {
  final brand = cardBrand(digits);
  final List<int> groups = brand == 'American Express' && digits.length == 15
      ? [4, 6, 5]
      : brand == 'Diners Club' && digits.length == 14
          ? [4, 6, 4]
          : [for (var i = 0; i < digits.length; i += 4) math.min(4, digits.length - i)];
  final out = <String>[];
  var at = 0;
  for (final g in groups) {
    if (at >= digits.length) break;
    out.add(digits.substring(at, math.min(at + g, digits.length)));
    at += g;
  }
  return out.join(' ');
}

/// The number as the card face shows it: all but the last four digits
/// masked, in the same grouping.
String maskCardNumber(String digits) {
  if (digits.length <= 4) return digits;
  final keep = digits.length - 4;
  var i = 0;
  return groupCardNumber(digits).split('').map((c) => c == ' ' ? c : (i++ < keep ? '•' : c)).join();
}

/// The card's face. [revealed] shows the whole number; otherwise only its
/// last four digits. [onTap] toggles it (the page decides).
class CardFace extends StatelessWidget {
  final String number;     // digits only
  final String holder;
  final String expiry;     // MM/YY
  final bool revealed;
  final VoidCallback? onTap;
  const CardFace({super.key, required this.number, this.holder = '', this.expiry = '', this.revealed = false, this.onTap});

  @override
  Widget build(BuildContext context) {
    final net = _network(cardBrand(number));
    final shown = number.isEmpty ? '•••• •••• •••• ••••' : (revealed ? groupCardNumber(number) : maskCardNumber(number));
    const ink = Colors.white;
    const label = TextStyle(color: Colors.white70, fontSize: 9, letterSpacing: 1.2, fontWeight: FontWeight.w600);
    final value = TextStyle(color: ink, fontSize: 15, letterSpacing: 1.5, fontWeight: FontWeight.w600, shadows: _emboss);
    return ConstrainedBox(
      constraints: const BoxConstraints(maxWidth: 420),
      child: AspectRatio(
        aspectRatio: 85.6 / 53.98, // ISO/IEC 7810 ID-1
        child: Semantics(
          label: 'Card ending ${number.length >= 4 ? number.substring(number.length - 4) : number}',
          button: onTap != null,
          child: Material(
            color: Colors.transparent,
            elevation: 6,
            shadowColor: net.colors.first.withValues(alpha: 0.5),
            borderRadius: BorderRadius.circular(16),
            clipBehavior: Clip.antiAlias,
            child: Ink(
              decoration: BoxDecoration(
                gradient: LinearGradient(colors: net.colors, begin: Alignment.topLeft, end: Alignment.bottomRight),
              ),
              child: InkWell(
                key: const Key('card-face'),
                onTap: onTap,
                child: Stack(children: [
                  Positioned.fill(child: CustomPaint(painter: _Sheen())),
                  Padding(
                    padding: const EdgeInsets.fromLTRB(22, 18, 22, 18),
                    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        const Spacer(),
                        Text(net.mark,
                            textAlign: TextAlign.right,
                            style: TextStyle(color: ink, fontSize: net.size, fontStyle: net.style, fontWeight: FontWeight.w900, height: 1.0, letterSpacing: 0.5)),
                      ]),
                      const Spacer(),
                      Row(children: [
                        const _Chip(),
                        const SizedBox(width: 12),
                        Transform.rotate(angle: math.pi / 2, child: const Icon(Icons.wifi, color: Colors.white70, size: 22)),
                      ]),
                      const Spacer(),
                      FittedBox(
                        fit: BoxFit.scaleDown,
                        child: Text(shown,
                            key: const Key('card-face-number'),
                            style: TextStyle(color: ink, fontFamily: 'monospace', fontSize: 22, letterSpacing: 2, fontWeight: FontWeight.w600, shadows: _emboss)),
                      ),
                      const SizedBox(height: 10),
                      Row(crossAxisAlignment: CrossAxisAlignment.end, children: [
                        Expanded(
                          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                            const Text('CARDHOLDER', style: label),
                            Text(holder.isEmpty ? '—' : holder.toUpperCase(), maxLines: 1, overflow: TextOverflow.ellipsis, style: value),
                          ]),
                        ),
                        if (expiry.isNotEmpty)
                          Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                            const Text('VALID THRU', style: label),
                            Text(expiry, style: value.copyWith(fontFamily: 'monospace')),
                          ]),
                      ]),
                    ]),
                  ),
                ]),
              ),
            ),
          ),
        ),
      ),
    );
  }

  static const _emboss = [Shadow(color: Color(0x66000000), offset: Offset(0, 1), blurRadius: 1)];
}

/// The EMV contact chip.
class _Chip extends StatelessWidget {
  const _Chip();

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 44,
      height: 34,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(6),
        gradient: const LinearGradient(colors: [Color(0xFFE9D8A6), Color(0xFFC9A44C), Color(0xFFF1E2B3)], begin: Alignment.topLeft, end: Alignment.bottomRight),
      ),
      child: CustomPaint(painter: _ChipLines()),
    );
  }
}

class _ChipLines extends CustomPainter {
  @override
  void paint(Canvas canvas, Size s) {
    final p = Paint()
      ..color = const Color(0x66704F10)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1;
    canvas.drawLine(Offset(0, s.height / 3), Offset(s.width, s.height / 3), p);
    canvas.drawLine(Offset(0, 2 * s.height / 3), Offset(s.width, 2 * s.height / 3), p);
    canvas.drawLine(Offset(s.width / 3, 0), Offset(s.width / 3, s.height / 3), p);
    canvas.drawLine(Offset(s.width / 3, 2 * s.height / 3), Offset(s.width / 3, s.height), p);
    canvas.drawLine(Offset(2 * s.width / 3, 0), Offset(2 * s.width / 3, s.height / 3), p);
    canvas.drawLine(Offset(2 * s.width / 3, 2 * s.height / 3), Offset(2 * s.width / 3, s.height), p);
    canvas.drawRRect(RRect.fromRectAndRadius(Rect.fromLTWH(s.width / 3, s.height / 3, s.width / 3, s.height / 3), const Radius.circular(3)), p);
  }

  @override
  bool shouldRepaint(_ChipLines old) => false;
}

/// A soft diagonal highlight, as light on a plastic card.
class _Sheen extends CustomPainter {
  @override
  void paint(Canvas canvas, Size s) {
    final path = Path()
      ..moveTo(s.width * 0.45, 0)
      ..lineTo(s.width, 0)
      ..lineTo(s.width, s.height * 0.55)
      ..close();
    canvas.drawPath(path, Paint()..color = const Color(0x14FFFFFF));
    canvas.drawCircle(Offset(s.width * 0.05, s.height * 1.1), s.height * 0.6, Paint()..color = const Color(0x0FFFFFFF));
  }

  @override
  bool shouldRepaint(_Sheen old) => false;
}
