// The Symbolon mark and the app's look. The mark is a round token broken in
// two along a zigzag seam, its halves slightly apart: each party keeps one,
// and they fit. The geometry matches tools/icon/make_icons.py, which makes
// the launcher icon and the splash screen from it.

import 'package:flutter/material.dart';

class Brand {
  static const indigo = Color(0xFF283593);
  static const gold = Color(0xFFFFC857);
  static const paper = Color(0xFFFFFFFF);

  static ThemeData theme(Brightness b) {
    final scheme = ColorScheme.fromSeed(seedColor: indigo, brightness: b, tertiary: b == Brightness.light ? const Color(0xFF7A5900) : gold);
    final shape = RoundedRectangleBorder(borderRadius: BorderRadius.circular(16));
    return ThemeData(
      colorScheme: scheme,
      useMaterial3: true,
      cardTheme: CardThemeData(shape: shape, clipBehavior: Clip.antiAlias),
      snackBarTheme: SnackBarThemeData(behavior: SnackBarBehavior.floating, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12))),
      inputDecorationTheme: InputDecorationTheme(border: OutlineInputBorder(borderRadius: BorderRadius.circular(12))),
      bottomSheetTheme: const BottomSheetThemeData(showDragHandle: true),
      listTileTheme: const ListTileThemeData(shape: RoundedRectangleBorder(borderRadius: BorderRadius.all(Radius.circular(16)))),
      // The back gesture previews the page underneath on Android 14+.
      pageTransitionsTheme: const PageTransitionsTheme(builders: {
        TargetPlatform.android: PredictiveBackPageTransitionsBuilder(),
        TargetPlatform.linux: FadeForwardsPageTransitionsBuilder(),
      }),
    );
  }
}

/// The mark alone, [size] wide. Its halves take [left] and [right], by
/// default the theme's primary colour and gold.
class SymbolonMark extends StatelessWidget {
  final double size;
  final Color? left;
  final Color? right;
  const SymbolonMark({super.key, this.size = 48, this.left, this.right});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Semantics(
      label: 'Symbolon',
      image: true,
      child: CustomPaint(size: Size(size, size * _h / _w), painter: _MarkPainter(left ?? cs.primary, right ?? Brand.gold)),
    );
  }
}

/// The mark on its indigo tile, as on the launcher.
class SymbolonBadge extends StatelessWidget {
  final double size;
  const SymbolonBadge({super.key, this.size = 96});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: Brand.indigo,
        borderRadius: BorderRadius.circular(size * 0.26),
        boxShadow: [BoxShadow(color: Brand.indigo.withValues(alpha: 0.35), blurRadius: size * 0.2, offset: Offset(0, size * 0.06))],
      ),
      alignment: Alignment.center,
      child: SymbolonMark(size: size * 0.64, left: Brand.paper),
    );
  }
}

// The mark's box in its own units (x 20..194, y 17..183), with a little air.
const double _w = 178, _h = 170, _cx = 107, _cy = 100;
const double _gap = 14, _dy = 3;
const _seam = [(100.0, 180.0), (92.0, 160.0), (108.0, 140.0), (90.0, 120.0), (110.0, 100.0), (92.0, 80.0), (108.0, 60.0), (94.0, 40.0), (100.0, 20.0)];

Path _leftHalf() {
  const y = _dy;
  final p = Path()
    ..fillType = PathFillType.evenOdd
    ..moveTo(100, 20 + y)
    ..arcToPoint(const Offset(100, 180 + y), radius: const Radius.circular(80), clockwise: false);
  for (final (sx, sy) in _seam.sublist(1, _seam.length - 1)) {
    p.lineTo(sx, sy + y);
  }
  p
    ..close()
    // The rim, cut out.
    ..moveTo(90, 33.75 + y)
    ..arcToPoint(const Offset(90, 166.25 + y), radius: const Radius.circular(67), clockwise: false)
    ..lineTo(90, 160.18 + y)
    ..arcToPoint(const Offset(90, 39.82 + y), radius: const Radius.circular(61))
    ..close();
  return p;
}

Path _rightHalf() {
  const y = -_dy;
  final p = Path()
    ..fillType = PathFillType.evenOdd
    ..moveTo(100 + _gap, 20 + y)
    ..arcToPoint(const Offset(100 + _gap, 180 + y), radius: const Radius.circular(80));
  for (final (sx, sy) in _seam.sublist(1, _seam.length - 1)) {
    p.lineTo(sx + _gap, sy + y);
  }
  p
    ..close()
    ..moveTo(124, 33.75 + y)
    ..arcToPoint(const Offset(124, 166.25 + y), radius: const Radius.circular(67))
    ..lineTo(124, 160.18 + y)
    ..arcToPoint(const Offset(124, 39.82 + y), radius: const Radius.circular(61), clockwise: false)
    ..close();
  return p;
}

class _MarkPainter extends CustomPainter {
  final Color left;
  final Color right;
  _MarkPainter(this.left, this.right);

  static final _l = _leftHalf();
  static final _r = _rightHalf();

  @override
  void paint(Canvas canvas, Size size) {
    final s = size.width / _w;
    canvas
      ..save()
      ..translate(size.width / 2, size.height / 2)
      ..scale(s)
      ..translate(-_cx, -_cy)
      ..drawPath(_l, Paint()..color = left)
      ..drawPath(_r, Paint()..color = right)
      ..restore();
  }

  @override
  bool shouldRepaint(_MarkPainter old) => old.left != left || old.right != right;
}
