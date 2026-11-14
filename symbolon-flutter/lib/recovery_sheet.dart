// The recovery sheet: what a person keeps to get their identity back after
// losing every device (SPEC 13.2). Both values are needed, so they are
// shown together: the identity log (which identity) and the kit (the key).
// On screen to write down, or as an image to print, with a QR code that the
// Recovery page scans.

import 'dart:math' as math;
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:qr/qr.dart';

import 'links.dart';
import 'widgets.dart';

const _ink = Color(0xFF3E2C00);
const _paper = Color(0xFFFFF0C2);

/// The sheet on screen: the identity log and the kit, in groups of four,
/// on paper colours in either theme.
class RecoverySheetCard extends StatelessWidget {
  final RecoverySheet sheet;
  const RecoverySheetCard(this.sheet, {super.key});

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    Widget value(String label, String v, {required bool secret, required Key key}) {
      final g = groupsOf(v);
      return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(children: [
          Expanded(child: Text(label, style: t.labelLarge?.copyWith(color: _ink))),
          IconButton(tooltip: 'Copy', icon: const Icon(Icons.copy, size: 20, color: _ink), onPressed: () => copyText(context, label, v, secret: secret)),
        ]),
        // One label, so a screen reader reads it as one value.
        Semantics(
          key: key,
          label: '$label: ${g.join(' ')}',
          excludeSemantics: true,
          child: Wrap(spacing: 14, children: [
            for (final x in g) Text(x, style: t.titleMedium?.copyWith(fontFamily: 'monospace', color: _ink, height: 1.6, letterSpacing: 0.5)),
          ]),
        ),
      ]);
    }

    return Card(
      key: const Key('kit-card'),
      color: _paper,
      margin: const EdgeInsets.only(bottom: 8),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 8, 8, 16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          if (sheet.log.isNotEmpty) ...[
            value('1. Identity log', sheet.log, secret: false, key: const Key('sheet-log')),
            const Divider(color: Color(0x553E2C00), height: 24),
          ],
          value(sheet.log.isEmpty ? 'Recovery kit' : '2. Recovery kit', sheet.kit, secret: true, key: const Key('sheet-kit')),
          const SizedBox(height: 8),
          Text('Both are needed. ${groupsOf(sheet.log).length + groupsOf(sheet.kit).length} groups of four in all.', style: t.bodySmall?.copyWith(color: _ink)),
        ]),
      ),
    );
  }
}

/// Saves the sheet as an image to print; says what to do with the file.
Future<void> saveSheet(BuildContext context, RecoverySheet sheet) async {
  final bytes = await sheetPng(sheet);
  final Uri? saved;
  try {
    saved = await FilePicker.saveFile(dialogTitle: 'Save your recovery sheet', fileName: 'symbolon-recovery-sheet.png', bytes: bytes, mimeType: 'image/png');
  } catch (e) {
    if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(errorBar('Could not save the sheet ($e).'));
    return;
  }
  if (saved == null || !context.mounted) return;
  await showOutput(context, 'Print it, then delete the file',
      'Print the sheet and keep the paper somewhere safe and private. Then delete the file, and do not keep it in a photo '
      'library or a cloud folder: anyone with the sheet can start a recovery of your identity. (Your devices are told, and '
      'can stop it.)');
}

/// The sheet as an A4 page at 150 dpi: the two values to read, and a QR
/// code with both for the Recovery page to scan.
Future<Uint8List> sheetPng(RecoverySheet sheet, {DateTime? made}) async {
  const w = 1240.0, h = 1754.0, margin = 110.0, inner = w - 2 * margin;
  final rec = ui.PictureRecorder();
  final c = Canvas(rec, const Rect.fromLTWH(0, 0, w, h));
  c.drawRect(const Rect.fromLTWH(0, 0, w, h), Paint()..color = Colors.white);
  var y = margin;

  double text(String s, double size, {bool mono = false, FontWeight weight = FontWeight.normal, Color color = Colors.black, double width = inner, double x = margin, TextAlign align = TextAlign.left}) {
    final b = ui.ParagraphBuilder(ui.ParagraphStyle(fontSize: size, fontFamily: mono ? 'monospace' : 'Roboto', fontWeight: weight, height: mono ? 1.5 : 1.35, textAlign: align))
      ..pushStyle(ui.TextStyle(color: color, letterSpacing: mono ? 2 : 0))
      ..addText(s);
    final p = b.build()..layout(ui.ParagraphConstraints(width: width));
    c.drawParagraph(p, Offset(x, y));
    return p.height;
  }

  // The QR code, both values in one, at the top right; the title beside it.
  const side = 380.0;
  final qr = QrImage(QrCode(payload: QrPayload.fromString(sheet.link), errorCorrectLevel: QrErrorCorrectLevel.medium));
  final left = w - margin - side, m = side / (qr.moduleCount + 8);
  final dark = Paint()..color = Colors.black;
  for (var r = 0; r < qr.moduleCount; r++) {
    for (var col = 0; col < qr.moduleCount; col++) {
      if (qr.isDark(r, col)) c.drawRect(Rect.fromLTWH(left + (col + 4) * m, y + (r + 4) * m, m + 0.5, m + 0.5), dark);
    }
  }
  final qrTop = y;
  y = qrTop + side;
  text('Scan on a new device', 24, color: Colors.black54, x: left, width: side, align: TextAlign.center);
  y = qrTop + 30;

  final d = made ?? DateTime.now();
  const beside = inner - side - 40;
  y += text('Symbolon recovery sheet', 60, weight: FontWeight.bold, width: beside) + 12;
  y += text('Made ${d.year}-${d.month.toString().padLeft(2, '0')}-${d.day.toString().padLeft(2, '0')}', 28, color: Colors.black54, width: beside) + 20;
  y += text('Keep it somewhere safe and private.', 28, weight: FontWeight.bold, width: beside);
  y = (qrTop + side + 60 > y ? qrTop + side + 60 : y);
  y += text('With this sheet you can get your identity back if you lose every device: on a new device, open Symbolon, choose '
          '"Lost every device? Recover with your kit", and scan the code above, or type both values in. Anyone who has this '
          'sheet can start a recovery of your identity; your devices are told, and can stop it.',
          28) +
      44;
  for (final (label, v) in [('1. Identity log', sheet.log), ('2. Recovery kit', sheet.kit)]) {
    y += text(label, 30, weight: FontWeight.bold) + 8;
    y += text(groupsOf(v).join('  '), 42, mono: true) + 36;
  }

  final img = await rec.endRecording().toImage(w.toInt(), h.toInt());
  final png = await img.toByteData(format: ui.ImageByteFormat.png);
  return png!.buffer.asUint8List();
}

/// Checks a sheet was written down right: two groups typed back from the
/// paper, one from each value, while the sheet is out of sight.
class SheetCheck extends StatefulWidget {
  final RecoverySheet sheet;
  final VoidCallback onBack;       // to look at the sheet again
  final VoidCallback onChecked;
  const SheetCheck({super.key, required this.sheet, required this.onBack, required this.onChecked});

  /// Which groups to ask for: (label, the group's text) twice.
  static List<(String, String)> asks(RecoverySheet s, math.Random r) {
    final log = groupsOf(s.log), kit = groupsOf(s.kit);
    (String, String) from(String name, List<String> g, int i) => ('Group ${i + 1} of ${g.length} of the $name', g[i]);
    if (log.isEmpty) {
      final a = r.nextInt(kit.length);
      final b = (a + 1 + r.nextInt(kit.length - 1)) % kit.length;
      return [from('recovery kit', kit, a < b ? a : b), from('recovery kit', kit, a < b ? b : a)];
    }
    return [from('identity log', log, r.nextInt(log.length)), from('recovery kit', kit, r.nextInt(kit.length))];
  }

  @override
  State<SheetCheck> createState() => _SheetCheckState();
}

class _SheetCheckState extends State<SheetCheck> {
  late final asks = SheetCheck.asks(widget.sheet, math.Random.secure());
  final fields = [TextEditingController(), TextEditingController()];
  bool tried = false;

  @override
  void dispose() {
    for (final f in fields) {
      f.dispose();
    }
    super.dispose();
  }

  bool ok(int i) => fields[i].text.trim().toLowerCase() == asks[i].$2;

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Text('Check what you wrote', style: t.headlineSmall),
      const SizedBox(height: 8),
      const Text('The sheet is hidden now. From your paper, type:'),
      const SizedBox(height: 16),
      for (var i = 0; i < 2; i++)
        Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: TextField(
            key: Key('check-${i + 1}'),
            controller: fields[i],
            maxLength: 4,
            autocorrect: false,
            enableSuggestions: false,
            keyboardType: TextInputType.visiblePassword,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 20, letterSpacing: 2),
            onChanged: (_) => setState(() {}),
            decoration: InputDecoration(
              labelText: asks[i].$1,
              border: const OutlineInputBorder(),
              counterText: '',
              suffixIcon: ok(i) ? const Icon(Icons.check_circle, color: Colors.green) : null,
              errorText: tried && !ok(i) ? 'Does not match: check this group on your paper' : null,
              errorMaxLines: 2,
            ),
          ),
        ),
      WideButton('Done', key: const Key('setup-finish'), icon: Icons.check, onPressed: () {
        // Read now, not at the last build: the last letter may just have been typed.
        if (ok(0) && ok(1)) return widget.onChecked();
        setState(() => tried = true);
      }),
      const SizedBox(height: 8),
      TextButton(key: const Key('sheet-again'), onPressed: widget.onBack, child: const Text('Show the sheet again')),
    ]);
  }
}

/// A new sheet on its own page (after a recovery starts, the kit that will
/// replace the old one): shown, saved to print if wanted, then checked.
class SheetPage extends StatefulWidget {
  final RecoverySheet sheet;
  final String title;
  final String intro;
  const SheetPage({super.key, required this.sheet, required this.title, required this.intro});

  @override
  State<SheetPage> createState() => _SheetPageState();
}

class _SheetPageState extends State<SheetPage> {
  bool checking = false, checked = false;

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: checked,
      child: Scaffold(
        appBar: AppBar(title: Text(widget.title), automaticallyImplyLeading: false),
        body: PageBody(children: [
          if (checking)
            SheetCheck(
              sheet: widget.sheet,
              onBack: () => setState(() => checking = false),
              onChecked: () {
                setState(() => checked = true);
                // Once rebuilt, so the page's guard lets it close.
          WidgetsBinding.instance.addPostFrameCallback((_) => mounted ? Navigator.of(context).pop() : null);
              },
            )
          else ...[
            Text(widget.intro),
            const SizedBox(height: 16),
            RecoverySheetCard(widget.sheet),
            const SizedBox(height: 8),
            WideButton('Save it to print', key: const Key('sheet-save'), icon: Icons.print_outlined, tonal: true, onPressed: () => saveSheet(context, widget.sheet)),
            const SizedBox(height: 12),
            WideButton('I have written it down', key: const Key('kept-kit'), icon: Icons.arrow_forward, onPressed: () => setState(() => checking = true)),
          ],
        ]),
      ),
    );
  }
}
