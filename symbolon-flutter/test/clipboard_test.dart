import 'package:material_ui/material_ui.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/widgets.dart';

// SPEC 22.2: a copied secret is marked sensitive and cleared within 30 s.
// On Android 10+ an app in the background cannot read the clipboard, so a
// clear that reads it back first never happens; the Android side does the
// copy and the clear itself (MainActivity.kt, Clip).
void main() {
  const platform = MethodChannel('symbolon/platform');
  final native = <MethodCall>[];
  final flutter = <MethodCall>[];

  Future<void> copy(WidgetTester t, {required bool secret}) async {
    t.binding.defaultBinaryMessenger.setMockMethodCallHandler(platform, (c) async {
      native.add(c);
      return true;
    });
    t.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, (c) async {
      flutter.add(c);
      return null;
    });
    addTearDown(() {
      t.binding.defaultBinaryMessenger.setMockMethodCallHandler(platform, null);
      t.binding.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, null);
    });
    await t.pumpWidget(MaterialApp(home: Scaffold(body: Builder(
      builder: (ctx) => TextButton(onPressed: () => copyText(ctx, 'Password', 'hunter2', secret: secret), child: const Text('copy')),
    ))));
    await t.tap(find.text('copy'));
    await t.pump();
  }

  setUp(() {
    native.clear();
    flutter.clear();
    debugClipboardAndroid = true;
  });
  tearDown(() => debugClipboardAndroid = null);

  testWidgets('on Android a secret is copied natively, which marks it and schedules the clear', (t) async {
    await copy(t, secret: true);
    expect(native.map((c) => c.method), ['copy']);
    expect(native.single.arguments, {'value': 'hunter2', 'secret': true});
    expect(flutter.where((c) => c.method == 'Clipboard.setData'), isEmpty);
    expect(find.textContaining('cleared from the clipboard in 30 seconds'), findsOneWidget);
  });

  testWidgets('on Android a plain copy also goes natively, cancelling a pending clear', (t) async {
    await copy(t, secret: false);
    expect(native.single.arguments, {'value': 'hunter2', 'secret': false});
    expect(flutter.where((c) => c.method == 'Clipboard.setData'), isEmpty);
    expect(find.text('Password copied'), findsOneWidget);
  });

  testWidgets('elsewhere the copy is Flutter\'s own', (t) async {
    debugClipboardAndroid = false;
    await copy(t, secret: true);
    expect(native, isEmpty);
    expect(flutter.where((c) => c.method == 'Clipboard.setData').single.arguments, {'text': 'hunter2'});
  });
}
