import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/pages/scan_page.dart';

// The scan page against a stand-in for the camera side (QrScanner.kt).
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final binary = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  const pair = 'symbolon://pair?h=box.lan&p=47000&c=AAAAAAAAAAAAAAAAAAAAAA&f=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

  late List<String> calls;
  PlatformException? refuse;

  setUp(() {
    calls = [];
    refuse = null;
    binary.setMockMethodCallHandler(ScanPage.camera, (call) async {
      calls.add(call.method);
      if (call.method == 'start') {
        if (refuse != null) throw refuse!;
        return {'texture': 7, 'width': 720, 'height': 1280, 'rotation': 0};
      }
      if (call.method == 'rotation') return 0;
      return null;
    });
  });
  tearDown(() => binary.setMockMethodCallHandler(ScanPage.camera, null));

  Future<void> fromCamera(String method, [Object? arguments]) => binary.handlePlatformMessage(
      ScanPage.camera.name, const StandardMethodCodec().encodeMethodCall(MethodCall(method, arguments)), (_) {});

  // A page that pushes the scan page and keeps what it returned.
  Future<List<String?>> open(WidgetTester tester, Widget page) async {
    final results = <String?>[];
    await tester.pumpWidget(MaterialApp(
      home: Builder(builder: (context) => TextButton(
        onPressed: () async => results.add(await Navigator.of(context).push<String>(MaterialPageRoute(builder: (_) => page))),
        child: const Text('open'),
      )),
    ));
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();
    return results;
  }

  testWidgets('starts the camera and shows its picture', (tester) async {
    await open(tester, const ScanPage());
    expect(calls, ['start']);
    expect(tester.widget<Texture>(find.byType(Texture)).textureId, 7);
    expect(find.text('Point the camera at the code your box shows.'), findsOneWidget);
  });

  testWidgets('a Home code returns its text, once, and stops the camera', (tester) async {
    final results = await open(tester, const ScanPage());
    await fromCamera('seen', pair);
    await fromCamera('seen', pair);
    await tester.pumpAndSettle();
    expect(results, [pair]);
    expect(find.byType(ScanPage), findsNothing);
    expect(calls, ['start', 'stop']);
  });

  testWidgets('another code says so and keeps scanning', (tester) async {
    final results = await open(tester, const ScanPage());
    await fromCamera('seen', 'https://example.com/');
    await tester.pump();
    expect(find.text('That code is not a Symbolon Home code.'), findsOneWidget);
    expect(results, isEmpty);
    await fromCamera('seen', pair);
    await tester.pumpAndSettle();
    expect(results, [pair]);
  });

  testWidgets('the add-a-device scanner takes what it is told to', (tester) async {
    bool isLink(String t) => t.startsWith('symbolon://link?');
    final results = await open(tester, ScanPage(accepts: isLink, wrong: "That is not a new device's code."));
    await fromCamera('seen', pair);
    await tester.pump();
    expect(find.text("That is not a new device's code."), findsOneWidget);
    await fromCamera('seen', 'symbolon://link?a=1&s=2');
    await tester.pumpAndSettle();
    expect(results, ['symbolon://link?a=1&s=2']);
  });

  testWidgets('going back returns nothing and stops the camera', (tester) async {
    final results = await open(tester, const ScanPage());
    await tester.tap(find.byType(BackButton));
    await tester.pumpAndSettle();
    expect(results, [null]);
    expect(calls, ['start', 'stop']);
  });

  testWidgets('a refused permission is shown, and not asked for again on resume', (tester) async {
    refuse = PlatformException(code: 'permission', message: 'Camera permission denied.');
    await open(tester, const ScanPage());
    await tester.pump();
    expect(find.text('Camera permission denied.'), findsOneWidget);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pump();
    expect(calls, ['start']);
  });

  testWidgets('leaving the app stops the camera; coming back starts it', (tester) async {
    await open(tester, const ScanPage());
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    expect(calls, ['start', 'stop']);
    expect(find.byType(Texture), findsNothing);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
    expect(calls, ['start', 'stop', 'start']);
    expect(find.byType(Texture), findsOneWidget);
  });
}
