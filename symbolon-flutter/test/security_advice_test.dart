// After the fix to the signing software (SPEC 6.2.2): the home page shows the
// key refresh while it is due and the master-key advice while it applies;
// the advice page shows the agent's words and takes a report.

import 'dart:io';

import 'package:material_ui/material_ui.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/main.dart';
import 'package:symbolon_ui/settings.dart';

import 'fake_agent.dart';

void main() {
  late FakeAgent agent;
  late Settings settings;

  setUp(() async {
    agent = await FakeAgent.create();
    settings = Settings(File('${agent.dir.path}/settings.json'), binary: agent.path, deviceDir: '${agent.dir.path}/dev', tutorialSeen: true);
  });
  tearDown(() => agent.dispose());

  Future<void> settle(WidgetTester t) async {
    for (var i = 0; i < 20; i++) {
      await t.runAsync(() => Future<void>.delayed(const Duration(milliseconds: 50)));
      await t.pump(const Duration(milliseconds: 50));
    }
  }

  Future<void> start(WidgetTester t) async {
    t.view.devicePixelRatio = 3;
    t.view.physicalSize = const Size(420, 900) * 3;
    addTearDown(t.view.reset);
    await t.pumpWidget(SymbolonApp(settings: settings));
    await settle(t);
  }

  testWidgets('a household made after the fix shows neither card', (t) async {
    File('${agent.dir.path}/reshare').writeAsStringSync('done');
    File('${agent.dir.path}/rotation').writeAsStringSync('none');
    await start(t);
    expect(find.byKey(const Key('security-refresh')), findsNothing);
    expect(find.byKey(const Key('security-advice')), findsNothing);
  });

  testWidgets('the refresh waiting for the cosigner, and the advice for a new household key', (t) async {
    File('${agent.dir.path}/reshare').writeAsStringSync('waiting-cosigner');
    File('${agent.dir.path}/rotation').writeAsStringSync('strongly-recommended');
    await start(t);
    expect(find.byKey(const Key('security-refresh')), findsOneWidget);
    expect(find.textContaining('waiting for your cosigner to be updated'), findsOneWidget);
    expect(find.byKey(const Key('security-advice')), findsOneWidget);
    expect(find.text('A new household key is strongly recommended'), findsOneWidget);
    expect(find.byKey(const Key('security-advice-avoid')), findsNothing);
    await t.ensureVisible(find.byKey(const Key('open-security-advice')));
    await t.tap(find.byKey(const Key('open-security-advice')));
    await t.pump();
    await settle(t);
    expect(find.textContaining('We strongly recommend a new household key.'), findsOneWidget);
    await t.ensureVisible(find.byKey(const Key('report-lost')));
    await t.tap(find.byKey(const Key('report-lost')));
    await t.pump();
    await settle(t);
    await t.tap(find.text('Yes'));
    await t.pump();
    await settle(t);
    expect(File('${agent.dir.path}/reported').readAsStringSync().trim(), 'lost');
    expect((await agent.argsLog.readAsString()).contains('device security-advice ${agent.dir.path}/dev --report lost'), isTrue);
  });

  testWidgets('no rollover once a device was reported lost', (t) async {
    File('${agent.dir.path}/rotation').writeAsStringSync('strongly-recommended');
    File('${agent.dir.path}/rollover').writeAsStringSync('avoid');
    await start(t);
    expect(find.byKey(const Key('security-advice-avoid')), findsOneWidget);
  });
}
