import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// The Android app trusts a browser's reported page only when the browser is
// signed by a key on this list (SPEC 22.6 item 2). A debug or userdebug key
// (the AOSP test key, a debug keystore) is one anyone can sign with, so the
// shipped list holds release keys only; AutofillCore.privilegedBrowser also
// skips any other entry.
void main() {
  test('the shipped privileged-browser list holds release signatures only', () {
    final f = File('android/app/src/main/assets/privileged_browsers.json');
    final apps = (jsonDecode(f.readAsStringSync()) as Map)['apps'] as List;
    expect(apps, isNotEmpty);
    for (final a in apps) {
      final info = (a as Map)['info'] as Map;
      final sigs = info['signatures'] as List;
      expect(sigs, isNotEmpty, reason: '${info['package_name']}');
      for (final s in sigs) {
        expect((s as Map)['build'], 'release', reason: '${info['package_name']}');
      }
    }
  });
}
