// 1Password through its CLI: the objects `op item get -` writes one after
// another are split correctly (braces inside strings included), and a fake
// `op` shows the calls and the problems the person is told about.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/onepassword.dart';

void main() {
  test('objects written one after another', () {
    final xs = splitObjects('{"a": "x}{y", "n": {"b": 1}}\n{"c": "q\\"}"}\n');
    expect(xs, [
      {'a': 'x}{y', 'n': {'b': 1}},
      {'c': 'q"}'},
    ]);
  });

  late Directory d;
  setUp(() async => d = await Directory.systemTemp.createTemp('fake-op'));
  tearDown(() => d.delete(recursive: true));

  Future<String> fakeOp(String script) async {
    final f = File('${d.path}/op');
    await f.writeAsString('#!/bin/bash\necho "\$*" >> "${d.path}/calls"\n$script\n');
    await Process.run('chmod', ['+x', f.path]);
    return f.path;
  }

  test('reads every item through op', () async {
    final op = await fakeOp(r'''
case "$1 $2" in
  "whoami --format") echo '{"url":"my.1password.com"}' ;;
  "item list") echo '[{"id":"a1"},{"id":"a2"}]' ;;
  "item get") cat > /dev/null; printf '{"id":"a1","title":"one"}\n{"id":"a2","title":"two {x}"}\n' ;;
esac''');
    final line = await readOnePassword(op: op);
    expect(jsonDecode(line), [
      {'id': 'a1', 'title': 'one'},
      {'id': 'a2', 'title': 'two {x}'},
    ]);
    expect(line.contains('\n'), isFalse);
    final calls = await File('${d.path}/calls').readAsString();
    expect(calls, contains('item get - --reveal --format json'));
  });

  test('says how to sign in when op is not signed in', () async {
    final op = await fakeOp('exit 1');
    expect(() => readOnePassword(op: op), throwsA(isA<OpProblem>().having((e) => e.message, 'message', contains('Integrate with 1Password CLI'))));
  });

  test('says op is missing', () async {
    expect(() => readOnePassword(op: '${d.path}/no-such-op'), throwsA(isA<OpProblem>().having((e) => e.message, 'message', contains('not installed'))));
  });
}
