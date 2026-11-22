// 1Password on Linux, through 1Password's own command-line tool (`op`):
// with the desktop app's CLI integration on, `op` asks the person to
// unlock 1Password and then reads their items. Symbolon hands what it
// reads to the agent on standard input (never through a file).

import 'dart:convert';
import 'dart:io';

/// Why 1Password cannot be read now, for the person; null when it can.
class OpProblem implements Exception {
  final String message;
  const OpProblem(this.message);
  @override
  String toString() => message;
}

/// Every item of every vault the person can read, as one line of JSON: an
/// array of `op item get --reveal --format json` objects. Throws
/// [OpProblem] when `op` is missing or not signed in.
Future<String> readOnePassword({String op = 'op'}) async {
  final ProcessResult who;
  try {
    who = await Process.run(op, ['whoami', '--format', 'json']);
  } on ProcessException {
    throw const OpProblem('The 1Password command-line tool (op) is not installed. Install it from 1Password, then try again.');
  }
  if (who.exitCode != 0) {
    throw const OpProblem('1Password is not signed in for its command-line tool. In the 1Password app: Settings › Developer › '
        '"Integrate with 1Password CLI", then try again (1Password will ask you to unlock it).');
  }
  final list = await Process.run(op, ['item', 'list', '--format', 'json']);
  if (list.exitCode != 0) throw OpProblem('1Password did not list your items: ${(list.stderr as String).trim()}');
  final ids = (jsonDecode(list.stdout as String) as List).cast<Map<String, dynamic>>();
  if (ids.isEmpty) return '[]';
  // `op item get -` takes the listing on standard input and writes each
  // item in full, one JSON object after another.
  final p = await Process.start(op, ['item', 'get', '-', '--reveal', '--format', 'json']);
  p.stdin.write(list.stdout as String);
  await p.stdin.close();
  final out = await p.stdout.transform(utf8.decoder).join();
  final err = await p.stderr.transform(utf8.decoder).join();
  if (await p.exitCode != 0) throw OpProblem('1Password did not give the items: ${err.trim()}');
  return jsonEncode(splitObjects(out));
}

/// The JSON objects written one after another in [s] (outside strings,
/// each runs from a top-level "{" to its matching "}").
List<Object?> splitObjects(String s) {
  final out = <Object?>[];
  var depth = 0, start = -1;
  var inStr = false, esc = false;
  for (var i = 0; i < s.length; i++) {
    final c = s[i];
    if (inStr) {
      if (esc) {
        esc = false;
      } else if (c == '\\') {
        esc = true;
      } else if (c == '"') {
        inStr = false;
      }
      continue;
    }
    if (c == '"') {
      inStr = true;
    } else if (c == '{') {
      if (depth == 0) start = i;
      depth++;
    } else if (c == '}') {
      depth--;
      if (depth == 0 && start >= 0) {
        out.add(jsonDecode(s.substring(start, i + 1)));
        start = -1;
      }
    }
  }
  return out;
}
