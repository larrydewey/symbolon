// Shared pieces: the PIN prompt, the progress sheet for long operations,
// plain-language errors, and display of long hex values.

import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'cli.dart';

/// Asks for the PIN (or another secret) in a dialog. The text is obscured
/// and lives only in the dialog's controller; null when cancelled.
Future<String?> askSecret(BuildContext context, {String title = 'Enter your PIN', String label = 'PIN', String? note, bool numeric = true}) {
  final c = TextEditingController();
  return showDialog<String>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text(title),
      content: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
        if (note != null) Padding(padding: const EdgeInsets.only(bottom: 12), child: Text(note)),
        TextField(
          key: const Key('secret-field'),
          controller: c,
          obscureText: true,
          autofocus: true,
          keyboardType: numeric ? TextInputType.number : TextInputType.visiblePassword,
          autocorrect: false,
          enableSuggestions: false,
          enableIMEPersonalizedLearning: false,
          decoration: InputDecoration(labelText: label, border: const OutlineInputBorder()),
          onSubmitted: (v) => Navigator.of(ctx).pop(v),
        ),
      ]),
      actions: [
        TextButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Cancel')),
        FilledButton(key: const Key('secret-ok'), onPressed: () => Navigator.of(ctx).pop(c.text), child: const Text('OK')),
      ],
    ),
  );
}

/// What a failed run means, in words for the user.
String friendlyError(CliResult r) {
  final p = r.problem;
  final l = p.toLowerCase();
  if (l.contains('wrong pin')) return 'Wrong PIN.';
  if (r.code == 124 || l.contains('timed out')) return 'This took too long and was stopped. Check that this device can reach the relay and the cosigner, then try again.';
  if (l.contains('cosigner is unreachable') || l.contains('did not sign') || l.contains('cosigner did not')) {
    return 'The cosigner did not answer. It may be offline or refusing (for example during a duress window).';
  }
  if (l.contains('cannot connect') || l.contains('no log at the relay') || l.contains('relay refused')) return 'Cannot reach the relay. Check the network connection.';
  if (l.contains('no device answered the code')) return 'Your other device did not scan the code in time. Try again, with both devices on the same network.';
  if (l.contains('cannot reach the new device')) return 'Cannot reach the new device. Both devices must be on the same network, and its code still showing.';
  if (l.contains("did not answer with this code's key")) return "The device at that address did not show this code. Scan the new device's code again.";
  if (l.contains('not set up')) return 'This device is not set up yet: open Setup.';
  if (l.contains('not for this relying party')) return 'This passkey belongs to another site.';
  if (l.contains('no such item')) return 'There is no item with that name.';
  if (l.contains('cannot run')) return 'The Symbolon agent could not be started ($p).';
  return p.isEmpty ? 'Something went wrong (exit ${r.code}).' : '${p[0].toUpperCase()}${p.substring(1)}.';
}

/// Runs [op] behind a progress sheet that says what is happening, how long
/// it has run and how long it usually takes; shows a failure as a message.
Future<CliResult> runTask(BuildContext context, String title, Future<CliResult> Function() op, {String? detail, String? usually}) async {
  final messenger = ScaffoldMessenger.of(context);
  final nav = Navigator.of(context);
  showModalBottomSheet<void>(
    context: context,
    isDismissible: false,
    enableDrag: false,
    builder: (_) => PopScope(canPop: false, child: _Progress(title: title, detail: detail, usually: usually)),
  );
  final CliResult r;
  try {
    r = await op();
  } finally {
    nav.pop();
  }
  if (!r.ok) {
    messenger.showSnackBar(errorBar(friendlyError(r)));
  } else {
    HapticFeedback.lightImpact();
  }
  return r;
}

/// A snack bar for something that failed: an icon, and long enough to read.
SnackBar errorBar(String m) => SnackBar(
      content: Row(children: [const Icon(Icons.error_outline, color: Colors.white), const SizedBox(width: 12), Expanded(child: Text(m))]),
      backgroundColor: Colors.red.shade700,
      duration: const Duration(seconds: 6),
    );

class _Progress extends StatefulWidget {
  final String title;
  final String? detail;
  final String? usually;
  const _Progress({required this.title, this.detail, this.usually});

  @override
  State<_Progress> createState() => _ProgressState();
}

class _ProgressState extends State<_Progress> {
  // Started here, not lazily: a late field that only dispose() reads would
  // never start, and the count would stay at 0 s.
  late final Timer tick;
  int s = 0;

  @override
  void initState() {
    super.initState();
    tick = Timer.periodic(const Duration(seconds: 1), (_) => setState(() => s++));
  }

  @override
  void dispose() {
    tick.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(24, 24, 24, 32),
        child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(widget.title, style: t.titleLarge),
          if (widget.detail != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(widget.detail!, style: t.bodyMedium)),
          const SizedBox(height: 20),
          const LinearProgressIndicator(),
          const SizedBox(height: 12),
          Text('${s ~/ 60 > 0 ? '${s ~/ 60} min ' : ''}${s % 60} s${widget.usually == null ? '' : ' · usually ${widget.usually}'}', style: t.bodySmall),
        ]),
      ),
    );
  }
}

void toast(BuildContext context, String m) => ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(m)));

/// How long a copied secret stays on the clipboard.
const clipboardKeep = Duration(seconds: 60);
Timer? _clearClipboard;

/// Copies [value] and says so. A [secret] is marked sensitive (Android 13+
/// keeps it out of the clipboard preview and the keyboard's suggestions) and
/// is cleared after [clipboardKeep], unless something else was copied since.
Future<void> copyText(BuildContext context, String label, String value, {bool secret = false}) async {
  HapticFeedback.selectionClick();
  var marked = false;
  if (secret && Platform.isAndroid) {
    try {
      marked = await const MethodChannel('symbolon/platform').invokeMethod<bool>('copySensitive', value) ?? false;
    } on PlatformException {
      marked = false;
    } on MissingPluginException {
      marked = false;
    }
  }
  if (!marked) await Clipboard.setData(ClipboardData(text: value));
  if (!context.mounted) return;
  if (!secret) return toast(context, '$label copied');
  _clearClipboard?.cancel();
  // Not under flutter test, whose fake clock would see the timer outlive the test.
  if (!Platform.environment.containsKey('FLUTTER_TEST')) {
    _clearClipboard = Timer(clipboardKeep, () async {
      final now = await Clipboard.getData(Clipboard.kTextPlain);
      if (now?.text == value) await Clipboard.setData(const ClipboardData(text: ''));
    });
  }
  toast(context, '$label copied. It is cleared from the clipboard in a minute.');
}

/// A long hex value, shortened to its ends, with a copy button; tap it to
/// see all of it.
class HexValue extends StatelessWidget {
  final String label;
  final String value;
  final bool secret;
  const HexValue(this.label, this.value, {super.key, this.secret = false});

  static String short(String v) => v.length <= 20 ? v : '${v.substring(0, 8)}…${v.substring(v.length - 8)}';

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return InkWell(
      onTap: () => showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: Text(label),
          content: SelectableText(value, style: const TextStyle(fontFamily: 'monospace')),
          actions: [
            TextButton(onPressed: () => _copy(context), child: const Text('Copy')),
            FilledButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Close')),
          ],
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 6),
        child: Row(children: [
          Expanded(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(label, style: t.labelMedium),
              const SizedBox(height: 2),
              Text(secret ? '•' * 16 : short(value), style: const TextStyle(fontFamily: 'monospace'), overflow: TextOverflow.ellipsis),
            ]),
          ),
          IconButton(tooltip: 'Copy', icon: const Icon(Icons.copy, size: 20), onPressed: () => _copy(context)),
        ]),
      ),
    );
  }

  void _copy(BuildContext context) => copyText(context, label, value, secret: secret);
}

/// A card with a title.
class Section extends StatelessWidget {
  final String title;
  final String? subtitle;
  final List<Widget> children;
  final Widget? trailing;
  const Section(this.title, {super.key, this.subtitle, required this.children, this.trailing});

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    return Card(
      margin: const EdgeInsets.only(bottom: 16),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Row(children: [Expanded(child: Text(title, style: t.titleMedium)), ?trailing]),
          if (subtitle != null) Padding(padding: const EdgeInsets.only(top: 4), child: Text(subtitle!, style: t.bodySmall)),
          const SizedBox(height: 12),
          ...children,
        ]),
      ),
    );
  }
}

/// A text field with a border and a label. What is typed is kept exactly:
/// no autocorrection, suggestions, capitals, smart punctuation or spaces
/// added after a period (the keyboard is told this is not prose).
class Field extends StatelessWidget {
  final TextEditingController controller;
  final String label;
  final String? hint;
  final bool obscure;
  final bool numeric;
  final bool url;
  final Key? fieldKey;
  final TextInputAction action;
  final String? Function(String)? check;   // what is wrong with the text, checked as it is typed and by Form.validate
  const Field(this.controller, this.label,
      {super.key, this.hint, this.obscure = false, this.numeric = false, this.url = false, this.fieldKey, this.action = TextInputAction.next, this.check});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextFormField(
        key: fieldKey,
        controller: controller,
        obscureText: obscure,
        textInputAction: action,
        autovalidateMode: AutovalidateMode.onUserInteraction,
        validator: check == null ? null : (v) => check!(v ?? ''),
        // Keyboards such as Gboard add spaces and capitals to ordinary text
        // even without suggestions; a URL or visible-password field gets none.
        keyboardType: numeric ? TextInputType.number : (url ? TextInputType.url : TextInputType.visiblePassword),
        autocorrect: false,
        enableSuggestions: false,
        enableIMEPersonalizedLearning: false,
        textCapitalization: TextCapitalization.none,
        smartDashesType: SmartDashesType.disabled,
        smartQuotesType: SmartQuotesType.disabled,
        decoration: InputDecoration(labelText: label, hintText: hint, border: const OutlineInputBorder()),
      ),
    );
  }
}

/// A search box with filter chips under it, for a list.
class FilterBar extends StatelessWidget {
  final TextEditingController query;
  final String hint;
  final List<String> filters;          // the first one shows everything
  final int selected;
  final ValueChanged<int> onSelected;
  const FilterBar({super.key, required this.query, required this.hint, this.filters = const [], this.selected = 0, required this.onSelected});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        ValueListenableBuilder(
          valueListenable: query,
          builder: (context, v, _) => TextField(
            key: const Key('search'),
            controller: query,
            keyboardType: TextInputType.visiblePassword,
            autocorrect: false,
            enableSuggestions: false,
            textInputAction: TextInputAction.search,
            decoration: InputDecoration(
              hintText: hint,
              prefixIcon: const Icon(Icons.search),
              suffixIcon: v.text.isEmpty ? null : IconButton(tooltip: 'Clear', icon: const Icon(Icons.close), onPressed: query.clear),
              border: const OutlineInputBorder(borderRadius: BorderRadius.all(Radius.circular(28))),
              contentPadding: const EdgeInsets.symmetric(horizontal: 16),
            ),
          ),
        ),
        if (filters.isNotEmpty) ...[
          const SizedBox(height: 8),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(children: [
              for (var i = 0; i < filters.length; i++)
                Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: ChoiceChip(key: Key('filter-${filters[i]}'), label: Text(filters[i]), selected: selected == i, onSelected: (_) => onSelected(i)),
                ),
            ]),
          ),
        ],
      ]),
    );
  }
}

/// A small coloured label naming what kind of thing a row is.
class KindTag extends StatelessWidget {
  final String text;
  final Color color;
  const KindTag(this.text, this.color, {super.key});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(color: color.withValues(alpha: 0.15), borderRadius: BorderRadius.circular(8)),
      child: Text(text, style: Theme.of(context).textTheme.labelSmall?.copyWith(color: color, fontWeight: FontWeight.w600)),
    );
  }
}

/// A page body: scrolls, keeps clear of the keyboard and the system bars,
/// and stays readable on wide screens.
class PageBody extends StatelessWidget {
  final List<Widget> children;
  const PageBody({super.key, required this.children});

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Align(
        alignment: Alignment.topCenter,
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 720),
          child: ListView(
            keyboardDismissBehavior: ScrollViewKeyboardDismissBehavior.onDrag,
            padding: EdgeInsets.fromLTRB(16, 16, 16, 24 + MediaQuery.viewInsetsOf(context).bottom),
            children: children,
          ),
        ),
      ),
    );
  }
}

/// A full-width primary button.
class WideButton extends StatelessWidget {
  final String label;
  final VoidCallback? onPressed;
  final IconData? icon;
  final bool tonal;
  const WideButton(this.label, {super.key, this.onPressed, this.icon, this.tonal = false});

  @override
  Widget build(BuildContext context) {
    final child = Padding(padding: const EdgeInsets.symmetric(vertical: 12), child: Text(label));
    final b = tonal
        ? (icon == null ? FilledButton.tonal(onPressed: onPressed, child: child) : FilledButton.tonalIcon(onPressed: onPressed, icon: Icon(icon), label: child))
        : (icon == null ? FilledButton(onPressed: onPressed, child: child) : FilledButton.icon(onPressed: onPressed, icon: Icon(icon), label: child));
    return SizedBox(width: double.infinity, child: b);
  }
}

/// Shows a result's text in a dialog.
Future<void> showOutput(BuildContext context, String title, String text) {
  return showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text(title),
      content: SingleChildScrollView(child: SelectableText(text)),
      actions: [FilledButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('Close'))],
    ),
  );
}
