import 'package:material_ui/material_ui.dart';

import '../app.dart';
import '../cli.dart';
import '../widgets.dart';

/// What to do after the fix to the signing software (the Paillier nonce
/// fix, SPEC 6.2.2): `device security-advice`, one plain sentence per line.
/// The words come from the agent on this device, worked out from the
/// verified identity log and this device's own files: the relay writes none
/// of them. Two buttons tell the device what only the person knows: a
/// device was lost or stolen, or the cosigner's operator reported a
/// security incident. Either only makes the advice stricter.
class SecurityAdvicePage extends StatefulWidget {
  final App app;
  const SecurityAdvicePage({super.key, required this.app});

  @override
  State<SecurityAdvicePage> createState() => _SecurityAdvicePageState();
}

class _SecurityAdvicePageState extends State<SecurityAdvicePage> {
  CliResult? result;

  @override
  void initState() {
    super.initState();
    load();
  }

  Future<void> load() async {
    final r = await widget.app.cli.securityAdvice(widget.app.dir);
    if (mounted) setState(() => result = r);
  }

  Future<void> report(String kind, String question) async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Are you sure?'),
        content: Text(question),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Yes')),
        ],
      ),
    );
    if (yes != true || !mounted) return;
    await widget.app.cli.securityReport(widget.app.dir, kind);
    await load();
  }

  @override
  Widget build(BuildContext context) {
    final r = result;
    return Scaffold(
      appBar: AppBar(title: const Text('After the security fix')),
      body: r == null
          ? const Center(child: CircularProgressIndicator())
          : PageBody(children: [
              if (!r.ok) Text(friendlyError(r), style: const TextStyle(color: Colors.red)),
              for (final l in r.lines) Padding(padding: const EdgeInsets.only(bottom: 12), child: Text(l)),
              const SizedBox(height: 8),
              Section('Tell Symbolon what happened', subtitle: 'Only if it is true: the advice above then gets stricter.', children: [
                WideButton('A device of mine was lost or stolen', key: const Key('report-lost'), tonal: true, icon: Icons.phonelink_erase,
                    onPressed: () => report('lost', 'One of your devices was lost or stolen (or you do not know where it is)?')),
                const SizedBox(height: 8),
                WideButton('My cosigner reported a security problem', key: const Key('report-cosigner'), tonal: true, icon: Icons.report,
                    onPressed: () => report('cosigner', 'Whoever runs your cosigner told you about a security incident?')),
              ]),
            ]),
    );
  }
}

/// The home page's card for the advice: a title and a few short sentences.
(String, String) adviceSummary(String level) => switch (level) {
      'compromised' => (
          'Your household key may be known to someone else',
          'A check of your recent messages found a problem. Treat your household key as known to someone else, and make a new one now.'
        ),
      'unknown' => (
          'Symbolon could not check your household key',
          'Until it can, follow the stricter advice: a new household key is strongly recommended.'
        ),
      'strongly-recommended' => (
          'A new household key is strongly recommended',
          'An older version of Symbolon had a flaw that could, in rare cases, reveal your household key. We strongly recommend a new one.'
        ),
      _ => (
          'A new household key is recommended',
          'An older version of Symbolon had a flaw that could, in rare cases, reveal your household key. We recommend a new one.'
        ),
    };

/// The home page's words for the key refresh that is still to run.
String refreshSummary(String state) => switch (state) {
      'waiting-cosigner' =>
        'The key refresh is waiting for your cosigner to be updated. Whoever runs your cosigner (your Symbolon Home box, or your provider) must install the update first; then finish the update here again.',
      'waiting-device' => 'The key refresh is waiting for another of your devices to be updated. Update Symbolon on each of your devices, then finish the update here again.',
      _ => 'Symbolon needs to refresh your household\'s keys once after a fix to its signing software. It takes your PIN and a few minutes with your cosigner. '
          'If you have other devices, finish the update on each of them at the same time.',
    };
