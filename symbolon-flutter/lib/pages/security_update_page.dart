import 'package:material_ui/material_ui.dart';

import '../app.dart';
import '../widgets.dart';

/// The security update (D-4, SPEC 9.2): the PIN, then the duress PIN if the
/// person has one. The duress profile gets a transport key of its own, so
/// the duress PIN no longer opens shared folders, and the device moves to a
/// new key, published in the identity log. The home page offers it while
/// `device status` says it is due, which it says alike under either PIN.
///
/// The same command then refreshes the household's keys once after the
/// fix to the signing software (SPEC 6.2.2). With [refreshOnly] (the update
/// above ran already) only the PIN is asked: the duress PIN is not used.
class SecurityUpdatePage extends StatefulWidget {
  final App app;
  final bool refreshOnly;
  const SecurityUpdatePage({super.key, required this.app, this.refreshOnly = false});

  @override
  State<SecurityUpdatePage> createState() => _SecurityUpdatePageState();
}

class _SecurityUpdatePageState extends State<SecurityUpdatePage> {
  final form = GlobalKey<FormState>();
  final pin = TextEditingController();
  final duressPin = TextEditingController();
  bool hasDuress = false;

  @override
  void dispose() {
    pin.dispose();
    duressPin.dispose();
    super.dispose();
  }

  Future<void> run() async {
    if (!(form.currentState?.validate() ?? false)) return;
    final app = widget.app;
    final r = await runTask(context, 'Finishing the security update', () => app.cli.securityUpdate(app.dir, pin.text, hasDuress ? duressPin.text : ''),
        usually: widget.refreshOnly ? 'a few minutes' : 'a few minutes (keep your other devices at hand)');
    if (!mounted) return;
    if (r.ok) Navigator.of(context).pop(true);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Security update')),
      body: Form(
        key: form,
        child: PageBody(children: [
          if (widget.refreshOnly)
            const Text('A fix to the signing software needs your household\'s keys refreshed once, with your cosigner. It takes a few minutes. '
                'If you have other devices, open Symbolon on each and finish the update there too, at the same time: they take part.')
          else
            const Text('Your duress PIN shows only what you chose for it. On devices set up before this update it also held a key that '
                'opens your shared folders. The update gives the duress PIN a key of its own and gives this device a new one. '
                'Then it refreshes your household\'s keys once, with your cosigner.'),
          const SizedBox(height: 16),
          Field(pin, 'PIN', obscure: true, numeric: true, fieldKey: const Key('su-pin'), check: (s) => s.isEmpty ? 'Your PIN' : null),
          if (!widget.refreshOnly)
          SwitchListTile(
            key: const Key('su-has-duress'),
            contentPadding: EdgeInsets.zero,
            title: const Text('I have a duress PIN on this device'),
            value: hasDuress,
            onChanged: (x) => setState(() => hasDuress = x),
          ),
          if (hasDuress && !widget.refreshOnly)
            Field(duressPin, 'Duress PIN', obscure: true, numeric: true, fieldKey: const Key('su-duress-pin'),
                check: (s) => s.isEmpty ? 'Your duress PIN' : (s == pin.text ? 'Must differ from your PIN' : null)),
          if (!hasDuress && !widget.refreshOnly)
            const Text('Without a duress PIN, any duress PIN this device had stops working.'),
          const SizedBox(height: 16),
          WideButton('Update', key: const Key('su-run'), icon: Icons.security_update_good, onPressed: run),
        ]),
      ),
    );
  }
}
