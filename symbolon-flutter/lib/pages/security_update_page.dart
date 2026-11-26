import 'package:material_ui/material_ui.dart';

import '../app.dart';
import '../widgets.dart';

/// The security update (D-4, SPEC 9.2): the PIN, then the duress PIN if the
/// person has one. The duress profile gets a transport key of its own, so
/// the duress PIN no longer opens shared folders, and the device moves to a
/// new key, published in the identity log. The home page offers it while
/// `device status` says it is due, which it says alike under either PIN.
class SecurityUpdatePage extends StatefulWidget {
  final App app;
  const SecurityUpdatePage({super.key, required this.app});

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
        usually: 'under a minute');
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
          const Text('Your duress PIN shows only what you chose for it. On devices set up before this update it also held a key that '
              'opens your shared folders. The update gives the duress PIN a key of its own and gives this device a new one.'),
          const SizedBox(height: 16),
          Field(pin, 'PIN', obscure: true, numeric: true, fieldKey: const Key('su-pin'), check: (s) => s.isEmpty ? 'Your PIN' : null),
          SwitchListTile(
            key: const Key('su-has-duress'),
            contentPadding: EdgeInsets.zero,
            title: const Text('I have a duress PIN on this device'),
            value: hasDuress,
            onChanged: (x) => setState(() => hasDuress = x),
          ),
          if (hasDuress)
            Field(duressPin, 'Duress PIN', obscure: true, numeric: true, fieldKey: const Key('su-duress-pin'),
                check: (s) => s.isEmpty ? 'Your duress PIN' : (s == pin.text ? 'Must differ from your PIN' : null)),
          if (!hasDuress)
            const Text('Without a duress PIN, any duress PIN this device had stops working.'),
          const SizedBox(height: 16),
          WideButton('Update', key: const Key('su-run'), icon: Icons.security_update_good, onPressed: run),
        ]),
      ),
    );
  }
}
