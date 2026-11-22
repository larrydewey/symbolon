import 'dart:io';

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import '../app.dart';
import '../cli.dart';
import '../session.dart';
import '../widgets.dart';

/// Duress alerts (SPEC 14.4): who is told when this identity is unlocked
/// with the duress PIN, and how. The settings live on the cosigner (your
/// Symbolon Home box), which sends the alerts: the phone under duress sends
/// nothing that looks different. Under the duress PIN this page shows no
/// contacts and cannot change them.
class AlertsPage extends StatefulWidget {
  final App app;
  const AlertsPage({super.key, required this.app});

  @override
  State<AlertsPage> createState() => _AlertsPageState();
}

class _AlertsPageState extends State<AlertsPage> with ClosesOnLock {
  App get app => widget.app;
  @override
  PinSession get lockingSession => app.session;

  AlertSettings? settings;
  String myParty = '';
  final person = TextEditingController();
  List<AlertContact> contacts = [];
  static const _ch = MethodChannel('symbolon/platform');

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => load());
  }

  @override
  void dispose() {
    person.dispose();
    super.dispose();
  }

  Future<void> load() async {
    final st = await app.cli.status(app.dir);
    myParty = DeviceStatus.parse(st)?.party ?? '';
    if (!mounted) return;
    final r = await app.withPin(context, (p) => runTask(context, 'Asking your Symbolon Home box', () => app.cli.alerts(app.dir, p), usually: 'a few seconds'),
        note: 'Unlock to see your duress alerts.');
    if (r == null || !mounted) return;
    final s = AlertSettings.parse(r);
    if (s == null) return;
    setState(() {
      settings = s;
      person.text = s.person;
      contacts = [...s.contacts];
    });
  }

  Future<void> save() async {
    if (Platform.isAndroid) {
      // The alert carries the phone's last known location: asked for here,
      // once, never at the moment of an unlock.
      try {
        await _ch.invokeMethod<bool>('askLocation');
      } on PlatformException {
        // Without it the alert says "location unknown".
      }
    }
    if (!mounted) return;
    final r = await app.withPin(
        context, (p) => runTask(context, 'Saving your duress alerts', () => app.cli.alertsSet(app.dir, person.text.trim(), contacts, p), usually: 'a few seconds'),
        note: 'Unlock to change your duress alerts.');
    if (r == null || !r.ok || !mounted) return;
    final s = AlertSettings.parse(r);
    setState(() {
      settings = s ?? settings;
      contacts = [...?s?.contacts];
    });
    toast(context, 'Saved');
  }

  Future<void> endDuress() async {
    final r = await app.withPin(context, (p) => runTask(context, 'Ending the duress alert', () => app.cli.duressEnd(app.dir, p), usually: 'a few seconds'),
        note: 'Your real PIN, on this device, to say you are safe.');
    if (r == null || !r.ok || !mounted) return;
    toast(context, 'Ended. Your contacts are told you are safe.');
    await load();
  }

  Future<void> registerHere() async {
    final r = await app.withPin(context, (p) => runTask(context, 'Setting up household alerts', () => app.cli.alertsRegister(app.dir, p), usually: 'a few seconds'),
        note: 'Unlock to receive household alerts on this device.');
    if (r == null || !r.ok || !mounted) return;
    if (Platform.isAndroid) {
      try {
        await _ch.invokeMethod<bool>('watchAlerts', app.dir);
      } on PlatformException {
        // Checked whenever the app opens, then.
      }
    }
    if (mounted) toast(context, 'This device will show household members\' duress alerts.');
  }

  Future<void> edit([int? i]) async {
    final c = await showDialog<AlertContact>(context: context, builder: (_) => _ContactDialog(contact: i == null ? null : contacts[i]));
    if (c == null) return;
    setState(() {
      if (i == null) {
        contacts = [...contacts, c];
      } else {
        contacts = [...contacts]..[i] = c;
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final s = settings;
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Duress alerts')),
      body: PageBody(children: [
        if (s != null && s.duress)
          Card(
            key: const Key('duress-open'),
            color: Theme.of(context).colorScheme.errorContainer,
            margin: const EdgeInsets.only(bottom: 16),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                Text('A duress alert is open', style: t.titleMedium),
                const SizedBox(height: 4),
                Text(s.party == myParty
                    ? 'This device opened it. End it from another of your devices once you are safe.'
                    : 'Since ${DateTime.fromMillisecondsSinceEpoch(s.startedAt * 1000).toLocal().toString().substring(0, 16)}. Your contacts were told.'),
                if (s.party != myParty) ...[
                  const SizedBox(height: 12),
                  WideButton('I\'m safe: end the alert', key: const Key('end-duress'), icon: Icons.check_circle_outline, onPressed: endDuress),
                ],
              ]),
            ),
          ),
        Section('How it works', children: const [
          Text('When you unlock Symbolon with your duress PIN, your Symbolon Home box tells the people below, with the time and your '
              'phone\'s last known location. This phone shows and sends nothing different. When the duress window ends, or you end it '
              'from another device, they are told you are safe.'),
        ]),
        if (s == null)
          WideButton('Load', key: const Key('alerts-load'), tonal: true, onPressed: load)
        else ...[
          Section('Your name in alerts', children: [
            Field(person, 'Name', fieldKey: const Key('alerts-person'), hint: 'Larry', action: TextInputAction.done),
          ]),
          Section('Who is told',
              trailing: IconButton(key: const Key('add-contact'), icon: const Icon(Icons.person_add_alt), tooltip: 'Add someone', onPressed: () => edit()),
              children: [
                if (contacts.isEmpty) const Text('No one yet.'),
                for (var i = 0; i < contacts.length; i++)
                  ListTile(
                    key: Key('contact-$i'),
                    contentPadding: EdgeInsets.zero,
                    title: Text(contacts[i].name),
                    subtitle: Text([
                      contacts[i].summary,
                      if (contacts[i].ntfy && contacts[i].topic.isNotEmpty) 'ntfy topic ${contacts[i].topic}',
                    ].where((x) => x.isNotEmpty).join('\n')),
                    isThreeLine: contacts[i].ntfy && contacts[i].topic.isNotEmpty,
                    onTap: () => edit(i),
                    trailing: Row(mainAxisSize: MainAxisSize.min, children: [
                      if (contacts[i].ntfy && contacts[i].topic.isNotEmpty)
                        IconButton(icon: const Icon(Icons.copy), tooltip: 'Copy the ntfy topic', onPressed: () => copyText(context, 'ntfy topic', contacts[i].topic)),
                      IconButton(
                          icon: const Icon(Icons.delete_outline),
                          tooltip: 'Remove',
                          onPressed: () => setState(() {
                                contacts = [...contacts]..removeAt(i);
                              })),
                    ]),
                  ),
                if (contacts.any((c) => c.ntfy))
                  Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: Text('Each ntfy contact subscribes to their topic on your box\'s ntfy server, in the ntfy app. The topic appears '
                        'after saving.', style: t.bodySmall),
                  ),
              ]),
          WideButton('Save', key: const Key('alerts-save'), onPressed: save),
          const SizedBox(height: 16),
          Section('Household alerts on this device', children: [
            const Text('Shows a notification when someone in your household, with an account on the same Symbolon Home box, unlocks with '
                'their duress PIN and names you.'),
            const SizedBox(height: 12),
            WideButton('Receive household alerts here', key: const Key('alerts-register'), tonal: true, onPressed: registerHere),
          ]),
        ],
      ]),
    );
  }
}

class _ContactDialog extends StatefulWidget {
  final AlertContact? contact;
  const _ContactDialog({this.contact});

  @override
  State<_ContactDialog> createState() => _ContactDialogState();
}

class _ContactDialogState extends State<_ContactDialog> {
  late final name = TextEditingController(text: widget.contact?.name ?? '');
  late final email = TextEditingController(text: widget.contact?.email ?? '');
  late final phone = TextEditingController(text: widget.contact?.phone ?? '');
  late final household = TextEditingController(text: widget.contact?.household ?? '');
  late final threnody = TextEditingController(text: widget.contact?.threnody ?? '');
  late bool ntfy = widget.contact?.ntfy ?? true;
  String? problem;

  @override
  void dispose() {
    for (final c in [name, email, phone, household, threnody]) {
      c.dispose();
    }
    super.dispose();
  }

  void done() {
    final n = name.text.trim();
    final e = email.text.trim();
    final p = phone.text.trim().replaceAll(' ', '');
    final h = household.text.trim().toLowerCase();
    final th = threnody.text.trim().replaceAll(' ', '');
    String? why;
    if (n.isEmpty) why = 'A name is needed.';
    if (why == null && e.isNotEmpty && !RegExp(r'^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$').hasMatch(e)) why = 'That email address does not look right.';
    if (why == null && p.isNotEmpty && !RegExp(r'^\+[0-9]{6,15}$').hasMatch(p)) why = 'Phone numbers start with + and the country code.';
    if (why == null && h.isNotEmpty && !RegExp(r'^[a-z0-9][a-z0-9-]{0,31}$').hasMatch(h)) why = 'The household name is their name on the box (letters, digits, -).';
    if (why == null && th.isNotEmpty && !RegExp(r'^[0-9A-Za-z]{8,128}$').hasMatch(th)) why = 'A Threnody fingerprint is letters and digits.';
    if (why == null && !ntfy && e.isEmpty && p.isEmpty && h.isEmpty && th.isEmpty) why = 'Choose at least one way to tell them.';
    if (why != null) {
      setState(() => problem = why);
      return;
    }
    Navigator.of(context).pop(AlertContact(name: n, ntfy: ntfy, email: e, phone: p, household: h, threnody: th, topic: widget.contact?.topic ?? ''));
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(widget.contact == null ? 'Add someone' : 'Edit'),
      content: SingleChildScrollView(
        child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Field(name, 'Name', fieldKey: const Key('contact-name')),
          SwitchListTile(
              key: const Key('contact-ntfy'),
              contentPadding: EdgeInsets.zero,
              title: const Text('ntfy notification'),
              subtitle: const Text('Through your box\'s ntfy server'),
              value: ntfy,
              onChanged: (x) => setState(() => ntfy = x)),
          Field(email, 'Email', fieldKey: const Key('contact-email'), hint: 'ann@example.com'),
          Field(phone, 'Text message', fieldKey: const Key('contact-phone'), hint: '+15551234567'),
          Field(household, 'Their Symbolon (household name)', fieldKey: const Key('contact-household'), helper: 'Their name on your Symbolon Home box'),
          Field(threnody, 'Threnody fingerprint', fieldKey: const Key('contact-threnody'), action: TextInputAction.done),
          if (problem != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(problem!, style: TextStyle(color: Theme.of(context).colorScheme.error))),
        ]),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.of(context).pop(), child: const Text('Cancel')),
        FilledButton(key: const Key('contact-done'), onPressed: done, child: const Text('Done')),
      ],
    );
  }
}
