import 'package:flutter/material.dart';

/// How Symbolon works, in a few pages: shown on first start, skippable, and
/// again from More › How Symbolon works.
class TutorialPage extends StatefulWidget {
  const TutorialPage({super.key});

  @override
  State<TutorialPage> createState() => _TutorialPageState();
}

class _TutorialPageState extends State<TutorialPage> {
  final pages = PageController();
  int at = 0;

  static const steps = [
    (Icons.fingerprint, 'Welcome to Symbolon',
        'Symbolon keeps your identity, your passkeys and your passwords safe, without trusting any single device or company with your keys.'),
    (Icons.call_split, 'Your key is split',
        'Your signing key never exists in one place. This device holds one share and a cosigner holds another, and both must take part '
            'to sign. A stolen phone cannot sign alone, and neither can a hacked cosigner.'),
    (Icons.visibility, 'Witnesses keep watch',
        'Every change to your identity, such as adding a device or recovering, goes into a log that independent witnesses countersign. '
            'Nobody can quietly swap your keys.'),
    (Icons.pin, 'Your PIN unlocks this device',
        'Enter your PIN once and the app stays unlocked for a while (More › Settings › Stay unlocked). It locks when you leave the app '
            'or tap the lock icon.'),
    (Icons.key, 'Passkeys and the vault',
        'Passkeys sign you in to sites without a password. The vault keeps logins and secrets, encrypted on this device; the relay keeps '
            'a copy it cannot read. Symbolon can even change a login\'s password for you.'),
    (Icons.healing, 'If things go wrong',
        'Setup gives you a recovery kit: write it down, and you can get your identity back even if you lose every device. A duress PIN '
            'opens a harmless view if someone forces you to unlock.'),
  ];

  @override
  void dispose() {
    pages.dispose();
    super.dispose();
  }

  void done() => Navigator.of(context).pop();

  @override
  Widget build(BuildContext context) {
    final t = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;
    final last = at == steps.length - 1;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 560),
            child: Column(children: [
              Align(
                alignment: Alignment.centerRight,
                child: TextButton(key: const Key('tutorial-skip'), onPressed: done, child: Text(last ? 'Close' : 'Skip')),
              ),
              Expanded(
                child: PageView(
                  controller: pages,
                  onPageChanged: (i) => setState(() => at = i),
                  children: [
                    for (final s in steps)
                      SingleChildScrollView(
                        padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 24),
                        child: Column(children: [
                          CircleAvatar(radius: 56, backgroundColor: cs.primaryContainer, child: Icon(s.$1, size: 56, color: cs.onPrimaryContainer)),
                          const SizedBox(height: 32),
                          Text(s.$2, style: t.headlineSmall, textAlign: TextAlign.center),
                          const SizedBox(height: 16),
                          Text(s.$3, style: t.bodyLarge, textAlign: TextAlign.center),
                        ]),
                      ),
                  ],
                ),
              ),
              Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                for (var i = 0; i < steps.length; i++)
                  AnimatedContainer(
                    duration: const Duration(milliseconds: 200),
                    margin: const EdgeInsets.all(4),
                    width: i == at ? 20 : 8,
                    height: 8,
                    decoration: BoxDecoration(color: i == at ? cs.primary : cs.outlineVariant, borderRadius: BorderRadius.circular(4)),
                  ),
              ]),
              Padding(
                padding: const EdgeInsets.fromLTRB(24, 16, 24, 24),
                child: Row(children: [
                  if (at > 0)
                    TextButton(
                      onPressed: () => pages.previousPage(duration: const Duration(milliseconds: 250), curve: Curves.easeOut),
                      child: const Text('Back'),
                    ),
                  const Spacer(),
                  FilledButton(
                    key: const Key('tutorial-next'),
                    onPressed: last ? done : () => pages.nextPage(duration: const Duration(milliseconds: 250), curve: Curves.easeOut),
                    child: Text(last ? 'Get started' : 'Next'),
                  ),
                ]),
              ),
            ]),
          ),
        ),
      ),
    );
  }
}
