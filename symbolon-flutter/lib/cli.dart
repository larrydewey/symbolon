// The bridge to the `symbolon` command-line agent. The UI holds no key
// material: every operation is one run of the binary, with PINs and secrets
// written to its standard input (never on the command line, where other
// processes could read them) and the result read from its output.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// Whether a kit as written (hex, any spacing) is a protected sheet: 68
/// bytes, version 1 (SPEC 13.2). A plain kit is its 32-byte seed.
bool kitIsProtected(String kit) {
  final k = kit.replaceAll(RegExp(r'[\s-]'), '').toLowerCase();
  return k.length == 136 && k.startsWith('01');
}

/// The lines a new kit's passphrase takes on standard input: it and the
/// same again, or none (an empty line when [explicitNone]: something
/// follows, or the agent would read on).
List<String> newKitPassLines(String pass, {bool explicitNone = false}) => pass.isEmpty ? [if (explicitNone) ''] : [pass, pass];

String _hex(String s) => utf8.encode(s).map((b) => b.toRadixString(16).padLeft(2, '0')).join();

class CliResult {
  final int code;
  final String out;
  final String err;
  const CliResult(this.code, this.out, this.err);

  bool get ok => code == 0;

  /// The lines of standard output, without empty ones.
  List<String> get lines => out.split('\n').where((l) => l.trim().isNotEmpty).toList();

  /// The value after `key ` on the first output line that starts with it.
  String? field(String key) {
    for (final l in lines) {
      if (l.startsWith('$key ')) return l.substring(key.length + 1).trim();
    }
    return null;
  }

  /// Why the vault came from this device's copy rather than the relay
  /// (offline, or the relay's copy did not verify); null when it did not.
  String? get localCopy {
    for (final l in err.split('\n')) {
      final i = l.indexOf('local copy: ');
      if (i >= 0) return l.substring(i + 12).split(';').first.trim();
    }
    return null;
  }

  /// What went wrong, for a message to the user: the agent's last error
  /// line without its "device: " prefix.
  String get problem {
    final ls = err.split('\n').where((l) => l.trim().isNotEmpty).toList();
    if (ls.isEmpty) return code == 124 ? 'timed out' : 'failed (exit $code)';
    final last = ls.last.trim();
    for (final p in ['device: ', 'cosigner: ', 'relay: ', 'witness: ']) {
      if (last.startsWith(p)) return last.substring(p.length);
    }
    return last;
  }
}

/// A run of the agent kept open for a conversation, one line each way
/// (signing in to another password manager: the server may ask for a code
/// partway through). Secrets go to its standard input only.
class AgentConversation {
  final Process _p;
  final StreamIterator<String> _out;
  final StringBuffer _err = StringBuffer();
  AgentConversation._(this._p) : _out = StreamIterator(_p.stdout.transform(utf8.decoder).transform(const LineSplitter())) {
    _p.stderr.transform(utf8.decoder).listen(_err.write);
  }

  /// The next line the agent writes, or null when it has finished.
  Future<String?> next({Duration timeout = const Duration(minutes: 10)}) async {
    final more = await _out.moveNext().timeout(timeout, onTimeout: () {
      _p.kill();
      return false;
    });
    return more ? _out.current : null;
  }

  void send(String line) => _p.stdin.writeln(line);

  /// Ends the conversation: standard input closed, the agent waited for
  /// (killed after [grace]).
  Future<int> close({Duration grace = const Duration(seconds: 5)}) async {
    try {
      await _p.stdin.close();
    } catch (_) {}
    return _p.exitCode.timeout(grace, onTimeout: () {
      _p.kill();
      return 124;
    });
  }

  String get errors => _err.toString();
}

/// Runs the agent. [binary] is the path to `symbolon`.
class SymbolonCli {
  final String binary;
  final Map<String, String> env;      // added to the agent's environment (SYMBOLON_KEYSTORE on Android)
  const SymbolonCli(this.binary, {this.env = const {}});

  /// One run with [args]; [input] lines go to standard input, then it is
  /// closed. Long operations (key generation, re-share) take minutes.
  Future<CliResult> run(List<String> args, {List<String> input = const [], Duration timeout = const Duration(minutes: 30)}) async {
    final Process p;
    try {
      p = await Process.start(binary, args, environment: env);
    } on ProcessException catch (e) {
      return CliResult(127, '', 'cannot run $binary: ${e.message}');
    }
    final out = p.stdout.transform(utf8.decoder).join();
    final err = p.stderr.transform(utf8.decoder).join();
    for (final l in input) {
      p.stdin.writeln(l);
    }
    await p.stdin.close();
    final code = await p.exitCode.timeout(timeout, onTimeout: () {
      p.kill();
      return 124;
    });
    // A killed run's children may hold its pipes open: do not wait on them.
    const grace = Duration(seconds: 2);
    return CliResult(code, await out.timeout(grace, onTimeout: () => ''), await err.timeout(grace, onTimeout: () => ''));
  }

  /// As [run], with each line of standard output and standard error passed
  /// to [onLine] as it comes (a long command that reports as it goes).
  Future<CliResult> runLive(List<String> args, void Function(String line) onLine,
      {List<String> input = const [], Duration timeout = const Duration(minutes: 30)}) async {
    final Process p;
    try {
      p = await Process.start(binary, args, environment: env);
    } on ProcessException catch (e) {
      return CliResult(127, '', 'cannot run $binary: ${e.message}');
    }
    final out = StringBuffer(), err = StringBuffer();
    final o = p.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen((l) {
      out.writeln(l);
      onLine(l);
    }).asFuture<void>();
    final e = p.stderr.transform(utf8.decoder).transform(const LineSplitter()).listen((l) {
      err.writeln(l);
      onLine(l);
    }).asFuture<void>();
    for (final l in input) {
      p.stdin.writeln(l);
    }
    await p.stdin.close();
    final code = await p.exitCode.timeout(timeout, onTimeout: () {
      p.kill();
      return 124;
    });
    const grace = Duration(seconds: 2);
    await o.timeout(grace, onTimeout: () {});
    await e.timeout(grace, onTimeout: () {});
    return CliResult(code, out.toString(), err.toString());
  }

  // ─── Adding a device by QR code (SPEC 11.5) ─────────────────────────

  /// On a new device: makes it and joins the identity of the device that
  /// scans its code. The "link symbolon://link?..." line comes first: the
  /// QR's content; [hosts] are this device's network addresses in it.
  Future<CliResult> linkNew(String dir, List<String> hosts, String pin, String duressPin, void Function(String line) onLine,
          {bool unprotected = false, bool keystore = false}) =>
      runLive(['device', 'link-new', dir, if (hosts.isNotEmpty) ...['--host', hosts.join(',')], if (unprotected) '--unprotected', if (keystore && !unprotected) '--keystore'],
          onLine, input: [pin, duressPin], timeout: const Duration(minutes: 40));

  /// On a device with the identity: adds the device whose code [link] is.
  /// The link (it carries the code's secret) and the PIN go to standard
  /// input, never the command line. Once the two devices have met, the agent
  /// prints "fingerprint F", the new device's keys as both devices show
  /// them; [confirm] asks the person whether the new device shows the same,
  /// and only a yes lets the agent enrol it (SPEC 11.1 step 2, 11.5).
  Future<CliResult> linkAdd(String dir, String link, String pin, Future<bool> Function(String fingerprint) confirm) async {
    final Process p;
    try {
      p = await Process.start(binary, ['device', 'link-add', dir], environment: env);
    } on ProcessException catch (e) {
      return CliResult(127, '', 'cannot run $binary: ${e.message}');
    }
    final out = StringBuffer(), err = StringBuffer();
    var answered = false;
    Future<void> answer(bool yes) async {
      if (answered) return;
      answered = true;
      try {
        p.stdin.writeln(yes ? 'y' : 'n');
        await p.stdin.close();
      } catch (_) {}
    }
    final o = p.stdout.transform(utf8.decoder).transform(const LineSplitter()).listen((l) {
      out.writeln(l);
      if (l.startsWith('fingerprint ')) confirm(l.substring(12).trim()).then(answer, onError: (_) => answer(false));
    }).asFuture<void>();
    final e = p.stderr.transform(utf8.decoder).listen(err.write).asFuture<void>();
    p.stdin.writeln(link);
    p.stdin.writeln(pin);
    final code = await p.exitCode.timeout(const Duration(minutes: 30), onTimeout: () {
      p.kill();
      return 124;
    });
    await answer(false);
    const grace = Duration(seconds: 2);
    await o.timeout(grace, onTimeout: () {});
    await e.timeout(grace, onTimeout: () {});
    return CliResult(code, out.toString(), err.toString());
  }

  // ─── Device ─────────────────────────────────────────────────────────

  Future<CliResult> deviceNew(String dir, String relayHost, int relayPort, String pin, String duressPin,
      {bool unprotected = false, bool keystore = false, String ca = '', bool fastKdf = false}) {
    // fastKdf: a cheap PIN stretch, for tests only.
    return run(['device', 'new', dir, relayHost, '$relayPort', if (unprotected) '--unprotected', if (keystore && !unprotected) '--keystore', if (fastKdf) '--fast-kdf', if (ca.isNotEmpty) ...['--ca', ca]],
        input: [pin, duressPin], timeout: const Duration(minutes: 5));
  }

  /// Inception: [witnesses] as host:port:keyhex. [kitPassphrase] seals the
  /// recovery kit's sheet (SPEC 13.2); empty for none.
  Future<CliResult> deviceInit(String dir, String cosignerKeys, List<String> witnesses, String pin,
      {String devicePrimes = '', String kitPrimes = '', String kitPassphrase = ''}) {
    return run(['device', 'init', dir, cosignerKeys, ...witnesses, if (devicePrimes.isNotEmpty) ...[devicePrimes, kitPrimes]],
        input: [pin, ...newKitPassLines(kitPassphrase)]);
  }

  Future<CliResult> status(String dir) => run(['device', 'status', dir], timeout: const Duration(minutes: 2));

  /// The security update (D-4): the PIN, then the duress PIN ("" when this
  /// device has none). The duress profile gets a transport key of its own
  /// and the device a new one, published in the log.
  Future<CliResult> securityUpdate(String dir, String pin, String duressPin) =>
      run(['device', 'security-update', dir], input: [pin, duressPin], timeout: const Duration(minutes: 10));

  Future<CliResult> register(String dir, String rp, String pin, {bool duress = false}) =>
      run(['device', 'register', dir, rp, if (duress) '--duress'], input: [pin], timeout: const Duration(minutes: 5));

  Future<CliResult> sign(String dir, String rp, String cid, String messageHex, String pin) =>
      run(['device', 'sign', dir, rp, cid, messageHex], input: [pin], timeout: const Duration(minutes: 10));

  /// A passkey made for a site through the system: what register prints,
  /// with authenticator-data and attestation-object. [uv]: the PIN was
  /// entered in this ceremony.
  Future<CliResult> waRegister(String dir, String rp, String pin, {bool uv = true, String replaces = ''}) =>
      run(['device', 'webauthn', 'register', dir, rp, if (uv) '--uv', if (replaces.isNotEmpty) ...['--replaces', replaces]], input: [pin], timeout: const Duration(minutes: 5));

  /// The passkeys imported from another manager (Synced): "passkey ..." lines.
  Future<CliResult> waSynced(String dir, String pin) =>
      run(['device', 'webauthn', 'synced', dir], input: [pin], timeout: const Duration(minutes: 5));

  /// Deletes an imported passkey that a Symbolon passkey replaced.
  Future<CliResult> waRetire(String dir, String cid, String pin, {bool force = false}) =>
      run(['device', 'webauthn', 'retire', dir, cid, if (force) '--force'], input: [pin], timeout: const Duration(minutes: 5));

  /// A WebAuthn assertion: authenticator-data, signature-der, r || s.
  Future<CliResult> waAssert(String dir, String rp, String cid, String clientDataHash, String pin, {bool uv = true}) =>
      run(['device', 'webauthn', 'assert', dir, rp, cid, clientDataHash, if (uv) '--uv'], input: [pin], timeout: const Duration(minutes: 10));

  Future<CliResult> forget(String dir) => run(['device', 'forget', dir], timeout: const Duration(minutes: 1));

  // ─── Vault ──────────────────────────────────────────────────────────

  // [share]: a shared folder's id, for the vault commands that work in one
  // (list, show, set, delete, import); "" is the person's own vault.
  static List<String> _in(String share) => share.isEmpty ? const [] : ['--share', share];

  /// One line per item: "TYPE NAME-HEX DETAIL-HEX FOLDER-HEX". Offline, the device's
  /// copy, with a "local copy: REASON" line on standard error.
  Future<CliResult> vaultList(String dir, String pin, {String share = ''}) =>
      run(['device', 'vault', 'list', dir, '--long', ..._in(share)], input: [pin], timeout: const Duration(minutes: 5));

  /// "FIELD VALUE-HEX" per field, "type" first.
  Future<CliResult> vaultShow(String dir, String name, String pin, {String share = ''}) =>
      run(['device', 'vault', 'show', dir, name, ..._in(share)], input: [pin], timeout: const Duration(minutes: 5));

  /// The item's current one-time code: "code CODE PERIOD LEFT". The key
  /// stays in the agent (SPEC 18.7).
  Future<CliResult> vaultCode(String dir, String name, String pin, {String share = ''}) =>
      run(['device', 'vault', 'code', dir, name, ..._in(share)], input: [pin], timeout: const Duration(minutes: 5));

  /// Stores an item of [type] with [fields] (field name to text); replaces
  /// one of the same name.
  Future<CliResult> vaultSet(String dir, String name, String type, Map<String, String> fields, String pin, {String share = ''}) => run(['device', 'vault', 'set', dir, name, type, ..._in(share)],
      input: [pin, for (final e in fields.entries) '${e.key} ${_hex(e.value)}', ''], timeout: const Duration(minutes: 5));

  /// Another password manager's export at [file], read and checked
  /// without the PIN: "item TYPE NAME-HEX FOLDER-HEX", "skip NAME-HEX
  /// REASON-HEX", "warn TEXT-HEX", "total N".
  Future<CliResult> vaultImportPreview(String dir, String file) =>
      run(['device', 'vault', 'import', dir, file, '--dry-run'], timeout: const Duration(minutes: 5));

  /// The export at [file] into the vault, as one new version.
  Future<CliResult> vaultImport(String dir, String file, String pin, {String share = ''}) =>
      run(['device', 'vault', 'import', dir, file, ..._in(share)], input: [pin], timeout: const Duration(minutes: 15));

  /// Signs in to Bitwarden or Vaultwarden at [server] ("bitwarden.com",
  /// "bitwarden.eu" or an https:// address) and imports its vault: a
  /// conversation (bwsignin.resid). [extraEnv]: the trust anchors and DNS
  /// servers, as for the breach check.
  Future<AgentConversation?> signinBitwarden(String dir, String server, {String share = '', Map<String, String> extraEnv = const {}}) async {
    try {
      final p = await Process.start(binary, ['device', 'vault', 'signin-bitwarden', dir, server, ..._in(share)], environment: {...env, ...extraEnv});
      return AgentConversation._(p);
    } on ProcessException {
      return null;
    }
  }

  /// Signs in to LastPass and imports its vault (experimental,
  /// lpsignin.resid): the same conversation as [signinBitwarden].
  Future<AgentConversation?> signinLastpass(String dir, {String share = '', Map<String, String> extraEnv = const {}}) async {
    try {
      final p = await Process.start(binary, ['device', 'vault', 'signin-lastpass', dir, ..._in(share)], environment: {...env, ...extraEnv});
      return AgentConversation._(p);
    } on ProcessException {
      return null;
    }
  }

  /// An export handed over on standard input as one [line] (1Password CLI
  /// output, format "1password-op"), checked without the PIN.
  Future<CliResult> vaultImportLinePreview(String dir, String line, String format) =>
      run(['device', 'vault', 'import', dir, '-', '--format', format, '--dry-run'], input: [line], timeout: const Duration(minutes: 5));

  /// The export in [line] into the vault, as one new version.
  Future<CliResult> vaultImportLine(String dir, String line, String format, String pin, {String share = ''}) =>
      run(['device', 'vault', 'import', dir, '-', '--format', format, ..._in(share)], input: [line, pin], timeout: const Duration(minutes: 15));

  /// Each login's password against Pwned Passwords (SPEC 26.1):
  /// "breached NAME-HEX COUNT" lines, "protected N not checked", then
  /// "checked N breached M". [extraEnv]: where the trust anchors and DNS
  /// servers are, where the system does not say (breach.dart).
  Future<CliResult> vaultBreach(String dir, String pin, {String share = '', Map<String, String> extraEnv = const {}}) =>
      SymbolonCli(binary, env: {...env, ...extraEnv})
          .run(['device', 'vault', 'breach', dir, ..._in(share)], input: [pin], timeout: const Duration(minutes: 20));

  Future<CliResult> vaultDelete(String dir, String name, String pin, {String share = ''}) =>
      run(['device', 'vault', 'delete', dir, name, ..._in(share)], input: [pin], timeout: const Duration(minutes: 5));

  /// Moves an item of the own vault into the protected tier ([on]) or back
  /// (SPEC 18.10): opening a protected item then needs the cosigner.
  Future<CliResult> vaultProtect(String dir, String name, bool on, String pin) =>
      run(['device', 'vault', on ? 'protect' : 'unprotect', dir, name], input: [pin], timeout: const Duration(minutes: 5));

  /// Each device's protected openings from the cosigner's records: "limit
  /// N", then "device PARTY-HEX LABEL-HEX hour H day D week W usual|unusual".
  Future<CliResult> openings(String dir, String pin) => run(['device', 'openings', dir], input: [pin], timeout: const Duration(minutes: 2));

  /// Gives a quorum without one a vault OPRF key (a re-share with the cosigner).
  Future<CliResult> protectionEnable(String dir, String pin) => run(['device', 'protection', 'enable', dir], input: [pin]);

  /// Changes the log's witnesses (SPEC 20.3): [add] as host:port:keyhex,
  /// [remove] as host:port. Each added witness's signed time is checked
  /// first. Removing a witness, or a change signed by fewer devices than
  /// the policy asks for, waits out the recovery delay (any device may
  /// veto it); the output says whether it is in force or pending. This is
  /// how a household paired with an older Symbolon Home moves its witness
  /// majority off the box (the box's reminder gives the addresses).
  Future<CliResult> witnesses(String dir, String pin, {List<String> add = const [], List<String> remove = const []}) =>
      run(['device', 'witnesses', dir, for (final a in add) ...['--add', a], for (final r in remove) ...['--remove', r]],
          input: [pin], timeout: const Duration(minutes: 5));

  // ─── Organizations (SPEC 29) ────────────────────────────────────────

  /// "org ID NAME-HEX", "version V gov G", "role R", "policy ...",
  /// "recovery on K/N delay S" or "recovery off", then "recovery-request
  /// CID REQUESTER OPENS-AT" per request to open one of this person's
  /// work folders (no PIN).
  Future<CliResult> orgShow(String dir) => run(['device', 'org', 'show', dir], timeout: const Duration(minutes: 5));

  /// "LOG NAME-HEX EXT-HEX|- owner|admin|member GROUP-IDS|-" per member (no PIN).
  Future<CliResult> orgMembers(String dir) => run(['device', 'org', 'members', dir], timeout: const Duration(minutes: 5));

  /// "GROUP-ID NAME-HEX PEOPLE" per group (no PIN).
  Future<CliResult> orgGroups(String dir) => run(['device', 'org', 'groups', dir], timeout: const Duration(minutes: 5));

  /// Prints "ORG-ID NAME-HEX member|pending"; [code] answers an invite.
  /// The code is a bearer secret: it goes to standard input ("-"), before
  /// the PIN, never on the command line.
  Future<CliResult> orgJoin(String dir, String org, String founder, String code, String pin) =>
      run(['device', 'org', 'join', dir, org, founder, if (code.isNotEmpty) '-'], input: [if (code.isNotEmpty) code, pin], timeout: const Duration(minutes: 5));

  /// Prints "CODE ID" for one person of the company directory.
  Future<CliResult> orgInvite(String dir, String ext, String name, String pin, {String groups = ''}) =>
      run(['device', 'org', 'invite', dir, ext, name, if (groups.isNotEmpty) groups], input: [pin], timeout: const Duration(minutes: 5));

  /// Adds those who answered invites, applies the company directory, re-keys group folders people left.
  /// The directory's group additions are printed ("add ...", "new ...", then "confirm HASH") and applied
  /// only when [yes] is that HASH, after the person confirmed them.
  Future<CliResult> orgSync(String dir, String pin, {String yes = ''}) =>
      run(['device', 'org', 'sync', dir, if (yes.isNotEmpty) ...['--yes', yes]], input: [pin], timeout: const Duration(minutes: 30));

  /// Escrows a work folder this person owns to the organization's recovery key.
  Future<CliResult> orgEscrow(String dir, String id, String pin) => run(['device', 'org', 'escrow', dir, id], input: [pin], timeout: const Duration(minutes: 5));

  /// "ID KIND A-HEX B-HEX C-HEX BY STATUS RESULT-HEX" per change queued at the relay's console (no PIN).
  Future<CliResult> orgChanges(String dir) => run(['device', 'org', 'changes', dir], timeout: const Duration(minutes: 5));

  /// Makes a change queued at the console, signed on this device; [hash] is the SHA-256 of the change
  /// as shown ("ID KIND A-HEX B-HEX C-HEX BY"), so the relay cannot swap it after it was shown.
  Future<CliResult> orgApprove(String dir, String id, String hash, String pin) =>
      run(['device', 'org', 'approve', dir, id, hash], input: [pin], timeout: const Duration(minutes: 30));

  /// Approves the passkey waiting at the console with [code], for this administrator, once [fingerprint]
  /// (as the console shows it) matches its key.
  Future<CliResult> orgConsoleKey(String dir, String code, String fingerprint, String pin) =>
      run(['device', 'org', 'console-key', dir, code, fingerprint], input: [pin], timeout: const Duration(minutes: 5));

  // ─── Shared folders ─────────────────────────────────────────────────

  /// "ID NAME-HEX owner|member PEOPLE [duress]" per folder; "ID - waiting
  /// WHY-HEX" for one this device has no key for yet. Offline, the folders
  /// as this device last saw them, with a "local copy" line on standard error.
  /// Under the duress PIN, only the folders chosen for it.
  Future<CliResult> shareList(String dir, String pin) => run(['device', 'share', 'list', dir], input: [pin], timeout: const Duration(minutes: 5));

  /// Prints the new folder's id.
  Future<CliResult> shareNew(String dir, String name, String pin) => run(['device', 'share', 'new', dir, name], input: [pin], timeout: const Duration(minutes: 5));

  /// "LOG-ID NAME-HEX FINGERPRINT owner|member", the owner first.
  Future<CliResult> shareMembers(String dir, String id, String pin) =>
      run(['device', 'share', 'members', dir, id], input: [pin], timeout: const Duration(minutes: 5));

  Future<CliResult> shareAdd(String dir, String id, String logId, String name, String pin) =>
      run(['device', 'share', 'add', dir, id, logId, name], input: [pin], timeout: const Duration(minutes: 5));

  /// Removes a person: the folder gets a new key and everything in it is sealed again.
  Future<CliResult> shareRemove(String dir, String id, String logId, String pin) =>
      run(['device', 'share', 'remove', dir, id, logId], input: [pin], timeout: const Duration(minutes: 10));

  Future<CliResult> shareDelete(String dir, String id, String pin) => run(['device', 'share', 'delete', dir, id], input: [pin], timeout: const Duration(minutes: 5));

  /// A member leaves; the owner's device re-keys the folder when it next lists its folders.
  Future<CliResult> shareLeave(String dir, String id, String pin) => run(['device', 'share', 'leave', dir, id], input: [pin], timeout: const Duration(minutes: 5));

  /// Whether this device opens the folder under its duress PIN too (read only there).
  Future<CliResult> shareDuress(String dir, String id, bool on, String pin) =>
      run(['device', 'share', 'duress', dir, id, on ? 'on' : 'off'], input: [pin], timeout: const Duration(minutes: 5));

  /// Moves an item to the own vault ([to] "") or the shared folder [to], from the own vault ([from] "") or a folder.
  /// [unprotect]: a protected item goes into a shared folder unprotected (it holds no protected items).
  Future<CliResult> vaultMove(String dir, String name, String to, String pin, {String from = '', bool unprotect = false}) =>
      run(['device', 'vault', 'move', dir, name, to.isEmpty ? 'own' : to, if (unprotect) '--unprotect', ..._in(from)], input: [pin], timeout: const Duration(minutes: 5));

  /// Publishes the name others see; prints "LOG-ID FINGERPRINT".
  Future<CliResult> shareCard(String dir, String name, String pin) => run(['device', 'share', 'card', dir, name], input: [pin], timeout: const Duration(minutes: 5));

  /// "LOG-ID FINGERPRINT" (no PIN).
  Future<CliResult> shareMe(String dir) => run(['device', 'share', 'me', dir], timeout: const Duration(minutes: 1));

  /// "LOG-ID NAME-HEX FINGERPRINT me|-" per person with a card (no PIN).
  Future<CliResult> sharePeople(String dir) => run(['device', 'share', 'people', dir], timeout: const Duration(minutes: 5));

  Future<CliResult> vaultGet(String dir, String name, String pin) => run(['device', 'vault', 'get', dir, name], input: [pin], timeout: const Duration(minutes: 5));

  Future<CliResult> vaultPut(String dir, String name, String secret, String pin) =>
      run(['device', 'vault', 'put', dir, name], input: [pin, secret], timeout: const Duration(minutes: 5));

  Future<CliResult> vaultLogin(String dir, String name, String origin, String user, String password, String pin) =>
      run(['device', 'vault', 'login', dir, name, origin, user], input: [pin, password], timeout: const Duration(minutes: 5));

  Future<CliResult> rotate(String dir, String name, String bundle, String repo, String pin, {String chromium = '', String share = ''}) =>
      run(['device', 'rotate', dir, name, bundle, repo, if (chromium.isNotEmpty) chromium, ..._in(share)], input: [pin], timeout: const Duration(minutes: 15));

  // ─── SSH keys (SPEC 16.1) ───────────────────────────────────────────

  /// "NAME-HEX PUBLIC-LINE" per key (no PIN).
  Future<CliResult> sshList(String dir) => run(['device', 'ssh', 'list', dir], timeout: const Duration(minutes: 1));

  /// A threshold key; prints its public line.
  Future<CliResult> sshNew(String dir, String name, String pin) => run(['device', 'ssh', 'new', dir, name], input: [pin], timeout: const Duration(minutes: 5));

  /// [passphrase] for a key file that has one.
  Future<CliResult> sshImport(String dir, String name, String file, String pin, {String passphrase = ''}) =>
      run(['device', 'ssh', 'import', dir, name, file], input: [pin, if (passphrase.isNotEmpty) passphrase], timeout: const Duration(minutes: 5));

  Future<CliResult> sshDelete(String dir, String name, String pin) => run(['device', 'ssh', 'delete', dir, name], input: [pin], timeout: const Duration(minutes: 5));

  /// Prints "signature BLOB-HEX" for [dataHex].
  /// [alg]: rsa-sha2-256 or rsa-sha2-512 for an RSA key.
  /// [onSignature] gets the signature as soon as it is printed: a key whose
  /// certificate is due is then renewed in the same run (SPEC 16.1.2), and
  /// the client need not wait for that.
  Future<CliResult> sshSign(String dir, String name, String dataHex, String pin, {String alg = '', void Function(String sig)? onSignature}) =>
      runLive(['device', 'ssh', 'sign', dir, name, if (alg.isNotEmpty) alg], (l) {
        if (l.startsWith('signature ')) onSignature?.call(l.substring(10).trim());
      }, input: [pin, dataHex], timeout: const Duration(minutes: 8));

  // ─── The SSH certificate authority (SPEC 16.1.2) ────────────────────

  /// "NAME-HEX PUBLIC-LINE" per certificate authority (no PIN).
  Future<CliResult> sshCas(String dir) => run(['device', 'ssh', 'cas', dir], timeout: const Duration(minutes: 1));

  /// A certificate authority held by the quorum; prints its public line.
  Future<CliResult> sshCaNew(String dir, String name, String pin) => run(['device', 'ssh', 'ca-new', dir, name], input: [pin], timeout: const Duration(minutes: 5));

  /// "KEY-HEX CA-HEX DAYS PRINCIPALS VALID-AFTER VALID-BEFORE CERT-LINE" per certificate (no PIN).
  Future<CliResult> sshCerts(String dir) => run(['device', 'ssh', 'certs', dir], timeout: const Duration(minutes: 1));

  /// A user certificate for [key] by [ca] naming [principals]; prints its line.
  Future<CliResult> sshCertify(String dir, String key, String ca, List<String> principals, int days, String pin) =>
      run(['device', 'ssh', 'certify', dir, key, ca, for (final p in principals) ...['--principal', p], '--days', '$days'], input: [pin], timeout: const Duration(minutes: 8));

  /// A new certificate for [key] with the settings the vault remembers.
  Future<CliResult> sshRenew(String dir, String key, String pin) => run(['device', 'ssh', 'renew', dir, key], input: [pin], timeout: const Duration(minutes: 8));

  /// The key, CA and certificate lists rebuilt from the vault (keys made on another device).
  Future<CliResult> sshRefresh(String dir, String pin) => run(['device', 'ssh', 'refresh', dir], input: [pin], timeout: const Duration(minutes: 8));

  // ─── Security keys (SPEC 9.4) ───────────────────────────────────────

  /// "NAME-HEX" per enrolled key. With [pin], the list as that PIN sees
  /// it: under the duress PIN, with the changes made under it (which are
  /// acted, never made: SPEC 14.2); without, the device's key file.
  Future<CliResult> keyList(String dir, {String? pin}) => pin == null
      ? run(['device', 'key', 'list', dir], timeout: const Duration(minutes: 1))
      : run(['device', 'key', 'list', dir, '--pin'], input: [pin], timeout: const Duration(minutes: 2));

  /// Enrolls the present key (two touches).
  Future<CliResult> keyAdd(String dir, String name, String pin) => run(['device', 'key', 'add', dir, name], input: [pin], timeout: const Duration(minutes: 3));

  Future<CliResult> keyRemove(String dir, String name, String pin) => run(['device', 'key', 'remove', dir, name], input: [pin], timeout: const Duration(minutes: 3));

  /// Whether this device fills only with a security key ("keys") or not
  /// ("any"), SPEC 22.7 item 2. The PIN, and a touch if a key is enrolled.
  Future<CliResult> keyFills(String dir, bool needKey, String pin) =>
      run(['device', 'key', 'fills', dir, needKey ? 'keys' : 'any'], input: [pin], timeout: const Duration(minutes: 3));

  // ─── Devices and recovery ───────────────────────────────────────────

  Future<CliResult> enroll(String dir, String newKeys, String pin, {String primes = ''}) =>
      run(['device', 'enroll', dir, newKeys, if (primes.isNotEmpty) primes], input: [pin]);

  Future<CliResult> join(String dir, String enrollerKeys, String pin, {String primes = ''}) =>
      run(['device', 'join', dir, enrollerKeys, if (primes.isNotEmpty) primes], input: [pin]);

  /// Starts a kit recovery. [kitPassphrase]: the old kit's, when its sheet
  /// is protected; [newKitPassphrase] seals the new kit's sheet ("" none).
  Future<CliResult> recover(String dir, String kit, String logId, {String kitPassphrase = '', String newKitPassphrase = ''}) =>
      run(['device', 'recover', dir, kit, logId],
          input: [if (kitIsProtected(kit)) kitPassphrase, ...newKitPassLines(newKitPassphrase, explicitNone: true)], timeout: const Duration(minutes: 20));

  Future<CliResult> veto(String dir, String pin) => run(['device', 'veto', dir], input: [pin], timeout: const Duration(minutes: 5));

  /// The log's pending events (`device pending`), oldest first.
  Future<List<PendingEvent>> pending(String dir) async {
    final r = await run(['device', 'pending', dir], timeout: const Duration(minutes: 2));
    return r.ok ? PendingEvent.parseAll(r.out) : const [];
  }

  /// This device confirms the pending authority event [seq], which another
  /// device signed, so that it takes effect at once (SPEC 8.2). The PIN,
  /// then "y" (the person saw the event in the app's list first).
  Future<CliResult> confirm(String dir, int seq, String pin) =>
      run(['device', 'confirm', dir, '$seq'], input: [pin, 'y'], timeout: const Duration(minutes: 5));

  Future<CliResult> recoverRelease(String dir, String pin) => run(['device', 'recover-release', dir], input: [pin], timeout: const Duration(minutes: 5));

  Future<CliResult> recoverFinish(String dir, String kit, String pin, {String kitPassphrase = '', String primes = ''}) =>
      run(['device', 'recover-finish', dir, kit, if (primes.isNotEmpty) primes], input: [pin, if (kitIsProtected(kit)) kitPassphrase]);

  /// "protected", "plain" or "unknown" (a kit made before passphrases).
  Future<String> kitStatus(String dir) async {
    final r = await run(['device', 'kit', 'status', dir], timeout: const Duration(minutes: 1));
    final l = r.ok ? r.out : '';
    return l.contains('protected by a passphrase') ? 'protected' : l.contains('no passphrase') ? 'plain' : 'unknown';
  }

  /// Replaces the recovery kit (SPEC 13.2): a new kit sealed under
  /// [newPassphrase] ("" for none), printed as a "NEW RECOVERY KIT" line,
  /// and a logged rotate-recovery. "kit replaced" when it took effect and
  /// the quorum re-shared to the new kit; "kit replacement pending" while
  /// it waits out the delay (vetoable), after which the same call finishes
  /// it (no new kit is made then, and the passphrase lines go unread).
  Future<CliResult> kitRenew(String dir, String pin, String newPassphrase, {String primes = ''}) =>
      run(['device', 'kit', 'renew', dir, if (primes.isNotEmpty) primes], input: [pin, ...newKitPassLines(newPassphrase, explicitNone: true)],
          timeout: const Duration(minutes: 30));

  // Duress alerts (SPEC 14.4).

  /// The unlock beacon, sent after every unlock under either PIN; [location]
  /// is "LAT,LON,ACC,AGE" (1e-7 degrees, meters, seconds) or empty.
  Future<CliResult> beacon(String dir, String pin, {String location = ''}) =>
      run(['device', 'beacon', dir, if (location.isNotEmpty) ...['--location', location]], input: [pin], timeout: const Duration(minutes: 2));

  /// The alert settings and whether a duress window is open.
  Future<CliResult> alerts(String dir, String pin) => run(['device', 'alerts', dir], input: [pin], timeout: const Duration(minutes: 2));

  /// Replaces the contacts (and the name alerts use).
  Future<CliResult> alertsSet(String dir, String person, List<AlertContact> contacts, String pin) => run(['device', 'alerts', 'set', dir],
      input: [pin, 'person ${_hexOr(person)}', for (final c in contacts) c.line, ''], timeout: const Duration(minutes: 2));

  /// Ends a duress window another device of this identity opened.
  Future<CliResult> duressEnd(String dir, String pin) => run(['device', 'duress', 'end', dir], input: [pin], timeout: const Duration(minutes: 2));

  /// Lets this device receive household members' alerts.
  Future<CliResult> alertsRegister(String dir, String pin) => run(['device', 'alerts', 'register', dir], input: [pin], timeout: const Duration(minutes: 2));

  /// New household alerts (no PIN): "alert SUBJECT-HEX TEXT-HEX" lines.
  Future<CliResult> alertsInbox(String dir) => run(['device', 'alerts', 'inbox', dir], timeout: const Duration(minutes: 2));
}

String _hexOr(String s) => s.isEmpty ? '-' : _hex(s);

String _unhex(String h) {
  if (h == '-') return '';
  try {
    return utf8.decode([for (var i = 0; i + 1 < h.length; i += 2) int.parse(h.substring(i, i + 2), radix: 16)], allowMalformed: true);
  } on FormatException {
    return '';
  }
}

/// Someone told when this identity's duress PIN is used, and how.
class AlertContact {
  final String name;
  final bool ntfy;
  final String email, phone, household, threnody;
  final String topic; // the ntfy topic the box made for them ("" if none)
  const AlertContact({required this.name, this.ntfy = false, this.email = '', this.phone = '', this.household = '', this.threnody = '', this.topic = ''});

  String get line => 'contact ${_hexOr(name)} ${ntfy ? 1 : 0} ${_hexOr(email)} ${_hexOr(phone)} ${_hexOr(household)} ${_hexOr(threnody)}';

  /// The channels, for a list.
  String get summary => [
        if (ntfy) 'ntfy',
        if (email.isNotEmpty) email,
        if (phone.isNotEmpty) phone,
        if (household.isNotEmpty) 'Symbolon ($household)',
        if (threnody.isNotEmpty) 'Threnody',
      ].join(' · ');
}

/// What `device alerts` reports.
class AlertSettings {
  final String person;
  final List<AlertContact> contacts;
  final bool duress;
  final int startedAt;
  final String party; // the device that opened the window
  const AlertSettings({this.person = '', this.contacts = const [], this.duress = false, this.startedAt = 0, this.party = ''});

  static AlertSettings? parse(CliResult r) {
    if (!r.ok) return null;
    var person = '';
    final cs = <AlertContact>[];
    bool? duress;
    var started = 0;
    var party = '';
    for (final l in r.lines) {
      final p = l.trim().split(' ');
      if (p.length == 2 && p[0] == 'person') person = _unhex(p[1]);
      if (p.length == 8 && p[0] == 'contact') {
        cs.add(AlertContact(name: _unhex(p[1]), ntfy: p[2] == '1', email: _unhex(p[3]), phone: _unhex(p[4]), household: _unhex(p[5]), threnody: _unhex(p[6]), topic: p[7] == '-' ? '' : p[7]));
      }
      if (p.length == 2 && p[0] == 'duress' && p[1] == 'none') duress = false;
      if (p.length == 4 && p[0] == 'duress' && p[1] == 'open') {
        duress = true;
        started = int.tryParse(p[2]) ?? 0;
        party = p[3];
      }
    }
    if (duress == null) return null;
    return AlertSettings(person: person, contacts: cs, duress: duress, startedAt: started, party: party);
  }
}

/// A household member's alert, from `device alerts inbox`.
class HouseholdAlert {
  final String subject, text;
  const HouseholdAlert(this.subject, this.text);

  static List<HouseholdAlert> parse(CliResult r) => [
        for (final l in r.lines)
          if (l.startsWith('alert ') && l.trim().split(' ').length == 3) HouseholdAlert(_unhex(l.trim().split(' ')[1]), _unhex(l.trim().split(' ')[2])),
      ];
}

/// What `device status` reports.
class DeviceStatus {
  final String party;
  final bool unprotected;
  final bool keystore;      // the Android Keystore profile
  final String? log;
  final int? sequence, epoch, parties, threshold, pending;
  final bool protectedItems; // the quorum has a vault OPRF key (SPEC 18.10)
  /// `device security-update` has not run on this device yet. It depends on
  /// the device's files alone, never on a PIN, so it shows the same under
  /// the PIN and the duress PIN (SPEC 9.2).
  final bool securityUpdate;
  const DeviceStatus(
      {required this.party, required this.unprotected, this.keystore = false, this.log, this.sequence, this.epoch, this.parties, this.threshold, this.pending, this.protectedItems = false,
      this.securityUpdate = false});

  static DeviceStatus? parse(CliResult r) {
    final party = r.field('party');
    if (party == null) return null;
    final profile = r.field('profile') ?? '';
    final log = r.field('log');
    final head = r.field('head');
    int? at(String k) {
      if (head == null) return null;
      final m = RegExp('\\b$k (\\d+)').firstMatch(head);
      return m == null ? null : int.parse(m.group(1)!);
    }

    return DeviceStatus(
      party: party,
      unprotected: profile.startsWith('UNPROTECTED'),
      keystore: profile.startsWith('KEYSTORE'),
      log: (log == null || log.startsWith('none')) ? null : log,
      sequence: at('sequence'),
      epoch: at('epoch'),
      parties: at('parties'),
      threshold: at('threshold'),
      pending: at('pending'),
      protectedItems: (r.field('protected') ?? '').startsWith('on'),
      securityUpdate: (r.field('security-update') ?? '').startsWith('due'),
    );
  }
}

/// One device's protected openings, as `device openings` reports them.
class Openings {
  final String party;
  final String label;
  final int hour, day, week;
  final bool unusual;
  const Openings(this.party, this.label, this.hour, this.day, this.week, this.unusual);

  /// The limit (per device per hour) and one entry per device.
  static (int, List<Openings>) parse(CliResult r) {
    var limit = 0;
    final out = <Openings>[];
    for (final l in r.lines) {
      final p = l.trim().split(' ');
      if (p.length == 2 && p[0] == 'limit') limit = int.tryParse(p[1]) ?? 0;
      if (p.length == 10 && p[0] == 'device') {
        String label;
        try {
          label = utf8.decode([for (var i = 0; i + 1 < p[2].length; i += 2) int.parse(p[2].substring(i, i + 2), radix: 16)]);
        } on FormatException {
          label = '';
        }
        out.add(Openings(p[1], label, int.tryParse(p[4]) ?? 0, int.tryParse(p[6]) ?? 0, int.tryParse(p[8]) ?? 0, p[9] == 'unusual'));
      }
    }
    return (limit, out);
  }
}

/// One line of `device pending`: "SEQ DIGEST READY confirmable|not-confirmable
/// KIND; signed by LABELS".
class PendingEvent {
  final int seq;
  final String digest;    // the first 16 hex digits
  final int readyAt;      // witness time (Unix seconds) it takes effect at, unless vetoed
  final bool confirmable; // not a recover, the kit's set-policy or a weakening set-policy
  final String what;      // KIND; signed by LABELS
  const PendingEvent({required this.seq, required this.digest, required this.readyAt, required this.confirmable, required this.what});

  static PendingEvent? parse(String line) {
    final w = line.trim().split(' ');
    if (w.length < 5) return null;
    final seq = int.tryParse(w[0]), ready = int.tryParse(w[2]);
    if (seq == null || ready == null || (w[3] != 'confirmable' && w[3] != 'not-confirmable')) return null;
    return PendingEvent(seq: seq, digest: w[1], readyAt: ready, confirmable: w[3] == 'confirmable', what: w.sublist(4).join(' '));
  }

  static List<PendingEvent> parseAll(String out) =>
      [for (final l in out.split('\n')) if (parse(l) case final p?) p];
}
