// The bridge to the `symbolon` command-line agent. The UI holds no key
// material: every operation is one run of the binary, with PINs and secrets
// written to its standard input (never on the command line, where other
// processes could read them) and the result read from its output.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

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

  // ─── Device ─────────────────────────────────────────────────────────

  Future<CliResult> deviceNew(String dir, String relayHost, int relayPort, String pin, String duressPin,
      {bool unprotected = false, bool keystore = false, String ca = '', bool fastKdf = false}) {
    // fastKdf: a cheap PIN stretch, for tests only.
    return run(['device', 'new', dir, relayHost, '$relayPort', if (unprotected) '--unprotected', if (keystore && !unprotected) '--keystore', if (fastKdf) '--fast-kdf', if (ca.isNotEmpty) ...['--ca', ca]],
        input: [pin, duressPin], timeout: const Duration(minutes: 5));
  }

  /// Inception: [witnesses] as host:port:keyhex.
  Future<CliResult> deviceInit(String dir, String cosignerKeys, List<String> witnesses, String pin, {String devicePrimes = '', String kitPrimes = ''}) {
    return run(['device', 'init', dir, cosignerKeys, ...witnesses, if (devicePrimes.isNotEmpty) ...[devicePrimes, kitPrimes]], input: [pin]);
  }

  Future<CliResult> status(String dir) => run(['device', 'status', dir], timeout: const Duration(minutes: 2));

  Future<CliResult> register(String dir, String rp, String pin, {bool duress = false}) =>
      run(['device', 'register', dir, rp, if (duress) '--duress'], input: [pin], timeout: const Duration(minutes: 5));

  Future<CliResult> sign(String dir, String rp, String cid, String messageHex, String pin) =>
      run(['device', 'sign', dir, rp, cid, messageHex], input: [pin], timeout: const Duration(minutes: 10));

  /// A passkey made for a site through the system: what register prints,
  /// with authenticator-data and attestation-object. [uv]: the PIN was
  /// entered in this ceremony.
  Future<CliResult> waRegister(String dir, String rp, String pin, {bool uv = true}) =>
      run(['device', 'webauthn', 'register', dir, rp, if (uv) '--uv'], input: [pin], timeout: const Duration(minutes: 5));

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

  Future<CliResult> vaultDelete(String dir, String name, String pin, {String share = ''}) =>
      run(['device', 'vault', 'delete', dir, name, ..._in(share)], input: [pin], timeout: const Duration(minutes: 5));

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
  Future<CliResult> orgJoin(String dir, String org, String founder, String code, String pin) =>
      run(['device', 'org', 'join', dir, org, founder, if (code.isNotEmpty) code], input: [pin], timeout: const Duration(minutes: 5));

  /// Prints "CODE ID" for one person of the company directory.
  Future<CliResult> orgInvite(String dir, String ext, String name, String pin, {String groups = ''}) =>
      run(['device', 'org', 'invite', dir, ext, name, if (groups.isNotEmpty) groups], input: [pin], timeout: const Duration(minutes: 5));

  /// Adds those who answered invites, applies the company directory, re-keys group folders people left.
  Future<CliResult> orgSync(String dir, String pin) => run(['device', 'org', 'sync', dir], input: [pin], timeout: const Duration(minutes: 30));

  /// Escrows a work folder this person owns to the organization's recovery key.
  Future<CliResult> orgEscrow(String dir, String id, String pin) => run(['device', 'org', 'escrow', dir, id], input: [pin], timeout: const Duration(minutes: 5));

  /// "ID KIND A-HEX B-HEX C-HEX BY STATUS RESULT-HEX" per change queued at the relay's console (no PIN).
  Future<CliResult> orgChanges(String dir) => run(['device', 'org', 'changes', dir], timeout: const Duration(minutes: 5));

  /// Makes a change queued at the console, signed on this device.
  Future<CliResult> orgApprove(String dir, String id, String pin) => run(['device', 'org', 'approve', dir, id], input: [pin], timeout: const Duration(minutes: 30));

  /// Approves the passkey waiting at the console with [code], for this administrator.
  Future<CliResult> orgConsoleKey(String dir, String code, String pin) => run(['device', 'org', 'console-key', dir, code], input: [pin], timeout: const Duration(minutes: 5));

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
  Future<CliResult> vaultMove(String dir, String name, String to, String pin, {String from = ''}) =>
      run(['device', 'vault', 'move', dir, name, to.isEmpty ? 'own' : to, ..._in(from)], input: [pin], timeout: const Duration(minutes: 5));

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
  Future<CliResult> sshSign(String dir, String name, String dataHex, String pin, {String alg = ''}) =>
      run(['device', 'ssh', 'sign', dir, name, if (alg.isNotEmpty) alg], input: [pin, dataHex], timeout: const Duration(minutes: 5));

  // ─── Security keys (SPEC 9.4) ───────────────────────────────────────

  /// "NAME-HEX" per enrolled key (no PIN).
  Future<CliResult> keyList(String dir) => run(['device', 'key', 'list', dir], timeout: const Duration(minutes: 1));

  /// Enrolls the present key (two touches).
  Future<CliResult> keyAdd(String dir, String name, String pin) => run(['device', 'key', 'add', dir, name], input: [pin], timeout: const Duration(minutes: 3));

  Future<CliResult> keyRemove(String dir, String name, String pin) => run(['device', 'key', 'remove', dir, name], input: [pin], timeout: const Duration(minutes: 3));

  // ─── Devices and recovery ───────────────────────────────────────────

  Future<CliResult> enroll(String dir, String newKeys, String pin, {String primes = ''}) =>
      run(['device', 'enroll', dir, newKeys, if (primes.isNotEmpty) primes], input: [pin]);

  Future<CliResult> join(String dir, String enrollerKeys, String pin, {String primes = ''}) =>
      run(['device', 'join', dir, enrollerKeys, if (primes.isNotEmpty) primes], input: [pin]);

  Future<CliResult> recover(String dir, String kitSeed, String logId) =>
      run(['device', 'recover', dir, kitSeed, logId], timeout: const Duration(minutes: 5));

  Future<CliResult> veto(String dir, String pin) => run(['device', 'veto', dir], input: [pin], timeout: const Duration(minutes: 5));

  Future<CliResult> recoverRelease(String dir, String pin) => run(['device', 'recover-release', dir], input: [pin], timeout: const Duration(minutes: 5));

  Future<CliResult> recoverFinish(String dir, String kitSeed, String pin, {String primes = ''}) =>
      run(['device', 'recover-finish', dir, kitSeed, if (primes.isNotEmpty) primes], input: [pin]);
}

/// What `device status` reports.
class DeviceStatus {
  final String party;
  final bool unprotected;
  final bool keystore;      // the Android Keystore profile
  final String? log;
  final int? sequence, epoch, parties, threshold, pending;
  const DeviceStatus(
      {required this.party, required this.unprotected, this.keystore = false, this.log, this.sequence, this.epoch, this.parties, this.threshold, this.pending});

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
    );
  }
}
