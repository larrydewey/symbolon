// Links that carry what a person would otherwise type: an organization's
// invite (SPEC 29.3: the org id, its founder and the invite code), and a
// recovery sheet (SPEC 13.2: the identity log and the kit seed). Each is
// shown as a QR code and read back by scanning or pasting it.
//
//   symbolon://org?o=ORG-ID&f=FOUNDER&c=CODE
//   symbolon://recover?l=LOG-ID&k=KIT-SEED

final _hex = RegExp(r'^[0-9a-f]+$');
bool _isHex(String s, int len) => s.length == len && _hex.hasMatch(s);

Uri? _uri(String text, String host) {
  final u = Uri.tryParse(text.trim());
  return u == null || u.scheme != 'symbolon' || u.host != host ? null : u;
}

class OrgInvite {
  final String org;      // 32 hex digits
  final String founder;  // the founder's log id, 64
  final String code;     // the invite code, 32
  const OrgInvite(this.org, this.founder, this.code);

  String get link => 'symbolon://org?o=$org&f=$founder&c=$code';

  static OrgInvite? parse(String text) {
    final u = _uri(text, 'org');
    if (u == null) return null;
    final o = (u.queryParameters['o'] ?? '').toLowerCase(), f = (u.queryParameters['f'] ?? '').toLowerCase(), c = (u.queryParameters['c'] ?? '').toLowerCase();
    return _isHex(o, 32) && _isHex(f, 64) && _isHex(c, 32) ? OrgInvite(o, f, c) : null;
  }

  static bool isLink(String text) => parse(text) != null;
}

class RecoverySheet {
  final String log;   // the identity log, 64 hex digits
  final String kit;   // the kit seed, hex
  const RecoverySheet(this.log, this.kit);

  String get link => 'symbolon://recover?l=$log&k=$kit';

  static RecoverySheet? parse(String text) {
    final u = _uri(text, 'recover');
    if (u == null) return null;
    final l = (u.queryParameters['l'] ?? '').toLowerCase(), k = (u.queryParameters['k'] ?? '').toLowerCase();
    return _isHex(l, 64) && k.length >= 32 && k.length.isEven && _hex.hasMatch(k) ? RecoverySheet(l, k) : null;
  }

  static bool isLink(String text) => parse(text) != null;
}

/// [s] in groups of four, for writing down and reading back.
List<String> groupsOf(String s) => [for (var i = 0; i < s.length; i += 4) s.substring(i, i + 4 > s.length ? s.length : i + 4)];
