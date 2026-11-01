// Checks for what the user types. Each returns null when the text is fine,
// or what is wrong with it, in words for the user (the shape of a
// FormField validator). Normalizers turn accepted input into what is
// stored (a card number without spaces, a site as its origin).

typedef Check = String? Function(String v);

String? required(String v, [String what = 'This']) => v.trim().isEmpty ? '$what is required' : null;

/// Runs [checks] in order and returns the first problem.
Check all(List<Check> checks) => (v) {
      for (final c in checks) {
        final m = c(v);
        if (m != null) return m;
      }
      return null;
    };

/// Empty text passes; otherwise [c] decides.
Check optional(Check c) => (v) => v.trim().isEmpty ? null : c(v);

String? itemName(String v) {
  final t = v.trim();
  if (t.isEmpty) return 'A name is required';
  if (t.length > 128) return 'At most 128 characters';
  if (t.contains('\n')) return 'One line only';
  return null;
}

String? singleLine(String v) => v.contains('\n') ? 'One line only' : null;

String? maxLength(String v, int n) => v.length > n ? 'At most $n characters' : null;

String digitsOf(String v) => v.replaceAll(RegExp(r'[\s-]'), '');

bool luhn(String digits) {
  var sum = 0;
  for (var i = 0; i < digits.length; i++) {
    var d = digits.codeUnitAt(digits.length - 1 - i) - 48;
    if (i.isOdd) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 == 0;
}

String? cardNumber(String v) {
  final d = digitsOf(v);
  if (d.isEmpty) return 'The card number is required';
  if (!RegExp(r'^\d+$').hasMatch(d)) return 'Digits only';
  if (d.length < 12 || d.length > 19) return 'A card number has 12 to 19 digits';
  if (!luhn(d)) return 'This card number is not valid (check the digits)';
  return null;
}

/// The card network from the number's first digits, or ''.
String cardBrand(String digits) {
  if (digits.startsWith('4')) return 'Visa';
  if (RegExp(r'^(5[1-5]|2[2-7])').hasMatch(digits)) return 'Mastercard';
  if (RegExp(r'^3[47]').hasMatch(digits)) return 'American Express';
  if (RegExp(r'^(6011|65|64[4-9])').hasMatch(digits)) return 'Discover';
  if (RegExp(r'^35').hasMatch(digits)) return 'JCB';
  if (RegExp(r'^3(0[0-5]|[68])').hasMatch(digits)) return 'Diners Club';
  return '';
}

/// MM/YY or MM/YYYY.
String? expiry(String v) {
  final m = RegExp(r'^\s*(\d{1,2})\s*/\s*(\d{2}|\d{4})\s*$').firstMatch(v);
  if (m == null) return 'Use MM/YY, as 08/29';
  final month = int.parse(m.group(1)!);
  if (month < 1 || month > 12) return 'The month is 01 to 12';
  return null;
}

String normalizeExpiry(String v) {
  final m = RegExp(r'^\s*(\d{1,2})\s*/\s*(\d{2}|\d{4})\s*$').firstMatch(v);
  if (m == null) return v.trim();
  final y = m.group(2)!;
  return '${m.group(1)!.padLeft(2, '0')}/${y.length == 4 ? y.substring(2) : y}';
}

String? cvv(String v) => RegExp(r'^\d{3,4}$').hasMatch(v.trim()) ? null : 'A security code is 3 or 4 digits';

String? cardPin(String v) => RegExp(r'^\d{4,12}$').hasMatch(v.trim()) ? null : 'A card PIN is 4 to 12 digits';

String? email(String v) => RegExp(r'^[^\s@]+@[^\s@]+\.[^\s@]+$').hasMatch(v.trim()) ? null : 'This is not an email address';

String? phone(String v) {
  final t = v.trim();
  if (!RegExp(r'^\+?[\d\s().-]+$').hasMatch(t)) return 'Digits, spaces and + ( ) - only';
  final n = t.replaceAll(RegExp(r'\D'), '').length;
  return n < 5 || n > 15 ? 'A phone number has 5 to 15 digits' : null;
}

/// YYYY-MM-DD, a real date, not in the future.
String? pastDate(String v) {
  final m = RegExp(r'^(\d{4})-(\d{2})-(\d{2})$').firstMatch(v.trim());
  if (m == null) return 'Use YYYY-MM-DD';
  final y = int.parse(m.group(1)!), mo = int.parse(m.group(2)!), d = int.parse(m.group(3)!);
  final dt = DateTime(y, mo, d);
  if (dt.year != y || dt.month != mo || dt.day != d) return 'There is no such date';
  if (dt.isAfter(DateTime.now())) return 'This date is in the future';
  return null;
}

/// A site address, with or without the https:// in front.
String? site(String v) {
  final t = v.trim();
  if (t.isEmpty) return 'The site address is required';
  final u = Uri.tryParse(t.contains('://') ? t : 'https://$t');
  if (u == null || (u.scheme != 'https' && u.scheme != 'http') || !_host(u.host)) return 'This is not a site address';
  return null;
}

/// The site's origin, as the agent stores it: scheme://host[:port].
String origin(String v) {
  final t = v.trim();
  final u = Uri.parse(t.contains('://') ? t : 'https://$t');
  return '${u.scheme}://${u.host.toLowerCase()}${u.hasPort ? ':${u.port}' : ''}';
}

bool _host(String h) =>
    h == 'localhost' ||
    RegExp(r'^(\d{1,3}\.){3}\d{1,3}$').hasMatch(h) ||
    RegExp(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$', caseSensitive: false).hasMatch(h);

/// A relying party for a passkey: a host name, as login.example.com.
String? hostName(String v) {
  final t = v.trim().toLowerCase();
  if (t.isEmpty) return 'The site is required';
  if (t.contains('://') || t.contains('/')) return 'Only the host name, as login.example.com';
  return _host(t) ? null : 'This is not a host name';
}

String? iban(String v) {
  final t = v.replaceAll(' ', '').toUpperCase();
  if (!RegExp(r'^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$').hasMatch(t)) return 'This is not an IBAN';
  final r = t.substring(4) + t.substring(0, 4);
  var mod = 0;
  for (final c in r.codeUnits) {
    final s = c >= 65 ? '${c - 55}' : String.fromCharCode(c);
    for (final d in s.codeUnits) {
      mod = (mod * 10 + d - 48) % 97;
    }
  }
  return mod == 1 ? null : 'This IBAN is not valid (check the digits)';
}

String? swift(String v) =>
    RegExp(r'^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$').hasMatch(v.trim().toUpperCase()) ? null : 'A SWIFT/BIC code is 8 or 11 letters and digits';

String? accountNumber(String v) => RegExp(r'^[A-Za-z0-9 -]{4,34}$').hasMatch(v.trim()) ? null : '4 to 34 letters and digits';

String? routing(String v) => RegExp(r'^[0-9 -]{4,15}$').hasMatch(v.trim()) ? null : '4 to 15 digits';

String? ssid(String v) {
  final t = v;
  if (t.isEmpty) return 'The network name is required';
  return t.length > 32 ? 'A network name is at most 32 characters' : null;
}

/// A PIN: digits only, at least [min].
String? pin(String v, {int min = 4}) {
  if (!RegExp(r'^\d*$').hasMatch(v)) return 'Digits only';
  if (v.length < min) return 'At least $min digits';
  if (v.length > 32) return 'At most 32 digits';
  return null;
}

/// An http(s) address with a host, as http://192.168.1.20:47000.
String? serviceUrl(String v) {
  final u = Uri.tryParse(v.trim());
  if (u == null || (u.scheme != 'http' && u.scheme != 'https') || u.host.isEmpty) return 'Use http://address:port';
  return null;
}

String? port(String v) {
  final n = int.tryParse(v.trim());
  return n == null || n < 1 || n > 65535 ? 'A port is 1 to 65535' : null;
}

/// A witness: host:port:public key (hex).
String? witness(String v) {
  final p = v.trim().split(':');
  if (p.length != 3) return 'Use host:port:public key';
  if (p[0].isEmpty) return 'The host is missing';
  if (port(p[1]) != null) return 'The port is 1 to 65535';
  return hex(p[2]) == null && p[2].length >= 64 ? null : 'The public key is hex';
}

String? hex(String v) => RegExp(r'^([0-9a-fA-F]{2})+$').hasMatch(v.trim()) ? null : 'Hex digits only (0-9, a-f)';

/// Hex of exactly [bytes] bytes.
Check hexBytes(int bytes) => (v) => hex(v) ?? (v.trim().length == bytes * 2 ? null : 'Exactly ${bytes * 2} hex digits');
