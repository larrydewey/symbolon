// The kinds of vault items and their fields. The agent stores any named
// fields (`vault set`); what each type has, how a field is entered and
// checked, and which ones are hidden until asked is decided here.

import 'dart:convert';

import 'package:flutter/material.dart';

import 'validate.dart' as v;

enum Input { text, multiline, secret, digits, email, phone, url, date }

class FieldSpec {
  final String name;          // as stored: a-z, 0-9, _
  final String label;
  final Input input;
  final bool required;
  final String? hint;
  final v.Check? check;       // for non-empty text; required is checked apart
  final String Function(String)? normalize;
  const FieldSpec(this.name, this.label, {this.input = Input.text, this.required = false, this.hint, this.check, this.normalize});

  bool get hidden => input == Input.secret;

  String? validate(String text) {
    if (text.trim().isEmpty) return required ? '$label is required' : null;
    if (input != Input.multiline && text.contains('\n')) return 'One line only';
    if (text.length > 60000) return 'Too long';
    return check?.call(text);
  }

  String stored(String text) => normalize?.call(text) ?? (input == Input.multiline || input == Input.secret ? text : text.trim());
}

class ItemType {
  final String id;
  final String label;
  final String plural;
  final IconData icon;
  final Color color;
  final List<FieldSpec> fields;
  final bool editable;      // false: made and changed by its own commands (SSH keys), not the editor
  const ItemType(this.id, this.label, this.plural, this.icon, this.color, this.fields, {this.editable = true});

  FieldSpec? field(String name) => fields.where((f) => f.name == name).firstOrNull;
}

const _notes = FieldSpec('notes', 'Notes', input: Input.multiline);

final itemTypes = <ItemType>[
  // A login needs a site, a username or a password (an imported one may
  // have only some of them); the editor asks for at least one field.
  ItemType('login', 'Login', 'Logins', Icons.language, Colors.teal, [
    FieldSpec('origin', 'Site address', input: Input.url, hint: 'accounts.example.com', check: v.site, normalize: v.origin),
    const FieldSpec('username', 'Username or email'),
    const FieldSpec('current', 'Password', input: Input.secret),
    const FieldSpec('totp', 'One-time code key (TOTP)', input: Input.secret, hint: 'otpauth://... or the key'),
    _notes,
  ]),
  ItemType('card', 'Card', 'Cards', Icons.credit_card, Colors.blue, [
    const FieldSpec('cardholder', 'Name on card'),
    FieldSpec('number', 'Card number', input: Input.digits, required: true, hint: '1234 5678 9012 3456', check: v.cardNumber, normalize: v.digitsOf),
    FieldSpec('expiry', 'Expiry', input: Input.date, hint: 'MM/YY', check: v.expiry, normalize: v.normalizeExpiry),
    const FieldSpec('cvv', 'Security code (CVV)', input: Input.secret, check: v.cvv),
    const FieldSpec('pin', 'Card PIN', input: Input.secret, check: v.cardPin),
    _notes,
  ]),
  ItemType('identity', 'Identity', 'Identities', Icons.badge_outlined, Colors.orange, [
    const FieldSpec('full_name', 'Full name'),
    const FieldSpec('email', 'Email', input: Input.email, check: v.email),
    const FieldSpec('phone', 'Phone', input: Input.phone, check: v.phone),
    const FieldSpec('address', 'Address', input: Input.multiline),
    const FieldSpec('birth_date', 'Date of birth', input: Input.date, hint: 'YYYY-MM-DD', check: v.pastDate),
    const FieldSpec('document', 'Passport or ID number', input: Input.secret),
    _notes,
  ]),
  ItemType('note', 'Note', 'Notes', Icons.sticky_note_2_outlined, Colors.amber, [
    const FieldSpec('text', 'Note', input: Input.multiline, required: true),
  ]),
  ItemType('bank', 'Bank account', 'Bank accounts', Icons.account_balance_outlined, Colors.green, [
    const FieldSpec('bank_name', 'Bank'),
    const FieldSpec('holder', 'Account holder'),
    const FieldSpec('account_number', 'Account number', input: Input.secret, check: v.accountNumber),
    const FieldSpec('routing', 'Routing or sort code', input: Input.digits, check: v.routing),
    FieldSpec('iban', 'IBAN', check: v.iban, normalize: (s) => s.replaceAll(' ', '').toUpperCase()),
    FieldSpec('swift', 'SWIFT/BIC', check: v.swift, normalize: (s) => s.trim().toUpperCase()),
    _notes,
  ]),
  ItemType('wifi', 'Wi-Fi', 'Wi-Fi', Icons.wifi, Colors.cyan, [
    const FieldSpec('ssid', 'Network name', required: true, check: v.ssid),
    const FieldSpec('password', 'Password', input: Input.secret),
    const FieldSpec('security', 'Security', hint: 'WPA2, WPA3, open'),
    _notes,
  ]),
  // SSH keys (SPEC 16.1): made, imported and deleted on the SSH keys page;
  // the private part never leaves the agent.
  ItemType('ssh', 'SSH key', 'SSH keys', Icons.vpn_key_outlined, Colors.brown, [
    const FieldSpec('public', 'Public key'),
    const FieldSpec('kind', 'Kind'),
    const FieldSpec('comment', 'Comment'),
  ], editable: false),
  ItemType('secret', 'Secret', 'Secrets', Icons.key_outlined, Colors.deepPurple, [
    const FieldSpec('secret', 'Secret', input: Input.secret, required: true),
    _notes,
  ]),
];

ItemType typeOf(String id) => itemTypes.firstWhere((t) => t.id == id, orElse: () => itemTypes.last);

/// A field the user added: a label, whether it is hidden, and the value.
/// Stored as custom_N, the value being label, 0x1f, "1" or "0", 0x1f, text.
class CustomField {
  final String label;
  final bool hidden;
  final String value;
  const CustomField(this.label, this.value, {this.hidden = false});

  static const maxCount = 20;
  static bool isCustom(String name) => RegExp(r'^custom_\d+$').hasMatch(name);

  String encode() => '$label\x1f${hidden ? 1 : 0}\x1f$value';

  static CustomField decode(String s) {
    final p = s.split('\x1f');
    if (p.length < 3) return CustomField('Field', s);
    return CustomField(p[0], p.sublist(2).join('\x1f'), hidden: p[1] == '1');
  }

  static String? checkLabel(String l) {
    if (l.trim().isEmpty) return 'A label is required';
    if (l.length > 64) return 'At most 64 characters';
    if (l.contains('\x1f') || l.contains('\n')) return 'One line only';
    return null;
  }
}

/// An item as the vault list shows it (`vault list --long`).
class VaultItem {
  final String name;
  final String type;
  final String detail;     // a login's origin, a card's last four digits
  final String folder;     // "" when in no folder; levels joined by "/"
  const VaultItem(this.name, this.type, {this.detail = '', this.folder = ''});

  ItemType get kind => typeOf(type);

  /// "TYPE NAME-HEX DETAIL-HEX [FOLDER-HEX]"; null for a line that is not one.
  static VaultItem? parse(String line) {
    final p = line.trim().split(' ');
    if (p.length != 3 && p.length != 4) return null;
    String un(String h) => h == '-' ? '' : unhex(h);
    try {
      return VaultItem(unhex(p[1]), p[0], detail: un(p[2]), folder: p.length == 4 ? un(p[3]) : '');
    } on FormatException {
      return null;
    }
  }

  String get subtitle => switch (type) {
        'login' => detail.replaceFirst(RegExp(r'^https://'), ''),
        'card' => detail.isEmpty ? 'Card' : '•••• $detail',
        _ => kind.label,
      };
}

String hexOf(String s) => utf8.encode(s).map((b) => b.toRadixString(16).padLeft(2, '0')).join();

String unhex(String h) {
  if (h.length.isOdd) throw const FormatException('odd hex');
  final b = <int>[];
  for (var i = 0; i < h.length; i += 2) {
    b.add(int.parse(h.substring(i, i + 2), radix: 16));
  }
  return utf8.decode(b, allowMalformed: true);
}
