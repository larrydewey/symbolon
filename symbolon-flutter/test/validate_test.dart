import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_ui/favicons.dart';
import 'package:symbolon_ui/validate.dart' as v;
import 'package:symbolon_ui/vault_types.dart';

void main() {
  test('card numbers: Luhn, length, spaces', () {
    expect(v.cardNumber('4111 1111 1111 1111'), isNull);
    expect(v.cardNumber('4111-1111-1111-1112'), contains('not valid'));
    expect(v.cardNumber('4111'), contains('12 to 19'));
    expect(v.cardNumber('4111 abcd'), 'Digits only');
    expect(v.digitsOf('4111 1111-1111 1111'), '4111111111111111');
    expect(v.cardBrand('4111111111111111'), 'Visa');
    expect(v.cardBrand('5500000000000004'), 'Mastercard');
    expect(v.cardBrand('340000000000009'), 'American Express');
  });

  test('expiry, security code, card PIN', () {
    expect(v.expiry('08/29'), isNull);
    expect(v.expiry('8/2029'), isNull);
    expect(v.normalizeExpiry('8/2029'), '08/29');
    expect(v.expiry('13/29'), contains('01 to 12'));
    expect(v.expiry('0829'), contains('MM/YY'));
    expect(v.cvv('123'), isNull);
    expect(v.cvv('12'), isNotNull);
    expect(v.cardPin('1234'), isNull);
    expect(v.cardPin('12a4'), isNotNull);
  });

  test('sites, hosts and origins', () {
    expect(v.site('accounts.example.com'), isNull);
    expect(v.site('https://accounts.example.com/login?x=1'), isNull);
    expect(v.origin('Accounts.Example.com/login'), 'https://accounts.example.com');
    expect(v.origin('http://localhost:8080/x'), 'http://localhost:8080');
    expect(v.site('ftp://example.com'), isNotNull);
    expect(v.site('not a site'), isNotNull);
    expect(v.hostName('login.example.com'), isNull);
    expect(v.hostName('https://login.example.com'), contains('Only the host'));
    expect(v.hostName('bad_host'), isNotNull);
  });

  test('identity and bank fields', () {
    expect(v.email('a@b.co'), isNull);
    expect(v.email('a@b'), isNotNull);
    expect(v.phone('+1 (555) 010-9999'), isNull);
    expect(v.phone('12'), isNotNull);
    expect(v.pastDate('1990-02-28'), isNull);
    expect(v.pastDate('1990-02-30'), contains('no such date'));
    expect(v.pastDate('2999-01-01'), contains('future'));
    expect(v.iban('GB82 WEST 1234 5698 7654 32'), isNull);
    expect(v.iban('GB82 WEST 1234 5698 7654 33'), contains('not valid'));
    expect(v.swift('DEUTDEFF'), isNull);
    expect(v.swift('DEUT'), isNotNull);
  });

  test('PINs, setup addresses, witnesses, hex', () {
    expect(v.pin('2468'), isNull);
    expect(v.pin('2468', min: 6), contains('6'));
    expect(v.pin('24a8'), 'Digits only');
    expect(v.serviceUrl('http://192.168.1.20:47000'), isNull);
    expect(v.serviceUrl('192.168.1.20:47000'), isNotNull);
    expect(v.port('0'), isNotNull);
    expect(v.witness('10.0.0.1:47011:${'ab' * 33}'), isNull);
    expect(v.witness('10.0.0.1:99999:${'ab' * 33}'), isNotNull);
    expect(v.hexBytes(32)('00' * 32), isNull);
    expect(v.hexBytes(32)('00' * 31), isNotNull);
  });

  test('custom fields and list lines round-trip', () {
    final c = CustomField.decode(const CustomField('Member no.', 'A-1\x1fx', hidden: true).encode());
    expect(c.label, 'Member no.');
    expect(c.hidden, isTrue);
    expect(c.value, 'A-1\x1fx');
    expect(CustomField.checkLabel(''), isNotNull);
    final it = VaultItem.parse('card ${hexOf('my visa')} ${hexOf('1111')}')!;
    expect(it.name, 'my visa');
    expect(it.subtitle, '•••• 1111');
    expect(VaultItem.parse('secret ${hexOf('bank')} -')!.detail, '');
    expect(VaultItem.parse('garbage'), isNull);
    final f = VaultItem.parse('login ${hexOf('mail')} - ${hexOf('Work/Email')}')!;
    expect(f.folder, 'Work/Email');
    expect(f.detail, '');
    expect(VaultItem.parse('card ${hexOf('v')} ${hexOf('1111')} -')!.folder, '');
    expect(typeOf('card').field('number')!.validate('4111 1111 1111 1111'), isNull);
    expect(typeOf('card').field('number')!.stored('4111 1111 1111 1111'), '4111111111111111');
    expect(typeOf('login').field('origin')!.stored('example.com/x'), 'https://example.com');
  });

  test('site icons come from the site, once, and a miss is remembered', () async {
    final icon = Uint8List.fromList(List.generate(64, (i) => i));
    var hits = 0;
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((rq) {
      hits++;
      if (rq.uri.path == '/favicon.ico') {
        rq.response.headers.contentType = ContentType('image', 'x-icon');
        rq.response.add(icon);
      } else {
        rq.response.statusCode = 404;
      }
      rq.response.close();
    });
    final dir = await Directory.systemTemp.createTemp('icons');
    final origin = 'http://127.0.0.1:${server.port}';
    expect(await Favicons(dir).icon(origin), icon);
    expect(await Favicons(dir).icon(origin), icon);     // from the file
    expect(hits, 1);
    await server.close(force: true);
    // A site without an icon: null, and not asked again soon.
    expect(await Favicons(dir).icon('http://127.0.0.1:1'), isNull);
    await dir.delete(recursive: true);
  });
}
