// A stand-in for the `symbolon` binary: a shell script that records its
// arguments and standard input and answers like the agent does.

import 'dart:io';

class FakeAgent {
  final Directory dir;
  FakeAgent(this.dir);

  String get path => '${dir.path}/symbolon';
  File get argsLog => File('${dir.path}/args.log');
  File get stdinLog => File('${dir.path}/stdin.log');

  static Future<FakeAgent> create() async {
    final d = await Directory.systemTemp.createTemp('fake-symbolon');
    final a = FakeAgent(d);
    await File(a.path).writeAsString(r'''#!/bin/bash
D="$(dirname "$0")"
echo "$*" >> "$D/args.log"
IN=$(cat)
printf '%s\n--\n' "$IN" >> "$D/stdin.log"
PIN=$(printf '%s\n' "$IN" | head -1)
case "$1 $2" in
  "device status")
    echo "party 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    echo "profile TPM"
    echo "log fa8f008b293b5457ef989520c8bbcbc959a09c0a8619b1d190f78271bf6b5795"
    echo "head sequence 3 epoch 2 parties 4 threshold 2 pending 1" ;;
  "device register")
    [ "$PIN" = "2468" ] || { echo "device: wrong PIN" >&2; exit 1; }
    echo "credential-id aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    echo "public-key 04bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ;;
  "device webauthn")
    [ "$PIN" = "2468" ] || { echo "device: wrong PIN" >&2; exit 1; }
    case "$3" in
      register)
        echo "credential-id cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        echo "public-key 04bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        echo "authenticator-data 0102"
        echo "attestation-object a3" ;;
      assert)
        echo "authenticator-data 0304"
        echo "signature-der 3006020101020101"
        echo "aaaa" ;;
    esac ;;
  "device key")
    case "$3" in
      list) [ -f "$D/keys" ] && cat "$D/keys" ;;
      *) [ "$PIN" = "2468" ] || { echo "device: wrong PIN" >&2; exit 1; }
         case "$3" in
           add) printf '%s\n' "$(printf %s "$5" | xxd -p)" >> "$D/keys"; echo "security key $5 added" ;;
           remove) grep -v "^$(printf %s "$5" | xxd -p)\$" "$D/keys" > "$D/keys.n"; mv "$D/keys.n" "$D/keys"; echo "removed" ;;
         esac ;;
    esac ;;
  "device ssh")
    case "$3" in
      list) printf '676974687562 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOxx github@laptop\n71756f72756d ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNy quorum\n' ;;
      *) [ "$PIN" = "2468" ] || { echo "device: wrong PIN" >&2; exit 1; }
         case "$3" in
           sign) echo "signature 0000000b7373682d6564323535313900000040aa" ;;
           new) echo "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNz $5" ;;
           *) echo "ok" ;;
         esac ;;
    esac ;;
  "device vault")
    [ "$PIN" = "2468" ] || { echo "device: wrong PIN" >&2; exit 1; }
    [ -f "$D/offline" ] && case "$3" in list|show|get) echo "device: local copy: no log at the relay; showing vault version 2 as this device last verified it" >&2 ;; *) echo "device: no log at the relay" >&2; exit 1 ;; esac
    case "$3" in
      list) case "$5" in
        --long) printf 'login 6d61696c 68747470733a2f2f6d61696c2e6578616d706c652e636f6d 576f726b2f456d61696c\nsecret 62616e6b -\ncard 76697361 31313131 46696e616e6365\n' ;;
        --kinds) printf 'login mail\nsecret bank\n' ;;
        *) printf 'mail\nbank\n' ;; esac ;;
      show) case "$5" in
        mail) printf 'type 6c6f67696e\nname 6d61696c\norigin 68747470733a2f2f6d61696c2e6578616d706c652e636f6d\nusername 616c696365\ncurrent 68756e74657232\n' ;;
        visa) printf 'type 63617264\nname 76697361\nnumber 34313131313131313131313131313131\ncvv 313233\ncustom_1 526577617264731f301f522d3432\n' ;;
        *) printf 'type 736563726574\nname 62616e6b\nsecret 733363726574\n' ;; esac ;;
      get) echo "hunter2" ;;
      *) echo "vault version 2, 2 items" ;;
    esac ;;
  "device share")
    A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    C=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    case "$3" in
      me) echo "$A 12345-67890-11111-22222-33333-44444"; exit 0 ;;
      people) printf '%s 416c696365 12345-67890-11111-22222-33333-44444 me\n%s 426f62 55555-66666-77777-88888-99999-00000 -\n%s 4361726f6c 13579-24680-11223-34455-66778-89900 -\n' "$A" "$B" "$C"; exit 0 ;;
    esac
    [ "$PIN" = "2468" ] || { echo "device: wrong PIN" >&2; exit 1; }
    case "$3" in
      list) printf '0123456789abcdef0123456789abcdef 46616d696c79 owner 2\nfedcba9876543210fedcba9876543210 - waiting 6e6f206b6579\n' ;;
      members) printf '%s 416c696365 12345-67890-11111-22222-33333-44444 owner\n%s 426f62 55555-66666-77777-88888-99999-00000 member\n' "$A" "$B" ;;
      new) echo "00112233445566778899aabbccddeeff" ;;
      card) echo "$A 12345-67890-11111-22222-33333-44444" ;;
      *) echo "shared folder version 3, 2 people" ;;
    esac ;;
  "device org")
    A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    O=0123456789abcdef0123456789abcdef
    case "$3" in
      show)
        [ -f "$D/org" ] || { echo "device: this device is in no organization (org join)" >&2; exit 1; }
        printf 'org %s 41636d65
version 3 gov 2
role %s
policy min_pin_len=6
recovery on 2/2 delay 259200
recovery-request 00112233445566778899aabbccddeeff %s 1800000000
' "$O" "$(cat "$D/org")" "$B"; exit 0 ;;
      members) printf '%s 416c696365 - owner -
%s 426f62 626f624061636d652e6578616d706c65 member -
' "$A" "$B"; exit 0 ;;
      groups) exit 0 ;;
      changes) printf '0123456789abcdef0123456789abcdef policy 6d61785f6f66666c696e655f64617973 37 - %s pending -\n' "$A"; exit 0 ;;
    esac
    [ "$PIN" = "2468" ] || { echo "device: wrong PIN" >&2; exit 1; }
    case "$3" in
      join) echo owner > "$D/org"; echo "$5 41636d65 member" ;;
      invite) echo "fedcba9876543210fedcba9876543210 11112222333344445555666677778888" ;;
      sync) echo "joined $B 626f62" ;;
      approve) echo "done" ;;
      *) echo "organization version 4, 2 people, 0 groups" ;;
    esac ;;
  *) echo "device: unknown command" >&2; exit 2 ;;
esac
''');
    await Process.run('chmod', ['+x', a.path]);
    return a;
  }

  Future<void> dispose() => dir.delete(recursive: true);
}
