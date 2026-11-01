// What the organization's device management sets for the app (SPEC 29.9):
// Android managed configurations (app_restrictions.xml), read through the
// platform channel. It carries no keys: the organization to join, its
// founder's log id (which binds the organization's id), an invite code,
// and settings the policy fixes.

import 'dart:io';

import 'package:flutter/services.dart';

class ManagedConfig {
  final String orgId;
  final String founder;
  final String inviteCode;
  final bool noDuress;
  const ManagedConfig({this.orgId = '', this.founder = '', this.inviteCode = '', this.noDuress = false});

  bool get hasOrg => orgId.length == 32 && founder.length == 64;

  static ManagedConfig fromMap(Map<String, dynamic> m) => ManagedConfig(
        orgId: (m['org_id'] as String? ?? '').trim().toLowerCase(),
        founder: (m['org_founder'] as String? ?? '').trim().toLowerCase(),
        inviteCode: (m['invite_code'] as String? ?? '').trim().toLowerCase(),
        noDuress: m['disable_duress'] == true,
      );

  static Future<ManagedConfig> read() async {
    if (!Platform.isAndroid) return const ManagedConfig();
    try {
      final m = await const MethodChannel('symbolon/platform').invokeMapMethod<String, dynamic>('managedConfig') ?? {};
      return fromMap(m);
    } on PlatformException {
      return const ManagedConfig();
    } on MissingPluginException {
      return const ManagedConfig();
    }
  }
}
