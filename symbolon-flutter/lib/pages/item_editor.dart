import 'package:flutter/material.dart';

import '../app.dart';
import '../validate.dart' as v;
import '../vault_types.dart';
import '../widgets.dart';

/// Adding or editing a vault item: the type's fields, each checked as it is
/// typed, and fields of the user's own. Saving replaces the item; a rename
/// stores the new name, then deletes the old one.
class ItemEditor extends StatefulWidget {
  final App app;
  final ItemType type;
  final Set<String> names;             // the vault's names, to warn of a replacement
  final String? name;                  // editing this item
  final Map<String, String>? fields;   // its fields, from `vault show`
  final Set<String> folders;           // the vault's folders, offered as it is typed
  final String folder;                 // a new item's folder (the one being viewed)
  final String share;                  // the shared folder it is in, "" for the own vault
  const ItemEditor({super.key, required this.app, required this.type, required this.names, this.name, this.fields, this.folders = const {}, this.folder = '', this.share = ''});

  @override
  State<ItemEditor> createState() => _ItemEditorState();
}

class _Custom {
  final label = TextEditingController();
  final value = TextEditingController();
  bool hidden = false;
}

class _ItemEditorState extends State<ItemEditor> {
  final form = GlobalKey<FormState>();
  late final name = TextEditingController(text: widget.name ?? '');
  late final folder = TextEditingController(text: widget.fields?['folder'] ?? widget.folder);
  late final values = {for (final f in widget.type.fields) f.name: TextEditingController(text: widget.fields?[f.name] ?? '')};
  final custom = <_Custom>[];
  final revealed = <String>{};
  // Fields this editor does not show (a login's rotation state): kept as they are.
  late final Map<String, String> kept = {
    for (final e in (widget.fields ?? {}).entries)
      if (e.key != 'type' && e.key != 'name' && e.key != 'folder' && widget.type.field(e.key) == null && !CustomField.isCustom(e.key)) e.key: e.value,
  };

  App get app => widget.app;

  @override
  void initState() {
    super.initState();
    final cs = (widget.fields ?? {}).entries.where((e) => CustomField.isCustom(e.key)).toList()
      ..sort((a, b) => int.parse(a.key.substring(7)).compareTo(int.parse(b.key.substring(7))));
    for (final e in cs) {
      final c = CustomField.decode(e.value);
      custom.add(_Custom()
        ..label.text = c.label
        ..value.text = c.value
        ..hidden = c.hidden);
    }
    values['number']?.addListener(() => setState(() {}));
  }

  @override
  void dispose() {
    name.dispose();
    folder.dispose();
    _folderFocus.dispose();
    for (final c in values.values) {
      c.dispose();
    }
    for (final c in custom) {
      c.label.dispose();
      c.value.dispose();
    }
    super.dispose();
  }

  Future<void> save() async {
    FocusScope.of(context).unfocus();
    if (!form.currentState!.validate()) return toast(context, 'Check the fields marked in red.');
    final t = widget.type;
    final n = name.text.trim();
    final fields = <String, String>{...kept};
    for (final f in t.fields) {
      final text = values[f.name]!.text;
      if (text.trim().isNotEmpty) fields[f.name] = f.stored(text);
    }
    if (t.fields.every((f) => !fields.containsKey(f.name)) && custom.isEmpty) return toast(context, 'Fill in at least one field.');
    final fo = folder.text.trim().split('/').map((x) => x.trim()).where((x) => x.isNotEmpty).join('/');
    if (fo.isNotEmpty) fields['folder'] = fo;
    for (var i = 0; i < custom.length; i++) {
      fields['custom_${i + 1}'] = CustomField(custom[i].label.text.trim(), custom[i].value.text, hidden: custom[i].hidden).encode();
    }
    final renamed = widget.name != null && widget.name != n;
    if ((widget.name == null || renamed) && widget.names.contains(n)) {
      final replace = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: Text('Replace $n?'),
          content: const Text('Your vault already has an item with this name. Saving replaces it.'),
          actions: [
            TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('Cancel')),
            FilledButton(onPressed: () => Navigator.of(ctx).pop(true), child: const Text('Replace')),
          ],
        ),
      );
      if (replace != true || !mounted) return;
    }
    final r = await app.withPin(context, (p) => runTask(context, 'Saving $n', () async {
          final s = await app.cli.vaultSet(app.dir, n, t.id, fields, p, share: widget.share);
          if (!s.ok || !renamed) return s;
          return app.cli.vaultDelete(app.dir, widget.name!, p, share: widget.share);
        }, usually: 'a few seconds'));
    if (!mounted || r == null || !r.ok) return;
    final detail = switch (t.id) {
      'login' => fields['origin'] ?? '',
      'card' => (fields['number'] ?? '').length >= 4 ? fields['number']!.substring(fields['number']!.length - 4) : '',
      _ => '',
    };
    toast(context, '$n saved');
    Navigator.of(context).pop(VaultItem(n, t.id, detail: detail, folder: fo));
  }

  TextInputType _keyboard(Input i) => switch (i) {
        Input.digits => TextInputType.number,
        Input.email => TextInputType.emailAddress,
        Input.phone => TextInputType.phone,
        Input.url => TextInputType.url,
        Input.date => TextInputType.datetime,
        Input.multiline => TextInputType.multiline,
        _ => TextInputType.visiblePassword,
      };

  Widget _field(FieldSpec f) {
    final c = values[f.name]!;
    final hide = f.hidden && !revealed.contains(f.name);
    final brand = f.name == 'number' ? v.cardBrand(v.digitsOf(c.text)) : '';
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextFormField(
        key: Key('edit-${f.name}'),
        controller: c,
        obscureText: hide,
        keyboardType: _keyboard(f.input),
        maxLines: f.input == Input.multiline ? 6 : 1,
        minLines: f.input == Input.multiline ? 3 : 1,
        autocorrect: false,
        enableSuggestions: false,
        enableIMEPersonalizedLearning: false,
        smartDashesType: SmartDashesType.disabled,
        smartQuotesType: SmartQuotesType.disabled,
        autovalidateMode: AutovalidateMode.onUserInteraction,
        validator: (s) => f.validate(s ?? ''),
        decoration: InputDecoration(
          labelText: f.required ? '${f.label} *' : f.label,
          hintText: f.hint,
          helperText: brand.isEmpty ? null : brand,
          border: const OutlineInputBorder(),
          suffixIcon: f.hidden
              ? IconButton(
                  icon: Icon(hide ? Icons.visibility : Icons.visibility_off),
                  onPressed: () => setState(() => hide ? revealed.add(f.name) : revealed.remove(f.name)),
                )
              : null,
        ),
      ),
    );
  }

  // The folder: typed, with the vault's folders offered; "/" between levels.
  Widget _folderField() {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: RawAutocomplete<String>(
        textEditingController: folder,
        focusNode: _folderFocus,
        optionsBuilder: (v) {
          final q = v.text.trim().toLowerCase();
          return (widget.folders.toList()..sort()).where((f) => f.toLowerCase().contains(q) && f != v.text);
        },
        fieldViewBuilder: (context, c, focus, submit) => TextFormField(
          key: const Key('item-folder'),
          controller: c,
          focusNode: focus,
          autocorrect: false,
          validator: (s) => (s ?? '').length > 200 ? 'At most 200 characters' : ((s ?? '').contains('\n') ? 'One line only' : null),
          decoration: const InputDecoration(labelText: 'Folder', hintText: 'Work, or Work/Clients', border: OutlineInputBorder(), prefixIcon: Icon(Icons.folder_outlined)),
        ),
        optionsViewBuilder: (context, select, options) => Align(
          alignment: Alignment.topLeft,
          child: Material(
            elevation: 4,
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxHeight: 240, maxWidth: 400),
              child: ListView(shrinkWrap: true, padding: EdgeInsets.zero, children: [
                for (final o in options) ListTile(dense: true, leading: const Icon(Icons.folder_outlined), title: Text(o), onTap: () => select(o)),
              ]),
            ),
          ),
        ),
      ),
    );
  }

  final _folderFocus = FocusNode();

  Widget _customField(int i) {
    final c = custom[i];
    return Card(
      key: Key('custom-$i'),
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(12, 12, 4, 4),
        child: Column(children: [
          Row(children: [
            Expanded(
              child: TextFormField(
                key: Key('custom-label-$i'),
                controller: c.label,
                autocorrect: false,
                enableSuggestions: false,
                keyboardType: TextInputType.visiblePassword,
                autovalidateMode: AutovalidateMode.onUserInteraction,
                validator: (s) => CustomField.checkLabel(s ?? ''),
                decoration: const InputDecoration(labelText: 'Label', hintText: 'Membership number', border: OutlineInputBorder()),
              ),
            ),
            IconButton(tooltip: 'Remove field', icon: const Icon(Icons.close), onPressed: () => setState(() => custom.removeAt(i))),
          ]),
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.only(right: 8),
            child: TextFormField(
              key: Key('custom-value-$i'),
              controller: c.value,
              obscureText: c.hidden,
              autocorrect: false,
              enableSuggestions: false,
              keyboardType: TextInputType.visiblePassword,
              autovalidateMode: AutovalidateMode.onUserInteraction,
              maxLines: c.hidden ? 1 : 4,
              minLines: 1,
              validator: (s) => (s ?? '').trim().isEmpty ? 'A value is required' : (c.hidden && (s ?? '').contains('\n') ? 'One line only' : null),
              decoration: const InputDecoration(labelText: 'Value', border: OutlineInputBorder()),
            ),
          ),
          SwitchListTile(
            contentPadding: const EdgeInsets.only(right: 8),
            title: const Text('Hidden until shown'),
            value: c.hidden,
            onChanged: (x) => setState(() => c.hidden = x),
          ),
        ]),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final t = widget.type;
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.name == null ? 'New ${t.label.toLowerCase()}' : 'Edit ${widget.name}'),
        actions: [TextButton(key: const Key('item-save'), onPressed: save, child: const Text('Save'))],
      ),
      body: Form(
        key: form,
        child: PageBody(children: [
          Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: TextFormField(
              key: const Key('item-name'),
              controller: name,
              autocorrect: false,
              enableSuggestions: false,
              keyboardType: TextInputType.visiblePassword,
              autovalidateMode: AutovalidateMode.onUserInteraction,
              validator: (s) => v.itemName(s ?? ''),
              decoration: InputDecoration(labelText: 'Name *', hintText: switch (t.id) {
                'login' => 'Email',
                'card' => 'Everyday Visa',
                'identity' => 'Me',
                'wifi' => 'Home Wi-Fi',
                _ => null,
              }, border: const OutlineInputBorder()),
            ),
          ),
          _folderField(),
          for (final f in t.fields) _field(f),
          for (var i = 0; i < custom.length; i++) _customField(i),
          if (custom.length < CustomField.maxCount)
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                key: const Key('add-field'),
                onPressed: () => setState(() => custom.add(_Custom())),
                icon: const Icon(Icons.add),
                label: const Text('Add a field'),
              ),
            ),
          const SizedBox(height: 16),
          WideButton('Save', icon: Icons.check, onPressed: save),
        ]),
      ),
    );
  }
}
