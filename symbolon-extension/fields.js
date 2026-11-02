// Injected into each frame of the tab when the user asks for a fill (the
// toolbar button or Ctrl+Shift+L; never on a click in the page, SPEC 22.2).
// It finds the fields a login or a card fills and later fills them. It
// keeps nothing: the values arrive as the fill call's argument and are
// written into the fields.
//
// The kinds are the HTML autocomplete tokens the agent knows (SPEC 22.5):
// username, email, current-password, cc-name, cc-number, cc-exp,
// cc-exp-month, cc-exp-year, cc-csc.

(() => {
  if (globalThis.__symbolon) return;

  const KINDS = new Set(['username', 'email', 'current-password', 'cc-name', 'cc-number', 'cc-exp', 'cc-exp-month', 'cc-exp-year', 'cc-csc']);

  // Guesses from name, id, placeholder and label, for fields without an
  // autocomplete token. Card guesses first: "card number" is not a username.
  const GUESSES = [
    ['cc-number', /card.?(number|num|no\b)|cc.?num|cardnum|\bpan\b/i],
    ['cc-csc', /\b(cvc|cvv|csc|cvn)\b|security.?code|card.?verification/i],
    ['cc-exp-month', /exp\w*.?(month|mm\b)|cc.?month|card.?month/i],
    ['cc-exp-year', /exp\w*.?(year|yy)|cc.?year|card.?year/i],
    ['cc-exp', /expir|exp.?date|\bmm\s*\/\s*yy|valid.?thru/i],
    ['cc-name', /name.?on.?card|card.?holder|cc.?name|holder.?name/i],
  ];

  function visible(el) {
    if (el.disabled || el.readOnly) return false;
    if (el.type === 'hidden') return false;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    const s = getComputedStyle(el);
    return s.visibility !== 'hidden' && s.display !== 'none' && Number(s.opacity) > 0.05;
  }

  function token(el) {
    const parts = (el.getAttribute('autocomplete') || '').trim().toLowerCase().split(/\s+/);
    const last = parts[parts.length - 1];
    return KINDS.has(last) ? last : '';
  }

  function describe(el) {
    const label = el.labels && el.labels.length ? el.labels[0].textContent : '';
    return [el.name, el.id, el.placeholder, el.getAttribute('aria-label'), label].filter(Boolean).join(' ');
  }

  function guess(el) {
    const d = describe(el);
    for (const [kind, re] of GUESSES) if (re.test(d)) return kind;
    return '';
  }

  // The fillable fields of this frame, each with its kind.
  function scanFields() {
    const out = [];
    const els = [...document.querySelectorAll('input, select')].filter(visible);
    const passwords = els.filter((e) => e.type === 'password' && !/new-password/.test(e.getAttribute('autocomplete') || ''));
    for (const el of els) {
      let kind = token(el);
      if (!kind && el.type === 'password') kind = passwords[0] === el ? 'current-password' : '';
      if (!kind) kind = guess(el);
      if (!kind && el.tagName === 'INPUT' && (el.type === 'email' || el.type === 'text') && passwords.length) {
        // The text field just before the first password field in the same form.
        const form = passwords[0].form;
        const before = els.filter((e) => e.tagName === 'INPUT' && (e.type === 'email' || e.type === 'text') && e.form === form &&
          (e.compareDocumentPosition(passwords[0]) & Node.DOCUMENT_POSITION_FOLLOWING));
        if (before[before.length - 1] === el) kind = el.type === 'email' ? 'email' : 'username';
      }
      if (kind) out.push({ el, kind });
    }
    return out;
  }

  function scan() {
    return { origin: location.origin, kinds: [...new Set(scanFields().map((f) => f.kind))] };
  }

  // Sets a value the way typing does, so the page's own scripts see it.
  function setValue(el, v) {
    const proto = el.tagName === 'SELECT' ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
    el.focus();
    setter.call(el, v);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    el.blur();
  }

  // A select's option for a month ("08" or "8") or a year ("2029" or "29").
  function pick(el, kind, v) {
    const want = kind === 'cc-exp-month' ? [v, String(Number(v))] : [v, v.slice(2)];
    for (const o of el.options) if (want.includes(o.value.trim()) || want.includes(o.textContent.trim())) return o.value;
    return null;
  }

  function adapt(el, kind, v) {
    if (el.tagName === 'SELECT') return pick(el, kind, v);
    if (kind === 'cc-exp') {
      const room = el.maxLength > 0 ? el.maxLength : 99;
      if (/yyyy/i.test(el.placeholder || '') && room >= 7) return v.slice(0, 3) + '20' + v.slice(3);
      if (room === 4) return v.slice(0, 2) + v.slice(3);
    }
    return v;
  }

  // Fills the fields of this frame whose kinds have a value. Refuses if the
  // frame is no longer at the origin the user approved.
  function fill(expectedOrigin, values) {
    if (location.origin !== expectedOrigin) return { filled: 0, error: 'the frame moved to another site' };
    let filled = 0;
    for (const { el, kind } of scanFields()) {
      if (!(kind in values)) continue;
      const v = adapt(el, kind, values[kind]);
      if (v === null) continue;
      setValue(el, v);
      filled++;
    }
    return { filled };
  }

  Object.defineProperty(globalThis, '__symbolon', { value: Object.freeze({ scan, fill }) });
})();
