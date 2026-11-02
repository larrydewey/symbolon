// The extension's whole logic (SPEC 22.5). On the toolbar button or the
// shortcut it asks every frame of the tab which fields it has, sends the
// agent the page's origin and each frame's origin AS THE BROWSER REPORTS
// THEM, and fills what the agent returns after the user approved it in the
// Symbolon window. Nothing is stored; a fill's values live only in this
// call.

const HOST = 'dev.symbolon.browser';
let nextId = 1;

function originOf(url) {
  try {
    const o = new URL(url).origin;
    return o === 'null' ? '' : o;
  } catch {
    return '';
  }
}

async function badge(tabId, text, title) {
  await chrome.action.setBadgeText({ tabId, text });
  await chrome.action.setTitle({ tabId, title: title || 'Fill with Symbolon (Ctrl+Shift+L)' });
  if (text) setTimeout(() => chrome.action.setBadgeText({ tabId, text: '' }).catch(() => {}), 8000);
}

// Each frame's scan with the origin the browser has for it (not the one
// the page reports). A frame whose two disagree is left out.
async function scanFrames(tabId) {
  const nav = await chrome.webNavigation.getAllFrames({ tabId });
  const byId = new Map(nav.map((f) => [f.frameId, f]));
  await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, files: ['fields.js'] }).catch(() => []);
  const rs = await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, func: () => globalThis.__symbolon && globalThis.__symbolon.scan() }).catch(() => []);
  const out = [];
  for (const r of rs) {
    const f = byId.get(r.frameId);
    if (!f || !r.result || !r.result.kinds.length) continue;
    const origin = originOf(f.url);
    if (!origin || origin !== r.result.origin) continue;
    out.push({ frame: r.frameId, documentId: r.documentId || f.documentId, origin, fields: r.result.kinds });
  }
  return out;
}

async function fillTab(tab) {
  const tabId = tab.id;
  const top = originOf(tab.url);
  if (!top) return badge(tabId, '!', 'Symbolon: nothing to fill on this page');
  const frames = await scanFrames(tabId);
  if (!frames.length) return badge(tabId, '!', 'Symbolon: no login or card fields found');
  const id = nextId++;
  await badge(tabId, '…', 'Symbolon: approve the fill in the Symbolon window');
  let reply;
  try {
    reply = await chrome.runtime.sendNativeMessage(HOST, { type: 'fill', id, top, frames: frames.map(({ frame, origin, fields }) => ({ frame, origin, fields })) });
  } catch (e) {
    return badge(tabId, '!', 'Symbolon: the agent is not installed (' + e.message + ')');
  }
  if (!reply || reply.id !== id) return badge(tabId, '!', 'Symbolon: no answer');
  if (reply.type === 'cancel') return badge(tabId, '', '');
  if (reply.type === 'error') return badge(tabId, '!', 'Symbolon: ' + reply.error);
  // The page must still be where it was when the user approved.
  const now = await chrome.tabs.get(tabId);
  if (originOf(now.url) !== top) return badge(tabId, '!', 'Symbolon: the page changed; nothing was filled');
  let filled = 0;
  for (const f of reply.fills) {
    const asked = frames.find((x) => x.frame === f.frame);
    if (!asked) continue;
    const target = asked.documentId ? { tabId, documentIds: [asked.documentId] } : { tabId, frameIds: [f.frame] };
    const rs = await chrome.scripting.executeScript({ target, func: (o, v) => globalThis.__symbolon.fill(o, v), args: [asked.origin, f.values] }).catch(() => []);
    for (const r of rs) filled += (r.result && r.result.filled) || 0;
  }
  reply = null;
  return badge(tabId, filled ? '✓' : '!', filled ? '' : 'Symbolon: nothing was filled');
}

chrome.action.onClicked.addListener((tab) => {
  fillTab(tab).catch((e) => badge(tab.id, '!', 'Symbolon: ' + e.message));
});
