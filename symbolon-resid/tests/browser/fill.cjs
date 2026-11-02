// Drives Chromium with the unpacked extension for tests/browser_e2e.sh:
//   node fill.cjs PROFILE EXTENSION PORT URL
// Opens URL, does what the toolbar button does (fillTab in the extension's
// service worker), and prints one JSON line: every frame's field values
// and the button's title (where an error is shown).
const { chromium } = require('playwright');

(async () => {
  const [profile, ext, port, url] = process.argv.slice(2);
  const ctx = await chromium.launchPersistentContext(profile, {
    executablePath: process.env.CHROMIUM || '/usr/bin/chromium',
    headless: true,
    args: [
      '--headless=new',
      `--disable-extensions-except=${ext}`,
      `--load-extension=${ext}`,
      `--host-resolver-rules=MAP * 127.0.0.1:${port}`,
      '--ignore-certificate-errors',
    ],
  });
  let sw = ctx.serviceWorkers()[0];
  if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 15000 });
  const page = ctx.pages()[0] || (await ctx.newPage());
  await page.goto(url);
  await page.waitForLoadState('load');
  for (const f of page.frames()) await f.waitForLoadState('load');
  const title = await sw.evaluate(async () => {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    const scanned = (await scanFrames(tab.id)).map((f) => f.origin + ' ' + f.fields.join(','));
    await fillTab(tab);
    return { title: await chrome.action.getTitle({ tabId: tab.id }), scanned };
  });
  const frames = {};
  for (const f of page.frames()) {
    const host = new URL(f.url()).host;
    frames[host === 'shop.example' && f !== page.mainFrame() ? 'sub' : host] = await f.evaluate(() =>
      Object.fromEntries([...document.querySelectorAll('input')].map((e) => [e.id, e.value])));
  }
  console.log(JSON.stringify({ title: title.title, scanned: title.scanned, frames }));
  await ctx.close();
})().catch((e) => {
  console.log(JSON.stringify({ error: String(e) }));
  process.exit(1);
});
