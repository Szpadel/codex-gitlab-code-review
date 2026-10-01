const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');
const { runInNewContext } = require('node:vm');

// Exercise the browser and fetch boundaries without a DOM dependency.
function transcriptPage(pathname, fetch) {
  const documentListeners = new Map();
  const entryListeners = new Map();
  const bodyListeners = new Map();
  const attributes = new Map();
  const entry = {
    open: false,
    addEventListener: (name, listener) => entryListeners.set(name, listener),
  };
  const body = {
    dataset: { transcriptBodyUrl: '/api/history/7/entries/42/body' },
    closest: () => entry,
    setAttribute: (name, value) => attributes.set(name, value),
    removeAttribute: (name) => attributes.delete(name),
    addEventListener: (name, listener) => bodyListeners.set(name, listener),
    append: (child) => { body.retry = child; },
  };
  const document = {
    addEventListener: (name, listener) => documentListeners.set(name, listener),
    querySelectorAll: () => [body],
    createElement: () => ({}),
  };
  const context = {
    document, fetch, URL,
    window: { location: { pathname, origin: 'https://review.example' } },
    console: { error() {} },
  };
  for (const file of ['feature_flag.js', 'transcript.js']) {
    runInNewContext(readFileSync(join(__dirname, '../src/http/assets', file), 'utf8'), context);
  }
  documentListeners.get('DOMContentLoaded')();
  return { entry, body, attributes, entryListeners, bodyListeners };
}

const settle = () => new Promise((resolve) => setImmediate(resolve));

for (const [pathname, expectedUrl] of [
  ['/history/7', 'https://review.example/api/history/7/entries/42/body'],
  ['/review/history/7/', 'https://review.example/review/api/history/7/entries/42/body'],
]) {
  test(`Opening an entry loads its body once at ${pathname}`, async () => {
    const requests = [];
    let finishResponse;
    const page = transcriptPage(pathname, (url, options) => {
      requests.push({ url: String(url), credentials: options.credentials });
      return new Promise((resolve) => { finishResponse = resolve; });
    });
    assert.equal(requests.length, 0);
    page.entry.open = true;
    page.entryListeners.get('toggle')();
    assert.match(page.body.textContent, /Loading entry body/);
    assert.equal(page.attributes.get('aria-busy'), 'true');
    page.entryListeners.get('toggle')();
    assert.deepEqual(requests, [{ url: expectedUrl, credentials: 'same-origin' }]);
    finishResponse({ ok: true, text: async () => '<pre>safe body</pre>' });
    await settle();
    assert.equal(page.body.innerHTML, '<pre>safe body</pre>');
    assert.equal(page.attributes.has('aria-busy'), false);
    page.entry.open = false;
    page.entryListeners.get('toggle')();
    page.entry.open = true;
    page.entryListeners.get('toggle')();
    assert.equal(requests.length, 1);
  });
}

for (const failure of [new Error('offline'), { ok: false, status: 503 }]) {
  test(`A failed body load exposes a retry: ${failure.message || failure.status}`, async () => {
    let requests = 0;
    const page = transcriptPage('/history/7', async () => {
      requests += 1;
      if (requests > 1) return { ok: true, text: async () => '<pre>recovered body</pre>' };
      if (failure instanceof Error) throw failure;
      return failure;
    });
    page.entry.open = true;
    page.entryListeners.get('toggle')();
    await settle();
    assert.match(page.body.textContent, /Entry body did not load/);
    assert.equal(page.body.retry.textContent, 'Retry');
    assert.equal(String(page.body.retry.href), 'https://review.example/api/history/7/entries/42/body');
    assert.equal(page.attributes.has('aria-busy'), false);
    let prevented = false;
    page.bodyListeners.get('click')({
      target: { closest: () => page.body.retry },
      preventDefault: () => { prevented = true; },
    });
    await settle();
    assert.equal(prevented, true);
    assert.equal(requests, 2);
    assert.equal(page.body.innerHTML, '<pre>recovered body</pre>');
  });
}
