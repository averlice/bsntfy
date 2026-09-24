const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};

let state = { acct: null, topic: null };

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  let data = null;
  try { data = await res.json(); } catch { /* non-json */ }
  if (!res.ok) {
    const err = new Error((data && data.error) || res.statusText);
    err.status = res.status;
    throw err;
  }
  return data;
}

function msg(id, text, kind = 'err') {
  const m = $(id);
  if (!m) return;
  m.textContent = text || '';
  m.className = 'msg ' + kind;
}

function instantiate(id) {
  const t = document.getElementById(id);
  return t.content.cloneNode(true);
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.append(ta);
    ta.select();
    try { document.execCommand('copy'); } catch { /* clipboard unavailable */ }
    ta.remove();
  }
  if (btn) {
    const old = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(() => (btn.textContent = old), 1500);
  }
}

function showModal(title, value, note) {
  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.append(instantiate('t-modal'));
  $('#modal-title', modal).textContent = title;
  $('#modal-value', modal).value = value;
  if (note) $('#modal-note', modal).textContent = note;
  $('#modal-copy', modal).addEventListener('click', () => copyText(value, $('#modal-copy', modal)));
  $('#modal-close', modal).addEventListener('click', () => modal.remove());
  modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
  document.body.append(modal);
}

const app = $('#app');

function renderAuth() {
  const root = instantiate('t-auth');
  let mode = 'login';
  let typedAcct = '';
  const tabs = [...root.querySelectorAll('.tab')];
  const btn = $('button[type=submit]', root);
  const $msg = $('#auth-msg', root);
  const numInput = $('input[name=accountNumber]', root);
  const pwInput = $('input[type=password]', root);
  const tabsEl = $('.tabs', root);
  const done = $('#reg-done', root);
  const doneAcct = $('#reg-acct', root);
  const doneCopy = $('#reg-copy', root);
  const doneContinue = $('#reg-continue', root);
  const formEl = $('form', root);

  const setMode = (m) => {
    mode = m;
    tabs.forEach((t) => t.classList.toggle('active', t.dataset.tab === m));
    btn.textContent = m === 'login' ? 'Log in' : 'Create account';
    if (m === 'login') {
      numInput.removeAttribute('readonly');
      numInput.setAttribute('required', '');
      numInput.placeholder = '';
      numInput.value = typedAcct;
    } else {
      numInput.setAttribute('readonly', '');
      numInput.removeAttribute('required');
      numInput.placeholder = 'Created for you when you click Create account';
      numInput.value = '';
    }
    pwInput.autocomplete = m === 'login' ? 'current-password' : 'new-password';
  };
  tabs.forEach((t) => t.addEventListener('click', () => setMode(t.dataset.tab)));
  setMode('register');

  formEl.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    btn.disabled = true;
    $msg.className = 'msg';
    $msg.textContent = '';
    try {
      if (mode === 'register') {
        const data = await api('/v1/register', { method: 'POST', body: JSON.stringify({ password: fd.get('password') }) });
        tabsEl.classList.add('hidden');
        e.target.classList.add('hidden');
        doneAcct.value = data.accountNumber;
        doneCopy.addEventListener('click', () => copyText(data.accountNumber, doneCopy));
        doneContinue.addEventListener('click', () => loadApp());
        done.classList.remove('hidden');
        return;
      }
      typedAcct = fd.get('accountNumber');
      await api('/v1/login', { method: 'POST', body: JSON.stringify({ accountNumber: typedAcct, password: fd.get('password') }) });
      loadApp();
    } catch (err) {
      msg('#auth-msg', err.message, 'err');
      btn.disabled = false;
    }
  });

  app.replaceChildren(root);
}

async function loadApp() {
  let info;
  try {
    info = await api('/v1/account');
  } catch {
    renderAuth();
    return;
  }
  state.acct = info.accountNumber;
  const root = instantiate('t-dash');
  $('#acct-label', root).textContent = 'Account ' + info.accountNumber;
  $('#logout', root).addEventListener('click', async () => {
    await api('/v1/logout', { method: 'POST' });
    renderAuth();
  });
  $('#show-pass', root).addEventListener('click', () => passwordPanel.classList.toggle('hidden'));
  const passwordPanel = $('#password-panel', root);
  $('#password-form', root).addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api('/v1/account/password', { method: 'POST', body: JSON.stringify({ oldPassword: fd.get('oldPassword'), newPassword: fd.get('newPassword') }) });
      e.target.reset();
      msg('#pass-msg', 'Password updated. Other tokens revoked.', 'ok');
    } catch (err) {
      msg('#pass-msg', err.message, 'err');
    }
  });
  $('#delete-acct-form', root).addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!confirm('Permanently delete your account and all of its data? This cannot be undone.')) return;
    const password = new FormData(e.target).get('password');
    try {
      await api('/v1/account', { method: 'DELETE', body: JSON.stringify({ password }) });
      renderAuth();
      msg('#auth-msg', 'Account deleted. You can create a new one any time.', 'ok');
    } catch (err) {
      msg('#delete-acct-msg', err.message, 'err');
    }
  });

  const view = $('#view', root);
  view.append(renderTopics());
  view.append(renderDevices());

  app.replaceChildren(root);
  await Promise.all([refreshTopics(), refreshDevices()]);
}

function renderTopics() {
  const root = instantiate('t-topic');
  $('#new-topic', root).addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = new FormData(e.target).get('name');
    try {
      await api('/v1/topics', { method: 'POST', body: JSON.stringify({ name }) });
      e.target.reset();
      await refreshTopics();
    } catch (err) {
      alert(err.message);
    }
  });
  return root;
}

async function refreshTopics() {
  const ul = $('#topic-list', app);
  const data = await api('/v1/topics');
  ul.replaceChildren();
  if (!data.topics.length) ul.append(el('li', 'empty', 'No topics yet. Create one to get started.'));
  for (const name of data.topics) {
    const li = el('li');
    const a = el('a', 'grow');
    a.href = '#';
    a.textContent = '/' + name;
    a.addEventListener('click', (e) => { e.preventDefault(); openTopic(name); });
    li.append(a);
    const del = el('button', 'ghost danger', '\u2715');
    del.title = 'Delete /' + name;
    del.addEventListener('click', async () => {
      if (!confirm('Delete /' + name + ' and all its API keys, subscribers, and feed?')) return;
      try {
        await api('/v1/topics/' + encodeURIComponent(name), { method: 'DELETE' });
        await refreshTopics();
      } catch (err) {
        alert(err.message);
      }
    });
    li.append(del);
    ul.append(li);
  }
}

function renderDevices() {
  const root = instantiate('t-devices');
  const form = $('#device-form', root);
  const pairCodeEl = $('#pair-code', root);
  const pairExpEl = $('#pair-exp', root);
  $('#new-device', root).addEventListener('click', () => form.classList.toggle('hidden'));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(form);
    try {
      const r = await api('/v1/device-tokens', { method: 'POST', body: JSON.stringify({ label: fd.get('label'), scope: fd.get('scope') }) });
      showModal('Device token', r.token, 'Shown once — ' + r.scope + ' token, expires ' + new Date(r.expiresAt).toLocaleDateString() + '.');
      form.classList.add('hidden');
      form.reset();
      await refreshDevices();
    } catch (err) {
      alert(err.message);
    }
  });
  $('#gen-pair', root).addEventListener('click', async () => {
    try {
      const r = await api('/v1/pair-codes', { method: 'POST' });
      pairCodeEl.textContent = r.code;
      pairCodeEl.classList.remove('hidden');
      let timer = 0;
      const tick = () => {
        clearTimeout(timer);
        const s = Math.ceil((r.expiresAt - Date.now()) / 1000);
        if (s <= 0) {
          pairExpEl.textContent = 'expired';
          return;
        }
        pairExpEl.textContent = 'expires in ' + Math.floor(s / 60) + 'm ' + String(s % 60).padStart(2, '0') + 's';
        timer = setTimeout(tick, 1000);
      };
      tick();
    } catch (err) {
      msg('#pair-msg', err.message, 'err');
    }
  });
  return root;
}

async function refreshDevices() {
  const ul = $('#device-list', app);
  const data = await api('/v1/device-tokens');
  ul.replaceChildren();
  if (!data.tokens.length) ul.append(el('li', 'empty', 'No device tokens yet. Create one for your app, or pair an app below.'));
  for (const t of data.tokens) {
    const li = el('li');
    const idEl = el('code', 'grow', t.id);
    idEl.title = 'Token ID — the full token was shown once when created and is not stored again';
    li.append(idEl);
    li.append(el('span', 'badge ' + (t.scope === 'manage' ? '' : 'on'), t.scope));
    if (t.label) li.append(el('span', 'badge', t.label));
    li.append(el('span', 'muted', 'expires ' + new Date(t.expiresAt).toLocaleDateString()));
    const del = el('button', 'ghost', '\u2715');
    del.title = 'Revoke this token';
    del.addEventListener('click', async () => {
      await api('/v1/device-tokens/' + t.id, { method: 'DELETE' });
      await refreshDevices();
    });
    li.append(del);
    ul.append(li);
  }
}

async function openTopic(name) {
  state.topic = name;
  const root = instantiate('t-detail');
  $('#d-name', root).textContent = name;
  const publishForm = $('#publish-form', root);
  const curlHelp = $('#curl-help', root);
  $('#back', root).addEventListener('click', () => {
    state.topic = null;
    renderDashTopics();
  });
  publishForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = new FormData(e.target).get('message');
    try {
      await api('/v1/publish/' + encodeURIComponent(name), { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: text });
      msg('#publish-msg', 'Published.', 'ok');
      publishForm.reset();
      await refreshFeed(view, name);
    } catch (err) {
      msg('#publish-msg', 'Publish failed: ' + err.message, 'err');
    }
  });
  $('#key-form', root).addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const r = await api('/v1/topics/' + encodeURIComponent(name) + '/keys', {
        method: 'POST',
        body: JSON.stringify({ label: fd.get('label'), perms: fd.get('perms') }),
      });
      showModal('API key for /' + name, r.key, 'Shown once — publish with Authorization: Bearer ' + r.key.slice(0, 4) + '...');
      e.target.reset();
      await refreshKeys(view, name);
    } catch (err) {
      alert(err.message);
    }
  });
  $('#delete-topic-btn', root).addEventListener('click', async () => {
    if (!confirm('Delete /' + name + '? Its API keys, subscribers, and feed are removed.')) return;
    try {
      await api('/v1/topics/' + encodeURIComponent(name), { method: 'DELETE' });
      renderDashTopics();
    } catch (err) {
      msg('#delete-topic-msg', err.message, 'err');
    }
  });

  const view = $('#view', app);
  view.replaceChildren(root);
  await Promise.all([refreshFeed(view, name), refreshKeys(view, name), refreshSubs(view, name)]);

  const origin = location.origin;
  curlHelp.textContent = [
    `curl -X POST "${origin}/v1/publish/${name}" \\`,
    `  -H 'Authorization: Bearer fy_...' \\`,
    `  -H 'Content-Type: text/plain' \\`,
    `  -d 'hello from curl'`,
  ].join('\n');
}

function renderDashTopics() {
  const root = instantiate('t-topic');
  const view = $('#view', app);
  view.replaceChildren(root);
  refreshTopics();
}

async function refreshFeed(root, name) {
  const ul = $('#feed-list', root);
  const data = await api('/v1/messages/' + encodeURIComponent(name));
  ul.replaceChildren();
  if (!data.messages.length) ul.append(el('li', 'empty', 'No messages yet.'));
  for (const m of data.messages) {
    const li = el('li');
    const span = el('span', 'grow', m.body);
    li.append(span);
    li.append(el('span', 'muted', new Date(m.time).toLocaleString()));
    ul.append(li);
  }
}

async function refreshKeys(root, name) {
  const ul = $('#key-list', root);
  const data = await api('/v1/topics/' + encodeURIComponent(name) + '/keys');
  ul.replaceChildren();
  if (!data.keys.length) ul.append(el('li', 'empty', 'No keys yet.'));
  for (const k of data.keys) {
    const li = el('li');
    const idEl = el('code', 'grow muted', k.id);
    idEl.title = 'Key ID — the full key was shown once when created and is not stored again';
    li.append(idEl);
    li.append(el('span', 'badge', k.perms));
    if (k.label) li.append(el('span', 'badge', k.label));
    const del = el('button', 'ghost', '\u2715');
    del.title = 'Delete this key';
    del.addEventListener('click', async () => {
      await api('/v1/topics/' + encodeURIComponent(name) + '/keys/' + k.id, { method: 'DELETE' });
      await refreshKeys(root, name);
    });
    li.append(del);
    ul.append(li);
  }
}

async function refreshSubs(root, name) {
  const ul = $('#sub-list', root);
  const data = await api('/v1/topics/' + encodeURIComponent(name) + '/subscribers');
  ul.replaceChildren();
  if (!data.subscribers.length) ul.append(el('li', 'empty', 'No subscribers yet. Subscribe from the app with a device token.'));
  for (const s of data.subscribers) {
    const li = el('li');
    li.append(el('code', 'grow', s.endpoint));
    li.append(el('span', 'badge ' + (s.encrypted ? 'on' : ''), s.encrypted ? 'encrypted' : 'plain'));
    const del = el('button', 'ghost danger', '\u2715');
    del.title = 'Remove this subscriber';
    del.addEventListener('click', async () => {
      if (!confirm('Remove this subscriber?')) return;
      try {
        await api('/v1/topics/' + encodeURIComponent(name) + '/subscribers/' + s.id, { method: 'DELETE' });
        await refreshSubs(root, name);
      } catch (err) {
        alert(err.message);
      }
    });
    li.append(del);
    ul.append(li);
  }
}

function boot() {
  loadApp();
}

boot();