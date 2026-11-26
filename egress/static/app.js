'use strict';

const $ = (id) => document.getElementById(id);
const POLL_MS = 2000;

let snap = null;
let connFilter = '';
const lastSig = { pending: null, conns: null, rules: null, log: null };
let lastPointer = 0;

// Replacing a button between mousedown and mouseup swallows the click, so a
// poll that lands while the pointer is down is deferred to the next tick.
document.addEventListener('pointerdown', () => { lastPointer = Date.now(); }, true);

/* ------------------------------------------------------------------ utils */

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));

function fmtBytes(n) {
  if (!n) return '0';
  const u = ['B', 'K', 'M', 'G'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)) + u[i];
}

function hhmmss(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleTimeString([], { hour12: false });
}

function rel(iso) {
  if (!iso) return '';
  const ms = new Date(iso).getTime() - Date.now();
  if (isNaN(ms)) return '';
  const s = Math.round(ms / 1000);
  if (s <= 0) return 'expired';
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  return `${(s / 3600).toFixed(1)}h`;
}

let toastTimer = null;
function toast(msg, bad = false) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.toggle('bad', bad);
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2600);
}

async function api(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  let data = {};
  try { data = await res.json(); } catch (_) { /* ignore */ }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

/* --------------------------------------------------------------- rendering */

function renderStatus(s) {
  const st = s.status;
  $('statusDot').classList.toggle('off', !st.ok || st.killswitch);
  document.body.classList.toggle('killed', st.killswitch);

  const kill = $('killBtn');
  kill.textContent = st.killswitch ? 'Release kill switch' : 'Kill switch';
  kill.classList.toggle('danger', !st.killswitch);
  kill.classList.toggle('warn', st.killswitch);

  const chips = [];
  chips.push(`<span class="chip ${st.ok ? 'on' : ''}">${st.ok ? 'enforcing' : 'error'}</span>`);
  chips.push(`<span class="chip">src <b>${esc(st.sources.join(', '))}</b></span>`);
  chips.push(`<span class="chip">lab <b>${esc(st.labs.join(', ') || '—')}</b></span>`);
  const names = Object.values(s.containers || {});
  if (names.length) {
    chips.push(`<span class="chip">${names.map((n) => `<b>${esc(n)}</b>`).join(' ')}</span>`);
  }
  $('meta').innerHTML = chips.join('');

  const banner = $('errorBanner');
  if (st.ok) {
    banner.hidden = true;
  } else {
    banner.hidden = false;
    banner.textContent = st.error
      ? 'nftables error — rules may not be enforced: ' + st.error
      : 'Kill switch DNS isolation not verified: ' + st.dns_error;
  }
}

function renderPending(list) {
  const sig = JSON.stringify(list.map((p) => [p.key, p.count, p.last_seen]));
  if (sig === lastSig.pending) return;
  lastSig.pending = sig;

  const box = $('pendingList');
  $('pendingCount').textContent = list.length;
  $('pendingCount').classList.toggle('hot', list.length > 0);

  if (!list.length) {
    box.innerHTML = '<div class="empty">Nothing waiting. Every new destination shows up here.</div>';
    return;
  }

  box.innerHTML = list.map((p) => {
    const port = p.port ? `:${p.port}` : '';
    const srcs = p.sources.join(', ');
    return `<div class="card" data-key="${esc(p.key)}">
      <div class="card-top">
        <span class="ip">${esc(p.dst)}</span><span class="port">${esc(port)}</span>
        <span class="pill ${esc(p.proto)}">${esc(p.proto)}</span>
      </div>
      <div class="card-sub" title="first seen ${esc(p.first_seen)}">${p.count} attempt${p.count === 1 ? '' : 's'} · from ${esc(srcs || '—')} · ${hhmmss(p.last_seen)}</div>
      <div class="card-actions">
        <button class="btn ok" data-act="allow" data-ttl="0">Allow</button>
        <button class="btn ghost" data-act="allow" data-ttl="3600">1 h</button>
        <button class="btn ghost" data-act="allow" data-ttl="600">10 m</button>
        <button class="btn danger" data-act="block">Block</button>
        <button class="btn ghost" data-act="clear">Dismiss</button>
      </div>
    </div>`;
  }).join('');
}

function renderConnections(list, force) {
  const sig = JSON.stringify(list.map((c) => [c.src, c.dst, c.dport, c.proto, c.state, c.bytes, c.packets]));
  if (!force && sig === lastSig.conns) return;
  lastSig.conns = sig;

  const rows = list.filter((c) => {
    if (!connFilter) return true;
    const hay = `${c.dst} ${c.dport} ${c.proto} ${c.state} ${c.container || ''}`.toLowerCase();
    return hay.includes(connFilter);
  });

  $('connCount').textContent = list.length;
  const body = $('connBody');

  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">${list.length ? 'No match.' : 'No live connections.'}</td></tr>`;
    return;
  }

  body.innerHTML = rows.map((c, i) => `<tr>
    <td class="dst">${esc(c.dst)}<span class="port">:${esc(c.dport)}</span></td>
    <td><span class="pill ${esc(c.proto)}">${esc(c.proto)}</span></td>
    <td><span class="st ${c.state === 'UNREPLIED' ? 'unrep' : ''}">${esc(c.state || '—')}</span></td>
    <td class="num">${fmtBytes(c.bytes)}</td>
    <td class="num">${c.packets || 0}</td>
    <td><button class="x" title="Kill this connection"
      data-kill="${i}" data-src="${esc(c.src)}" data-dst="${esc(c.dst)}"
      data-sport="${esc(c.sport)}" data-dport="${esc(c.dport)}" data-proto="${esc(c.proto)}">×</button></td>
  </tr>`).join('');
}

function renderRules(list) {
  const sig = JSON.stringify(list.map((r) => [r.id, r.action, r.dst, r.port, r.proto, r.note, r.expires]));
  if (sig === lastSig.rules) return;
  lastSig.rules = sig;

  $('ruleCount').textContent = list.length;
  const box = $('rulesList');

  if (!list.length) {
    box.innerHTML = '<div class="empty">No rules yet. The cage is fully closed.</div>';
    return;
  }

  box.innerHTML = list.map((r) => `<div class="row">
    <span class="tag ${esc(r.action)}">${r.action === 'allow' ? 'ALLOW' : 'BLOCK'}</span>
    <span class="dest">${esc(r.dst)}${r.port ? ':' + esc(r.port) : ''}</span>
    <span class="pill ${esc(r.proto)}">${esc(r.proto)}</span>
    ${r.expires ? `<span class="exp">${rel(r.expires)}</span>` : ''}
    <span class="note" title="${esc(r.note)}">${esc(r.note || '')}</span>
    <button class="x" data-del="${esc(r.id)}" title="Remove rule">×</button>
  </div>`).join('');
}

const KIND_LABEL = {
  deny: 'DENY', host_denied: 'HOST', allow: 'ALLOW', block: 'BLOCK',
  unblock: 'REMOVE', expire: 'EXPIRE', killswitch_on: 'KILL', killswitch_off: 'RELEASE',
  killswitch_dns_error: 'ERROR', kill_drop: 'KILLED', conntrack_kill: 'DROP',
};

const flowsCut = (ev) => (ev.flows ? ` — ${ev.flows} live flow${ev.flows === 1 ? '' : 's'} dropped` : '');

function describe(ev) {
  switch (ev.kind) {
    case 'allow':
      return `<b>${esc(ev.dst)}${ev.port ? ':' + esc(ev.port) : ''}</b> ${esc(ev.proto)} approved${ev.ttl ? ` for ${Math.round(ev.ttl / 60)}m` : ''}${ev.note ? ' — ' + esc(ev.note) : ''}`;
    case 'block':
      return `<b>${esc(ev.dst)}${ev.port ? ':' + esc(ev.port) : ''}</b> ${esc(ev.proto)} blocked${ev.note ? ' — ' + esc(ev.note) : ''}${flowsCut(ev)}`;
    case 'unblock':
      return ev.dst
        ? `rule removed: <b>${esc(ev.dst)}${ev.port ? ':' + esc(ev.port) : ''}</b> ${esc(ev.proto)}${flowsCut(ev)}`
        : `rule removed`;
    case 'expire':
      return ev.dst
        ? `time-limited rule expired: <b>${esc(ev.dst)}${ev.port ? ':' + esc(ev.port) : ''}</b> ${esc(ev.proto)}${flowsCut(ev)}`
        : `time-limited rule expired`;
    case 'killswitch_on': {
      const bits = [];
      if (ev.flows) bits.push(`${ev.flows} flow${ev.flows === 1 ? '' : 's'} cleared`);
      if (ev.frozen?.length) bits.push(`frozen: ${ev.frozen.map(esc).join(', ')}`);
      return `kill switch engaged — every packet to or from the cage and lab is dropped${bits.length ? ` (${bits.join('; ')})` : ''}`;
    }
    case 'killswitch_off':
      return `kill switch released${ev.thawed?.length ? ` — resumed ${ev.thawed.map(esc).join(', ')}` : ''}`;
    case 'killswitch_dns_error':
      return `kill switch DNS check failed: ${esc(ev.detail)}`;
    case 'conntrack_kill':
      return `${esc(ev.dst || '')}${ev.dport ? ':' + esc(ev.dport) : ''} connection ${ev.ok ? 'killed' : 'kill failed'}`;
    default:
      return `<b>${esc(ev.src || '?')}</b> → ${esc(ev.dst)}${ev.port ? ':' + esc(ev.port) : ''} ${esc(ev.proto)}`;
  }
}

function renderLog(events) {
  const box = $('logList');
  const list = events.slice(-120).reverse();
  if (!list.length) {
    box.innerHTML = '<div class="empty">No events yet.</div>';
    return;
  }
  const key = list.length + '|' + (list[0]?.t || '');
  if (key === lastSig.log) return;
  lastSig.log = key;

  box.innerHTML = list.map((ev) => `<div class="logline">
    <span class="t">${hhmmss(ev.t)}</span>
    <span class="k ${esc(ev.kind)}">${KIND_LABEL[ev.kind] || esc(ev.kind)}</span>
    <span class="d">${describe(ev)}</span>
  </div>`).join('');
}

/* -------------------------------------------------------------------- poll */

async function refresh() {
  try {
    const res = await fetch('/api/snapshot', { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    snap = await res.json();
    renderStatus(snap);
    if (Date.now() - lastPointer < 1500) return;   // do not swap the DOM under a click
    renderPending(snap.pending);
    renderConnections(snap.connections);
    renderRules(snap.rules);
    renderLog(snap.events);
  } catch (err) {
    $('statusDot').classList.add('off');
    $('errorBanner').hidden = false;
    $('errorBanner').textContent = 'Cannot reach the egress daemon: ' + err.message;
  }
}

/* ----------------------------------------------------------------- actions */

$('pendingList').addEventListener('click', async (ev) => {
  const btn = ev.target.closest('button[data-act]');
  if (!btn) return;
  const card = btn.closest('.card');
  const key = card.dataset.key;
  const item = (snap?.pending || []).find((p) => p.key === key);
  if (!item) return;

  const act = btn.dataset.act;
  btn.disabled = true;
  try {
    if (act === 'clear') {
      await api('/api/pending/clear', { key });
      toast('Dismissed — it returns if the agent tries again');
    } else {
      await api(`/api/${act}`, {
        dst: item.dst,
        port: item.port,
        proto: item.proto,
        ttl: Number(btn.dataset.ttl || 0),
      });
      toast(act === 'allow'
        ? `Allowed ${item.dst}${item.port ? ':' + item.port : ''}`
        : `Blocked ${item.dst}${item.port ? ':' + item.port : ''}`);
    }
    await refresh();
  } catch (err) {
    toast(err.message, true);
  } finally {
    btn.disabled = false;
  }
});

$('connBody').addEventListener('click', async (ev) => {
  const btn = ev.target.closest('button[data-kill]');
  if (!btn) return;
  btn.disabled = true;
  try {
    const out = await api('/api/conntrack/delete', {
      src: btn.dataset.src,
      dst: btn.dataset.dst,
      sport: btn.dataset.sport,
      dport: btn.dataset.dport,
      proto: btn.dataset.proto,
    });
    toast(out.ok ? 'Connection dropped' : 'Could not drop: ' + (out.detail || 'unknown'), !out.ok);
    await refresh();
  } catch (err) {
    toast(err.message, true);
  } finally {
    btn.disabled = false;
  }
});

$('rulesList').addEventListener('click', async (ev) => {
  const btn = ev.target.closest('button[data-del]');
  if (!btn) return;
  btn.disabled = true;
  try {
    await api('/api/rule/delete', { id: btn.dataset.del });
    toast('Rule removed');
    await refresh();
  } catch (err) {
    toast(err.message, true);
  }
});

$('killBtn').addEventListener('click', async () => {
  const on = !(snap?.status?.killswitch);
  if (on && !confirm('Drop every packet to and from the ARTEX and lab networks (including established connections) and freeze the cage containers?')) return;
  try {
    await api('/api/killswitch', { on });
    toast(on ? 'Kill switch engaged' : 'Kill switch released');
    await refresh();
  } catch (err) {
    toast(err.message, true);
  }
});

$('connFilter').addEventListener('input', (ev) => {
  connFilter = ev.target.value.trim().toLowerCase();
  if (snap) renderConnections(snap.connections, true);
});

$('downloadBtn').addEventListener('click', () => {
  window.location.href = '/api/events';
});

/* ---------------------------------------------------------------- add rule */

const dlg = $('addDialog');
$('addRuleBtn').addEventListener('click', () => dlg.showModal());

$('addForm').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const submitter = ev.submitter;
  if (submitter && submitter.value === 'cancel') { dlg.close(); return; }
  try {
    const action = $('fAction').value;
    await api(`/api/${action}`, {
      dst: $('fDst').value.trim(),
      port: Number($('fPort').value),
      proto: $('fProto').value,
      ttl: 0,
      note: $('fNote').value.trim(),
    });
    dlg.close();
    $('addForm').reset();
    toast('Rule saved');
    await refresh();
  } catch (err) {
    toast(err.message, true);
  }
});

/* -------------------------------------------------------------------- boot */

refresh();
setInterval(() => {
  if (document.visibilityState === 'visible') refresh();
}, POLL_MS);

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') refresh();
});
