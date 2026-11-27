// Coffeo engine 1.0.0-alpha.3 (step 2a: adds video layers)
// Does: read ZIP/folder, validate (spec 0.1), store locally (OPFS), apply fonts + static page layers + Tier A UI,
// site map from script attributes, host policy (visitor | locked). Not yet: worker import, video, audio, interactions, text effects.
const VERSION = '1.0.0-alpha.3';
const MAX_VIDEOS = 1; // device tier 1 limit; the Governor will raise or lower this later
const L = { zip: 100 << 20, total: 200 << 20, entry: 50 << 20, count: 300, json: 256 << 10 };
const KNOWN = ['page.background', 'page.foreground', 'ui.topbar', 'ui.ribbon', 'ui.bottombar', 'ui.panel', 'ui.chatbox', 'ui.card', 'ui.button', 'ui.input', 'text.heading', 'text.body', 'text.link', 'text.caption'];
export const isTarget = t => typeof t === 'string' && (/^x\.[a-z0-9-]+\.[a-z0-9-]+$/.test(t) || KNOWN.includes(t.split(':')[0]) && /^[a-z.-]+(:[a-z0-9-]+)?$/.test(t));
const FALLBACK = ['system-ui', 'sans-serif', 'serif', 'monospace', 'ui-monospace', 'cursive'];

// ---------- paths, checksums ----------
export function safePath(p) {
  if (typeof p !== 'string' || !p || p.length > 200) return null;
  if (/[\\\u0000-\u001f]/.test(p) || /^\//.test(p) || /^[a-zA-Z]:/.test(p) || /(^|\/)\.{1,2}(\/|$)/.test(p) || /\/\//.test(p)) return null;
  return p;
}
const T = new Uint32Array(256).map((_, i) => { let c = i; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
const crc32 = u => { let c = -1; for (let i = 0; i < u.length; i++) c = T[(c ^ u[i]) & 255] ^ (c >>> 8); return (c ^ -1) >>> 0; };

// ---------- entry sources: ZIP and folder -> Map(path -> Uint8Array) ----------
export async function readZip(blob) {
  if (blob.size > L.zip) throw new Error('ZIP is larger than the 100 MB limit');
  const tail = new DataView(await blob.slice(Math.max(0, blob.size - 65557)).arrayBuffer());
  let e = -1;
  for (let i = tail.byteLength - 22; i >= 0; i--) if (tail.getUint32(i, true) === 0x06054b50) { e = i; break; }
  if (e < 0) throw new Error('Not a ZIP file');
  const n = tail.getUint16(e + 10, true), cdSize = tail.getUint32(e + 12, true), cdOff = tail.getUint32(e + 16, true);
  if (n === 0xffff || cdOff === 0xffffffff) throw new Error('ZIP64 archives are not supported yet');
  if (n > L.count) throw new Error('Too many files in ZIP');
  const cd = new DataView(await blob.slice(cdOff, cdOff + cdSize).arrayBuffer());
  const td = new TextDecoder('utf-8', { fatal: true }), list = [], seen = new Set();
  let o = 0, total = 0;
  for (let i = 0; i < n; i++) {
    if (o + 46 > cd.byteLength || cd.getUint32(o, true) !== 0x02014b50) throw new Error('Corrupt ZIP directory');
    const made = cd.getUint16(o + 4, true) >> 8, flag = cd.getUint16(o + 8, true), meth = cd.getUint16(o + 10, true);
    const crc = cd.getUint32(o + 16, true), cs = cd.getUint32(o + 20, true), us = cd.getUint32(o + 24, true);
    const nl = cd.getUint16(o + 28, true), xl = cd.getUint16(o + 30, true), cl = cd.getUint16(o + 32, true);
    const ext = cd.getUint32(o + 38, true), off = cd.getUint32(o + 42, true);
    let name;
    try { name = td.decode(new Uint8Array(cd.buffer, o + 46, nl)); } catch { throw new Error('Invalid file name in ZIP'); }
    o += 46 + nl + xl + cl;
    if (name.endsWith('/')) continue;
    if (flag & 1) throw new Error('Encrypted ZIP entries are not allowed');
    if (made === 3 && ((ext >>> 16) & 0xf000) === 0xa000) throw new Error('Symbolic links are not allowed: ' + name);
    const p = safePath(name);
    if (!p) throw new Error('Unsafe file path in ZIP: ' + name);
    const k = p.normalize('NFC').toLowerCase();
    if (seen.has(k)) throw new Error('Duplicate file path: ' + p);
    seen.add(k);
    if (us > L.entry) throw new Error('File too large (over 50 MB): ' + p);
    total += us;
    if (total > L.total) throw new Error('ZIP expands beyond the 200 MB limit');
    list.push({ p, meth, crc, cs, us, off });
  }
  const files = new Map();
  let got = 0;
  for (const f of list) {
    const lh = new DataView(await blob.slice(f.off, f.off + 30).arrayBuffer());
    if (lh.getUint32(0, true) !== 0x04034b50) throw new Error('Corrupt ZIP entry: ' + f.p);
    const a = f.off + 30 + lh.getUint16(26, true) + lh.getUint16(28, true), raw = blob.slice(a, a + f.cs);
    let s;
    if (f.meth === 0) s = raw.stream();
    else if (f.meth === 8) s = raw.stream().pipeThrough(new DecompressionStream('deflate-raw'));
    else throw new Error('Unsupported compression in ' + f.p);
    const rd = s.getReader(), ch = [];
    let len = 0;
    for (;;) {
      const { done, value } = await rd.read();
      if (done) break;
      len += value.length; got += value.length;
      if (len > f.us || got > L.total) { rd.cancel(); throw new Error('ZIP content does not match its declared size: ' + f.p); }
      ch.push(value);
    }
    if (len !== f.us) throw new Error('ZIP content does not match its declared size: ' + f.p);
    const u = new Uint8Array(len);
    let q = 0;
    for (const c of ch) { u.set(c, q); q += c.length; }
    if (crc32(u) !== f.crc) throw new Error('Checksum mismatch: ' + f.p);
    files.set(f.p, u);
  }
  return files;
}

export async function readFolder(fileList) {
  const files = new Map(), seen = new Set();
  let total = 0;
  const arr = [...fileList];
  if (arr.length > L.count) throw new Error('Too many files in folder');
  for (const f of arr) {
    const rel = (f.webkitRelativePath || f.name).split('/').slice(1).join('/');
    if (!rel || /(^|\/)(\.DS_Store|Thumbs\.db)$/.test(rel)) continue;
    const p = safePath(rel);
    if (!p) throw new Error('Unsafe file path in folder: ' + rel);
    const k = p.normalize('NFC').toLowerCase();
    if (seen.has(k)) throw new Error('Duplicate file path: ' + p);
    seen.add(k);
    if (f.size > L.entry) throw new Error('File too large (over 50 MB): ' + p);
    total += f.size;
    if (total > L.total) throw new Error('Folder is larger than the 200 MB limit');
    files.set(p, new Uint8Array(await f.arrayBuffer()));
  }
  return files;
}

// ---------- validation (spec 0.1) -> plan ----------
const sniff = u => u.length < 12 ? null : u[0] === 0x89 && u[1] === 0x50 && u[2] === 0x4e && u[3] === 0x47 ? 'image'
  : u[0] === 0xff && u[1] === 0xd8 && u[2] === 0xff ? 'image'
  : u[0] === 0x52 && u[1] === 0x49 && u[2] === 0x46 && u[3] === 0x46 && u[8] === 0x57 && u[9] === 0x45 ? 'image'
  : u[0] === 0x77 && u[1] === 0x4f && u[2] === 0x46 && u[3] === 0x32 ? 'woff2'
  : u[0] === 0x1a && u[1] === 0x45 && u[2] === 0xdf && u[3] === 0xa3 ? 'video'
  : u[4] === 0x66 && u[5] === 0x74 && u[6] === 0x79 && u[7] === 0x70 ? 'video' : null;

export function validate(files) {
  const E = [], W = [], used = new Set();
  const json = p => {
    const u = files.get(p);
    if (!u) return null;
    if (u.length > L.json) { E.push(p + ' is too large'); return null; }
    try { return JSON.parse(new TextDecoder().decode(u)); } catch { E.push(p + ' is not valid JSON'); return null; }
  };
  const asset = (p, kind, where) => {
    if (!safePath(p) || !files.has(p)) { E.push(where + ': file not found: ' + p); return false; }
    if (sniff(files.get(p)) !== kind) { E.push(where + ': ' + p + ' is not a valid ' + ({ image: 'PNG, JPEG or WebP image', woff2: 'WOFF2 font', video: 'WebM or MP4 video' }[kind])); return false; }
    used.add(p); return true;
  };
  const root = json('coffeo.json');
  if (!root) { if (!E.length) E.push('coffeo.json is required'); return { errors: E, warnings: W }; }
  if (root.spec !== '0.1') E.push('Unsupported spec version: ' + root.spec + ' (this engine reads 0.1)');
  if (typeof root.id !== 'string' || !/^[a-z0-9]+(\.[a-z0-9-]+)+$/.test(root.id)) E.push('coffeo.json: id must look like com.example.my-set');
  if (typeof root.name !== 'string' || !root.name || root.name.length > 60) E.push('coffeo.json: name is required (60 characters at most)');
  if (typeof root.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(root.version)) E.push('coffeo.json: version must look like 1.0.0');
  const plan = { root: { spec: root.spec, id: root.id, name: root.name, version: root.version }, layers: [], ui: [], fonts: { families: [], assign: {} }, files: [] };

  const pg = json('themes/page/page.json');
  if (pg) {
    const ids = new Set(), slots = new Set();
    for (const l of Array.isArray(pg.layers) ? pg.layers : []) {
      const w = 'page layer ' + l.id;
      if (typeof l.id !== 'string' || ids.has(l.id)) { E.push('page layer ids must be unique strings'); continue; }
      ids.add(l.id);
      if (!isTarget(l.target)) { E.push(w + ': unknown target ' + l.target); continue; }
      const slot = l.slot || 'overlay', fit = l.fit || 'cover', z = l.z ?? 0, op = l.opacity ?? 1;
      if (!['behind', 'overlay'].includes(slot)) E.push(w + ': slot must be behind or overlay');
      if (!['cover', 'contain', 'stretch', 'tile'].includes(fit)) E.push(w + ': fit must be cover, contain, stretch or tile');
      if (!Number.isInteger(z) || z < 0 || z > 100) E.push(w + ': z must be a whole number from 0 to 100');
      if (typeof op !== 'number' || op < 0 || op > 1) E.push(w + ': opacity must be from 0 to 1');
      if (slots.has(l.target + slot)) E.push(w + ': only one layer per target and slot is supported in this version');
      slots.add(l.target + slot);
      if (!l.media || !['image', 'video'].includes(l.media.type)) { E.push(w + ': media type must be image or video'); continue; }
      if (l.media.type === 'image') {
        if (asset(l.media.src, 'image', w)) plan.layers.push({ id: l.id, target: l.target, slot, z, fit, opacity: op, src: l.media.src });
        continue;
      }
      if (fit === 'tile') E.push(w + ': tile is only for images');
      const srcs = [];
      for (const x of Array.isArray(l.media.sources) ? l.media.sources : []) {
        if (typeof x.type !== 'string' || !/^video\/(webm|mp4)(; codecs=[\w.,\- ]{1,40})?$/.test(x.type)) { E.push(w + ': video source type must be video/webm or video/mp4'); continue; }
        if (asset(x.src, 'video', w)) srcs.push({ src: x.src, type: x.type });
      }
      if (!srcs.length) { E.push(w + ': a video layer needs at least one valid source'); continue; }
      let poster = null;
      if (l.media.poster != null && asset(l.media.poster, 'image', w)) poster = l.media.poster;
      plan.layers.push({ id: l.id, target: l.target, slot, z, fit, opacity: op, video: { sources: srcs, poster } });
    }
  }
  const ui = json('ui/manifest.json');
  if (ui) for (const o of Array.isArray(ui.overrides) ? ui.overrides : []) {
    if (!isTarget(o.target) || typeof o.set !== 'object' || !o.set) { E.push('ui: each override needs a valid target and a set object'); continue; }
    const s = {};
    for (const [k, v] of Object.entries(o.set)) {
      if (k === 'opacity' && typeof v === 'number' && v >= 0 && v <= 1) s.opacity = v;
      else if (k === 'borderRadius' && typeof v === 'string' && /^\d{1,2}px$/.test(v) && parseInt(v) <= 64) s.borderRadius = v;
      else E.push('ui ' + o.target + ': property ' + k + ' is not allowed without host permission (allowed now: opacity, borderRadius)');
    }
    plan.ui.push({ target: o.target, set: s });
  }
  const fm = json('fonts/manifest.json');
  if (fm) {
    const fam = new Set();
    for (const f of Array.isArray(fm.families) ? fm.families : []) {
      if (typeof f.id !== 'string' || typeof f.name !== 'string' || !/^[A-Za-z0-9 _-]{1,64}$/.test(f.name)) { E.push('fonts: each family needs an id and a simple name'); continue; }
      const fb = (f.fallback || ['sans-serif']).filter(x => FALLBACK.includes(x));
      const fl = [];
      for (const x of Array.isArray(f.files) ? f.files : []) {
        const weight = x.weight || '400', style = x.style || 'normal';
        if (!/^([1-9]00|normal|bold)$/.test(weight) || !['normal', 'italic'].includes(style)) { E.push('fonts ' + f.id + ': bad weight or style'); continue; }
        if (asset(x.src, 'woff2', 'font ' + f.id)) fl.push({ src: x.src, weight, style });
      }
      fam.add(f.id);
      plan.fonts.families.push({ id: f.id, name: f.name, fallback: fb, files: fl });
    }
    for (const [t, id] of Object.entries(fm.assign || {})) {
      if (!isTarget(t) || !fam.has(id)) E.push('fonts: bad assignment ' + t); else plan.fonts.assign[t] = id;
    }
  }
  const stray = [...files.keys()].filter(p => !used.has(p) && !/\.json$/.test(p));
  if (stray.length) W.push(stray.length + ' file(s) are not referenced and were ignored');
  plan.files = [...used];
  return { plan, errors: E, warnings: W };
}

export function parseMap(s) {
  const out = [];
  for (const part of (s || '').split(';')) {
    const t = part.trim(), i = t.indexOf('=');
    if (i < 1) continue;
    const id = t.slice(0, i).trim();
    let sel = t.slice(i + 1).trim();
    const b = sel.indexOf('{');
    if (b >= 0) sel = sel.slice(0, b).trim(); // {adjust} is read later (needs host permission support)
    if (isTarget(id) && sel) out.push({ id, sel });
  }
  return out;
}

// ---------- browser part ----------
let live = null, cfg = { policy: 'visitor', url: null, targets: '' }, hostSet = null;
const emit = d => dispatchEvent(new CustomEvent('coffeo-report', { detail: d }));
const usedTargets = p => [...new Set([...p.layers.map(l => l.target), ...p.ui.map(u => u.target), ...Object.keys(p.fonts.assign)])];

function mark(map) {
  const marks = new Map(), matched = new Set();
  const add = (el, id) => {
    if (!marks.has(el)) {
      marks.set(el, { had: el.hasAttribute('data-coffeo'), orig: el.getAttribute('data-coffeo') });
      el.setAttribute('data-coffeo-on', '');
      if (getComputedStyle(el).position === 'static') el.setAttribute('data-coffeo-pos', '');
    }
    const toks = (el.getAttribute('data-coffeo') || '').split(/\s+/).filter(Boolean);
    if (!toks.includes(id)) el.setAttribute('data-coffeo', [...toks, id].join(' '));
    matched.add(id);
  };
  for (const { id, sel } of map) { let l; try { l = document.querySelectorAll(sel); } catch { continue; } l.forEach(el => add(el, id)); }
  document.querySelectorAll('[data-coffeo]').forEach(el => (el.getAttribute('data-coffeo') || '').split(/\s+/).filter(isTarget).forEach(t => add(el, t)));
  return { marks, matched };
}

export function remove() {
  if (!live) return;
  live.dispose.forEach(f => f());
  document.adoptedStyleSheets = document.adoptedStyleSheets.filter(s => s !== live.sheet);
  live.urls.forEach(u => URL.revokeObjectURL(u));
  live.fonts.forEach(f => document.fonts.delete(f));
  live.marks.forEach((m, el) => {
    if (m.had) el.setAttribute('data-coffeo', m.orig); else el.removeAttribute('data-coffeo');
    el.removeAttribute('data-coffeo-on'); el.removeAttribute('data-coffeo-pos');
  });
  live = null;
}

async function apply(plan, blobs, source, extra = []) {
  remove();
  const urls = new Map(), fonts = [], warnings = [...extra];
  const url = p => { if (!urls.has(p)) urls.set(p, URL.createObjectURL(blobs.get(p))); return urls.get(p); };
  const { marks, matched } = mark(parseMap(cfg.targets));
  const css = ['[data-coffeo-on]{isolation:isolate}', '[data-coffeo-pos]{position:relative}'];
  const sel = t => `[data-coffeo~="${t}"]`;
  for (const l of plan.layers) {
    if (l.video) continue;
    const pos = l.fit === 'tile' ? '0 0/auto repeat' : `center/${l.fit === 'stretch' ? '100% 100%' : l.fit} no-repeat`;
    css.push(`${sel(l.target)}${l.slot === 'behind' ? '::before' : '::after'}{content:"";position:absolute;inset:0;pointer-events:none;z-index:${l.slot === 'behind' ? -1 : l.z};opacity:${l.opacity};background:url("${url(l.src)}") ${pos}}`);
  }
  for (const u of plan.ui) {
    const d = [u.set.opacity != null && `opacity:${u.set.opacity}`, u.set.borderRadius && `border-radius:${u.set.borderRadius}`].filter(Boolean).join(';');
    if (d) css.push(`${sel(u.target)}[data-coffeo-on]{${d}}`);
  }
  for (const f of plan.fonts.families) {
    for (const x of f.files) {
      try {
        const ff = new FontFace(f.name, await blobs.get(x.src).arrayBuffer(), { weight: x.weight, style: x.style, display: 'swap' });
        await ff.load(); document.fonts.add(ff); fonts.push(ff);
      } catch { warnings.push('Font could not be loaded: ' + x.src); }
    }
  }
  for (const [t, id] of Object.entries(plan.fonts.assign)) {
    const f = plan.fonts.families.find(x => x.id === id);
    css.push(`${sel(t)}[data-coffeo-on]{font-family:"${f.name}",${f.fallback.join(',') || 'sans-serif'}}`);
  }
  const dispose = [];
  let videos = 0;
  for (const l of plan.layers.filter(x => x.video)) {
    const host = document.querySelector(sel(l.target));
    if (!host) continue;
    const slotEl = host.querySelector(`:scope > [data-coffeo-slot="${l.slot}"]`);
    const box = slotEl || document.createElement('div');
    if (!slotEl) {
      box.setAttribute('data-coffeo-layer', '');
      box.style.cssText = `position:absolute;inset:0;pointer-events:none;overflow:hidden;z-index:${l.slot === 'behind' ? -1 : l.z};opacity:${l.opacity}`;
      l.slot === 'behind' ? host.prepend(box) : host.append(box);
      dispose.push(() => box.remove());
    }
    const still = l.video.poster ? url(l.video.poster) : null, reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
    const v = document.createElement('video'), src = l.video.sources.find(x => v.canPlayType(x.type));
    if (!src || reduced || videos >= MAX_VIDEOS) {
      if (still) { const im = document.createElement('div'); im.style.cssText = `position:absolute;inset:0;background:url("${still}") center/${l.fit === 'stretch' ? '100% 100%' : l.fit} no-repeat`; box.append(im); dispose.push(() => im.remove()); }
      warnings.push('Video layer ' + l.id + ' is shown as a still image' + (reduced ? ' (reduced motion is on)' : !src ? ' (this browser cannot play its formats)' : ' (this device tier allows ' + MAX_VIDEOS + ' video at a time)'));
      continue;
    }
    videos++;
    v.muted = v.loop = v.playsInline = true; v.preload = 'auto'; v.tabIndex = -1; v.setAttribute('aria-hidden', 'true');
    if (still) v.poster = still;
    v.style.cssText = `display:block;width:100%;height:100%;object-fit:${l.fit === 'stretch' ? 'fill' : l.fit}`;
    const b = blobs.get(src.src), vurl = URL.createObjectURL(b.slice(0, b.size, src.type.split(';')[0]));
    urls.set('v:' + l.id, vurl);
    v.src = vurl; box.append(v);
    let seen = true;
    const sync = () => { seen && !document.hidden ? v.play().catch(() => {}) : v.pause(); };
    const io = new IntersectionObserver(es => { seen = es[es.length - 1].isIntersecting; sync(); });
    io.observe(host); document.addEventListener('visibilitychange', sync);
    dispose.push(() => { io.disconnect(); document.removeEventListener('visibilitychange', sync); v.pause(); v.removeAttribute('src'); v.load(); v.remove(); });
  }
  const sheet = new CSSStyleSheet();
  sheet.replaceSync(css.join('\n'));
  document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
  live = { sheet, urls: [...urls.values()], fonts, marks, dispose, name: plan.root.name, source };
  const used = usedTargets(plan);
  const r = { ok: true, source, name: plan.root.name, version: plan.root.version, matched: used.filter(t => matched.has(t)), missing: used.filter(t => !matched.has(t)), warnings };
  emit(r); return r;
}

// ---------- local store (OPFS) ----------
const dirOf = async () => (await navigator.storage.getDirectory()).getDirectoryHandle('coffeo', { create: true });
async function store(plan, files) {
  const dir = await dirOf(), name = 's' + Date.now(), d = await dir.getDirectoryHandle(name, { create: true });
  const put = async (n, data) => { const w = await (await d.getFileHandle(n, { create: true })).createWritable(); await w.write(data); await w.close(); };
  await put('plan.json', JSON.stringify(plan));
  for (const p of plan.files) await put(encodeURIComponent(p), files.get(p));
  const old = localStorage.getItem('coffeo.active');
  localStorage.setItem('coffeo.active', name);
  if (old) try { await dir.removeEntry(old, { recursive: true }); } catch {}
}
async function load() {
  const name = localStorage.getItem('coffeo.active');
  if (!name) return null;
  try {
    const d = await (await dirOf()).getDirectoryHandle(name), blobs = new Map();
    const plan = JSON.parse(await (await (await d.getFileHandle('plan.json')).getFile()).text());
    for (const p of plan.files) blobs.set(p, await (await d.getFileHandle(encodeURIComponent(p))).getFile());
    return { plan, blobs };
  } catch { return null; }
}

// ---------- public API ----------
async function loadHost() {
  if (!cfg.url) return null;
  const u = new URL(cfg.url, location.href);
  if (u.origin !== location.origin) throw new Error('The site Style Set must be on the same site');
  const res = await fetch(u, { cache: 'no-cache' });
  if (!res.ok) throw new Error('Could not load ' + cfg.url);
  const files = await readZip(await res.blob()), v = validate(files);
  if (v.errors.length) throw new Error('Site Style Set is invalid: ' + v.errors[0]);
  return { plan: v.plan, blobs: new Map(v.plan.files.map(p => [p, new Blob([files.get(p)])])) };
}
async function show() {
  let note = [];
  if (cfg.policy !== 'locked') {
    const mine = await load();
    if (mine) return apply(mine.plan, mine.blobs, 'visitor');
    if (localStorage.getItem('coffeo.active')) note = ['Your saved theme could not be read from this device.'];
  }
  hostSet ||= await loadHost();
  if (hostSet) return apply(hostSet.plan, hostSet.blobs, 'site', note);
  remove(); const r = { ok: true, source: 'none', matched: [], missing: [], warnings: [] }; emit(r); return r;
}
export const Coffeo = {
  get version() { return VERSION; },
  get policy() { return cfg.policy; },
  get current() { return live && { name: live.name, source: live.source }; },
  async import(src) {
    if (cfg.policy === 'locked') throw new Error('This site uses a theme chosen by its owner');
    try {
      const files = src instanceof Blob ? await readZip(src) : await readFolder(src);
      const v = validate(files);
      if (v.errors.length) { const r = { ok: false, errors: v.errors, warnings: v.warnings }; emit(r); throw Object.assign(new Error(v.errors[0]), { report: r }); }
      try { await store(v.plan, files); } catch (e) { throw new Error('Could not save the theme on this device: ' + e.message); }
      const r = await show(); r.warnings = [...(r.warnings || []), ...v.warnings]; return r;
    } catch (e) {
      if (!e.report) emit({ ok: false, errors: [e.message], warnings: [] });
      throw e;
    }
  },
  async reset() {
    if (cfg.policy === 'locked') throw new Error('This site uses a theme chosen by its owner');
    const n = localStorage.getItem('coffeo.active');
    localStorage.removeItem('coffeo.active');
    if (n) try { await (await dirOf()).removeEntry(n, { recursive: true }); } catch {}
    return show();
  },
};
if (typeof document !== 'undefined') {
  const tag = [...document.scripts].find(s => s.src === import.meta.url) || document.querySelector('script[data-policy],script[data-targets],script[data-style-set]');
  if (tag) cfg = { policy: tag.dataset.policy === 'locked' ? 'locked' : 'visitor', url: tag.dataset.styleSet || null, targets: tag.dataset.targets || '' };
  window.Coffeo = Coffeo;
  if (new URLSearchParams(location.search).get('coffeo') !== 'off') {
    const go = () => show().catch(e => emit({ ok: false, errors: [e.message], warnings: [] }));
    document.readyState === 'loading' ? addEventListener('DOMContentLoaded', go) : go();
  }
}
