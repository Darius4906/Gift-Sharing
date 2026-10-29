/* Gift Exchange – shared logic (pairing + encryption). Used by admin.html and index.html. */
(function (root) {
  const cr = typeof crypto !== 'undefined' ? crypto : require('node:crypto').webcrypto;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const ITER = 200000;

  /* ---------- helpers ---------- */
  function normalizeName(s) {
    return String(s)
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s]/gu, ' ')
      .split(/\s+/).filter(Boolean)
      .sort()                       // word order doesn't matter: "Isaac Jane" = "Jane Isaac"
      .join(' ');
  }

  function randInt(n) {
    const a = new Uint32Array(1);
    const lim = Math.floor(0x100000000 / n) * n;
    let x;
    do { cr.getRandomValues(a); x = a[0]; } while (x >= lim);
    return x % n;
  }

  function shuffle(arr) {
    const a = arr.slice();
    for (let i = a.length - 1; i > 0; i--) {
      const j = randInt(i + 1);
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }

  function b64(buf) {
    let s = '';
    for (const x of new Uint8Array(buf)) s += String.fromCharCode(x);
    return btoa(s);
  }
  function unb64(s) {
    const bin = atob(s);
    const b = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
    return b;
  }
  async function sha256hex(str) {
    const h = await cr.subtle.digest('SHA-256', enc.encode(str));
    return [...new Uint8Array(h)].map(x => x.toString(16).padStart(2, '0')).join('');
  }

  /* ---------- input parsing & family rules ---------- */
  // One person per line. Optional family tag after "|":  "Odumusi Olamide | Odumusi"
  function parseLines(text) {
    return text.split(/\r?\n/)
      .map(l => l.split('\t')[0])
      .map(l => {
        const [n, f] = l.split('|');
        return { name: (n || '').trim().replace(/\s+/g, ' '), family: (f || '').trim() };
      })
      .filter(p => p.name);
  }

  function tokens(str) {
    return normalizeName(str).split(' ').filter(t => t.length >= 2); // ignore initials like "O."
  }
  // Two people can't be paired if their sets share a word.
  // Without a tag, the set is every word of their name; with a tag, only the tag's words.
  function familySet(p) { return new Set(tokens(p.family ? p.family : p.name)); }

  function findDuplicates(people) {
    const seen = new Map(), dups = [];
    for (const p of people) {
      const k = normalizeName(p.name);
      if (seen.has(k)) dups.push(p.name); else seen.set(k, p.name);
    }
    return dups;
  }

  function sharedGroups(people) {
    const byTok = new Map();
    for (const p of people) for (const t of familySet(p)) {
      if (!byTok.has(t)) byTok.set(t, []);
      byTok.get(t).push(p.name);
    }
    return [...byTok.entries()].filter(([, v]) => v.length > 1);
  }

  /* ---------- the draw ---------- */
  // Returns an array where result[i] = index of the person that person i gives to (or null if impossible).
  function makePairs(people, maxSteps = 3e6) {
    const n = people.length;
    if (n < 2) return null;
    const fam = people.map(familySet);
    const ok = (i, j) => {
      if (i === j) return false;
      for (const t of fam[i]) if (fam[j].has(t)) return false;
      return true;
    };
    const idx = [...Array(n).keys()];
    const cands = idx.map(i => idx.filter(j => ok(i, j)));
    if (cands.some(c => c.length === 0)) return null;

    const order = shuffle(idx).sort((a, b) => cands[a].length - cands[b].length);
    const taken = new Array(n).fill(false);
    const result = new Array(n).fill(-1);
    let steps = 0;

    function go(k) {
      if (k === n) return true;
      if (++steps > maxSteps) return false;
      const i = order[k];
      for (const j of shuffle(cands[i])) {
        if (taken[j]) continue;
        taken[j] = true; result[i] = j;
        if (go(k + 1)) return true;
        taken[j] = false; result[i] = -1;
        if (steps > maxSteps) return false;
      }
      return false;
    }
    return go(0) ? result : null;
  }

  /* ---------- encryption ---------- */
  function secretFor(name, code) {
    return normalizeName(name) + '|' + String(code || '').trim().toLowerCase();
  }
  async function deriveKey(secret, saltB64) {
    const base = await cr.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
    return cr.subtle.deriveKey(
      { name: 'PBKDF2', salt: unb64(saltB64), iterations: ITER, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function sealEntry(giver, receiver, code, saltB64) {
    const id = await sha256hex(saltB64 + '|' + normalizeName(giver));
    const key = await deriveKey(secretFor(giver, code), saltB64);
    const iv = cr.getRandomValues(new Uint8Array(12));
    const ct = await cr.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify({ to: receiver })));
    return { id, iv: b64(iv), ct: b64(ct) };
  }
  // Returns the receiver's name, or null if the name/code doesn't match.
  async function openEntry(data, name, code) {
    const id = await sha256hex(data.salt + '|' + normalizeName(name));
    const e = (data.entries || []).find(x => x.id === id);
    if (!e) return null;
    try {
      const key = await deriveKey(secretFor(name, code), data.salt);
      const pt = await cr.subtle.decrypt({ name: 'AES-GCM', iv: unb64(e.iv) }, key, unb64(e.ct));
      return JSON.parse(dec.decode(pt)).to;
    } catch (_) { return null; }
  }

  const CODE_CHARS = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
  function makeCode(len = 6) {
    let s = '';
    for (let i = 0; i < len; i++) s += CODE_CHARS[randInt(CODE_CHARS.length)];
    return s;
  }

  // Builds the whole data.json object. Pairings are never returned in readable form.
  async function buildData(people, useCodes) {
    const pairs = makePairs(people);
    if (!pairs) return null;
    const salt = b64(cr.getRandomValues(new Uint8Array(16)));
    const codes = [];
    const entries = [];
    for (let i = 0; i < people.length; i++) {
      const code = useCodes ? makeCode() : '';
      if (useCodes) codes.push({ name: people[i].name, code });
      entries.push(await sealEntry(people[i].name, people[pairs[i]].name, code, salt));
    }
    return { data: { version: 1, needsCode: !!useCodes, salt, entries: shuffle(entries) }, codes };
  }

  const api = { normalizeName, parseLines, findDuplicates, sharedGroups, makePairs, buildData, openEntry, sealEntry, makeCode };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.GiftCore = api;
})(typeof self !== 'undefined' ? self : globalThis);
