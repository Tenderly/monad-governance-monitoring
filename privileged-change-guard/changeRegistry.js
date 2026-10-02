// changeRegistry.js: registry of announced privileged changes for privChangeGuard.js
// (Tenderly Web3 Action, webhook trigger with authenticated: false, one file).
//
// WHAT IT IS FOR
//   Announce a planned privileged change BEFORE you execute it. privChangeGuard.js treats a
//   matching change (same network, contract, kind, role, new holder or value, inside the
//   validity window) as announced: it is reported as info instead of high, and it does not
//   trigger the auto-pause for a strong holder. An announcement never excuses a single-key
//   holder (EOA, EIP-7702 EOA, 1-of-N Safe): that stays critical and still pauses.
//
// HOW IT IS AUTHENTICATED
//   Nothing secret travels in the request. The announcer signs the canonical message below
//   (EIP-191, personal_sign, for example with a hardware wallet) and the action accepts it
//   only when the signer is in CONFIG.announcers. The guard verifies the signature again
//   when a change arrives, so a forged storage row or another action of the project cannot
//   fake notice. Each announcement is single use and cannot be replayed once cancelled.
//   The webhook is deliberately unauthenticated: the signature is the credential, so no Tenderly
//   access key has to travel with the request. Use the helper announce.js to build and sign a request.
//   Anyone who knows the webhook URL can start an execution (an invalid request simply fails, and
//   nobody can forge an announcement), so keep the URL private and watch the Execution History.
//
// REQUESTS (POST https://api.tenderly.co/api/v1/actions/<actionId>/webhook, JSON body)
//   {"op":"announce","announcement":{network,contract,kind,role,holder,value,validFrom,validUntil,nonce,note},"signature":"0x.."}
//   {"op":"cancel","id":"a1b2c3d4","signature":"0x.."}   signs "<MESSAGE_HEAD> cancel" + newline + "id: <id>"
//   {"op":"list"}                                          results go to the execution log only
//   kind: owner, pending-owner, role, role-admin, authority, ward, proxy, proxy-admin, safe, timelock,
//   minter, pause or any. An AccessControl, ACLManager or AccessManager role is kind "role"; a Circle
//   style minter is kind "minter". role: 32-byte hex id, or @PAUSER, @BLACKLISTER, @RESCUER for Circle
//   style fixed roles. Addresses and ids are lowercase hex, times are unix seconds.
//
// In our tests the webhook answered HTTP 200 before the action ran, so the response does not tell
// you whether the announcement was stored: read the result in the action's Execution History.
// An invalid request fails the run with the reason.
// Webhook actions run in parallel: two announcements sent within the same second can lose one
// (the loser is simply not announced, which is the safe direction): send them one by one.
// Storage: one JSON key shared with the guard, at most CONFIG.maxItems entries and CONFIG.maxBytes bytes.

const CONFIG = {
  registryKey: 'privGuard:announcements:v2', // must match privChangeGuard.js CONFIG.storage.registryKey
  consumedKey: 'privGuard:consumed:v1', // must match privChangeGuard.js CONFIG.storage.consumedKey
  announcers: [], // addresses whose signature counts; must match privChangeGuard.js CONFIG.announcers
  maxItems: 100,
  maxBytes: 90000, // serialized size cap, far below the 100 KB storage value limit
  maxValidDays: 30, // an announcement cannot be valid longer than this
  maxNoteChars: 160,
  defaultNetwork: '143',
  networks: ['1', '143', '10143'], // network ids an announcement may name; the guard matches the network id of the alert payload
  slackSecret: 'SLACK_WEBHOOK_URL', // optional: confirmations to Slack
  notifySlack: true,
};

const KINDS = ['owner', 'pending-owner', 'role', 'role-admin', 'authority', 'ward', 'proxy', 'proxy-admin', 'safe', 'timelock', 'minter', 'pause', 'any'];

const isAddr = (a) => typeof a === 'string' && /^0x[0-9a-f]{40}$/.test(a);
class BadRequest extends Error {}
const bad = (m) => {
  throw new BadRequest(m);
};
const shortAddr = (a) => (a && a.length > 14 ? `${a.slice(0, 6)}...${a.slice(-4)}` : String(a));

// The signed text. Keep byte for byte equal to announcementMessage() in privChangeGuard.js.
function announcementMessage(a) {
  return [
    'Monad privileged change announcement v1',
    `network: ${a.network}`,
    `contract: ${a.contract}`,
    `kind: ${a.kind}`,
    `role: ${a.role || '-'}`,
    `holder: ${a.holder || '-'}`,
    `value: ${a.value === null || a.value === undefined ? '-' : a.value}`,
    `validFrom: ${a.validFrom}`,
    `validUntil: ${a.validUntil}`,
    `nonce: ${a.nonce}`,
    `note: ${a.note || '-'}`,
  ].join('\n');
}
const cancelMessage = (id) => `Monad privileged change announcement v1 cancel\nid: ${id}`;

// Strict: the signature covers exactly these strings, so nothing is normalised here.
function validateAnnouncement(p, now) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) bad('announcement must be a JSON object (use announce.js to build it)');
  const network = String(p.network === undefined ? CONFIG.defaultNetwork : p.network);
  if (!CONFIG.networks.includes(network)) bad(`network ${String(network).replace(/[^\w]/g, '').slice(0, 12)} is not supported`);
  if (!isAddr(p.contract)) bad('contract must be a lowercase 0x address');
  if (!KINDS.includes(p.kind)) bad(`kind must be one of ${KINDS.join(', ')}`);
  let holder = null;
  if (p.holder !== undefined && p.holder !== null && p.holder !== '') {
    if (!isAddr(p.holder)) bad('holder must be a lowercase 0x address');
    holder = p.holder;
  }
  let value = null;
  if (p.value !== undefined && p.value !== null && p.value !== '') {
    if (!/^\d{1,78}$/.test(String(p.value)) || String(p.value) !== String(BigInt(p.value))) bad('value must be a non-negative integer in plain decimal (threshold, delay in seconds, ...)');
    value = String(p.value);
  }
  if (!holder && value === null) bad('give holder (who receives or loses the power) or value (new threshold or delay)');
  let role = null;
  if (p.role !== undefined && p.role !== null && p.role !== '') {
    if (!/^(0x[0-9a-f]{64}|@[A-Z0-9_]{2,32})$/.test(p.role)) bad('role must be a lowercase 32-byte hex id or @NAME for a fixed role (use announce.js to resolve a role name)');
    if (p.kind !== 'role' && p.kind !== 'any') bad('role is only used with kind "role"');
    role = p.role;
  }
  const validFrom = p.validFrom;
  const validUntil = p.validUntil;
  if (!Number.isSafeInteger(validFrom) || !Number.isSafeInteger(validUntil)) bad('validFrom and validUntil must be unix seconds (integers)');
  if (validUntil <= now) bad('validUntil is in the past');
  if (validUntil - now > CONFIG.maxValidDays * 86400) bad(`validUntil is more than ${CONFIG.maxValidDays} days ahead`);
  if (validFrom >= validUntil) bad('validFrom must be before validUntil');
  if (validUntil - validFrom > CONFIG.maxValidDays * 86400) bad(`the window is longer than ${CONFIG.maxValidDays} days`);
  if (typeof p.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(p.nonce)) bad('nonce must be 32 lowercase hex characters (random, one per announcement)');
  const note = p.note === undefined || p.note === null ? '' : p.note;
  if (typeof note !== 'string' || note.length > CONFIG.maxNoteChars || !/^[\x20-\x7e]*$/.test(note) || /[<>]/.test(note)) bad(`note must be printable ASCII without < or >, at most ${CONFIG.maxNoteChars} characters`);
  return { network, contract: p.contract, kind: p.kind, role, holder, value, validFrom, validUntil, nonce: p.nonce, note };
}

// Signer of an EIP-191 signature, accepted only when it is a configured announcer.
function announcerOf(message, signature) {
  const allowed = (CONFIG.announcers || []).map((x) => String(x).toLowerCase());
  if (!allowed.length) bad('CONFIG.announcers is empty: nobody can announce');
  let eth;
  try {
    eth = require('ethers'); // ethers v5: the docs list Ethers.js as bundled in the runtime, and require() worked in our tests of a deployed action
  } catch (e) {
    bad('ethers is not available in this runtime: announcements cannot be verified, nothing stored');
  }
  if (typeof signature !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(signature)) bad('signature must be a 65-byte hex signature');
  let signer;
  try {
    signer = eth.utils.verifyMessage(message, signature).toLowerCase();
  } catch (e) {
    bad('signature could not be verified');
  }
  if (!allowed.includes(signer)) bad('signature is not from a configured announcer');
  return signer;
}

const idOf = (message) => require('crypto').createHash('sha256').update(message).digest('hex').slice(0, 8);
const fmt = (a) => `${a.id} ${a.kind}${a.role ? ` role ${a.role.slice(0, 10)}..` : ''} on ${a.contract} (net ${a.network}) holder ${a.holder || '-'}${a.value !== null ? ` value ${a.value}` : ''} until ${new Date(a.validUntil * 1000).toISOString()}${a.note ? ` "${a.note}"` : ''}`;

async function load(context) {
  const v = await context.storage.getJson(CONFIG.registryKey); // in our tests a missing key read back as {}; any other shape counts as empty
  return v && v.v === 2 && Array.isArray(v.items) ? v : { v: 2, items: [], used: [] };
}
async function consumedIds(context) {
  try {
    const c = await context.storage.getJson(CONFIG.consumedKey);
    return new Set(Array.isArray(c && c.items) ? c.items.map((x) => x.id) : []);
  } catch (e) {
    return new Set();
  }
}

async function slack(context, text) {
  if (!CONFIG.notifySlack) return;
  let url;
  try {
    url = await context.secrets.get(CONFIG.slackSecret);
  } catch (e) {
    return;
  }
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text }), signal: AbortSignal.timeout(8000) });
    if (r.status !== 200) console.error(`slack HTTP ${r.status}`);
  } catch (e) {
    console.error('slack failed');
  }
}

const actionFn = async (context, event) => {
  const p = (event && event.payload) || {};
  if (typeof p !== 'object' || Array.isArray(p)) bad('body must be a JSON object');
  const op = String(p.op || 'announce');
  const now = Math.floor(Date.now() / 1000);
  let result;
  let notify = null;

  if (op === 'list') {
    const reg = await load(context);
    const used = await consumedIds(context);
    const live = reg.items.filter((a) => a.validUntil > now);
    console.log(live.length ? `${live.length} active announcement(s):\n${live.map((a) => fmt(a) + (used.has(a.id) ? ' [consumed]' : '')).join('\n')}` : 'no active announcements');
    return { ok: true, active: live.length };
  }

  if (op === 'announce') {
    // Everything is checked before storage is touched; the read-modify-write below is short.
    const a = validateAnnouncement(p.announcement, now);
    const message = announcementMessage(a);
    const signer = announcerOf(message, p.signature);
    const id = idOf(message);
    const reg = await load(context);
    reg.items = reg.items.filter((x) => x.validUntil > now); // prune expired
    reg.used = (reg.used || []).filter((u) => u.u > now);
    if (reg.used.some((u) => u.n === a.nonce) || (await consumedIds(context)).has(id)) bad('this announcement was already used or cancelled: sign a new one (new nonce)');
    const dup = reg.items.find((x) => x.nonce === a.nonce);
    if (dup) {
      result = `already registered (repeated request): ${fmt(dup)}`;
    } else {
      if (reg.items.length >= CONFIG.maxItems) bad(`registry full (${CONFIG.maxItems} active announcements); cancel some first`);
      const item = { id, ...a, announcer: signer, sig: p.signature, createdAt: now };
      reg.items.push(item);
      if (Buffer.byteLength(JSON.stringify(reg)) > CONFIG.maxBytes) bad('registry storage is full (size cap); cancel some announcements first');
      await context.storage.putJson(CONFIG.registryKey, reg);
      result = `announced ${fmt(item)} (signed by ${shortAddr(signer)}, single use)`;
      notify = result;
    }
  } else if (op === 'cancel') {
    const id = String(p.id || '');
    if (!/^[0-9a-f]{8}$/.test(id)) bad('id must be the 8-hex id returned by announce (see list)');
    announcerOf(cancelMessage(id), p.signature);
    const reg = await load(context);
    const i = reg.items.findIndex((x) => x.id === id);
    if (i < 0) bad(`no active announcement with id ${id}`);
    const [gone] = reg.items.splice(i, 1);
    reg.used = [...(reg.used || []).filter((u) => u.u > now), { n: gone.nonce, u: gone.validUntil }]; // the same signed message can never be announced again
    await context.storage.putJson(CONFIG.registryKey, reg);
    result = `cancelled ${fmt(gone)}`;
    notify = result;
  } else bad('op must be announce, cancel or list');

  console.log(result);
  if (notify) await slack(context, `:memo: Change registry: ${notify}`);
  return { ok: true, result };
};

module.exports = { actionFn, CONFIG, _internal: { announcementMessage, cancelMessage } }; // _internal: local tests only
