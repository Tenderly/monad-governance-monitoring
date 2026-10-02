#!/usr/bin/env node
// Creates the GOV alerts of the packs listed in index.json (core/, extended/) and, optionally, the
// alerts of optional/ in a Tenderly project (Alerts REST API).
// DRY RUN by default: prints what it would create and calls nothing.
//
//   TENDERLY_ACCESS_KEY=... ACCOUNT=<account slug> PROJECT=<project slug> \
//   PACKS=base,timelock,aave-fork,safe GUARD_ACTION_ID=<privChangeGuard action id> \
//   NOTIFY_CHANNEL_IDS=<email or Slack destination id, comma separated> \
//   DRY_RUN=0 node alerts/create-alerts.js
//
// PACKS=all creates every pack (100 alerts). The tag (default: "tag" of index.json, mf-privileged)
// is the only thing the alerts are scoped to: they carry no network filter, so one alert covers
// every chain on which a tagged contract lives. TAG overrides it, NAME_PREFIX is prepended to every
// alert name.
// The action id doubles as its delivery channel id once it is deployed with an alert trigger.
// After creating, the alerts are read back once through the alert list to confirm their delivery channels.
// Your plan may limit how many alerts an account can have. Check your alert quota in the Dashboard before a
// real run: the dry run and the start of a real run both print how many alerts would be created. If the API
// refuses a create, its own error message is printed and the run stops (alerts created so far stay, are listed
// in created-alerts.json, and are skipped by name when you run again).
//
// OPTIONAL=safe-delegatecall-non-library,admin-wallet-tripwire,token-mint-from-zero,pool-outflow-of-token
// adds alerts of optional/ (see index.json "optional"). The ones marked deliver_to "notify" go to
// NOTIFY_CHANNEL_IDS only (an Event or ERC20 alert on a token is meant for Slack or Email: the Web3
// Action payload does not carry the matched transfers). Placeholders in a body are filled from the
// environment: SAFE_ADDRESS (the Safe of the delegatecall alert, one alert per Safe), TOKEN_ADDRESS, HOLDER_ADDRESS (the address that holds the token: for an Aave V3 fork
// the aToken of one reserve), NETWORK_ID, MIN_AMOUNT (raw token units); ADMIN_TAG
// (default "admin_tag" of index.json, mf-admin-wallets) is the address tag of the tripwire. A body
// with an unresolved placeholder is never created.
// An alert is created once per name: for one alert per reserve (or per token) give each run its own
// LABEL, which is appended to the name of every optional alert of the run ("... (aUSDC)").
// DIRECTION=received turns pool-outflow-of-token into the inflow alert (a minted collateral token
// arriving at its own aToken); the default is sent.
// REQUIRE_DOLLAR_VALUE=0 creates the admin wallet tripwire without its USD price filter (default: the
// body as shipped, "require_dollar_value": true, which skips tokens with no known USD price such as spam,
// airdrops and fake Transfer logs of look-alike tokens). The API accepts require_dollar_value only
// together with match_non_project_contracts (any ERC20 token), so a body that has it without is refused.
const fs = require('fs');
const path = require('path');

process.on('uncaughtException', (e) => {
  console.error(e.message); // a bad setting is a message, not a stack
  process.exit(1);
});
const env = process.env;
const DRY = env.DRY_RUN !== '0';
const API = 'https://api.tenderly.co/api/v1';
const idx = JSON.parse(fs.readFileSync(path.join(__dirname, 'index.json'), 'utf8'));
const packs = env.PACKS === 'all' ? Object.keys(idx.packs) : (env.PACKS || (env.OPTIONAL ? '' : 'base')).split(',').map((s) => s.trim()).filter(Boolean);
const optional = (env.OPTIONAL || '').split(',').map((s) => s.trim()).filter(Boolean);
const tag = env.TAG || idx.tag;
const adminTag = env.ADMIN_TAG || idx.admin_tag;
const prefix = env.NAME_PREFIX || '';
const label = (env.LABEL || '').trim();
if (label && !/^[\x20-\x7e]{1,60}$/.test(label)) throw new Error('LABEL must be 1 to 60 printable ASCII characters');
const direction = (env.DIRECTION || '').trim();
if (direction && !['sent', 'received'].includes(direction)) throw new Error('DIRECTION must be sent or received');
const dollarEnv = (env.REQUIRE_DOLLAR_VALUE || '').trim();
if (dollarEnv && !['0', '1'].includes(dollarEnv)) throw new Error('REQUIRE_DOLLAR_VALUE must be 0 or 1');
const notifyIds = (env.NOTIFY_CHANNEL_IDS || '').split(',').map((s) => s.trim()).filter(Boolean);
const guardIds = [env.GUARD_ACTION_ID].map((s) => (s || '').trim()).filter(Boolean);
const channelsFor = (deliverTo) => (deliverTo === 'notify' ? notifyIds : [...guardIds, ...notifyIds]);

for (const p of packs) if (!idx.packs[p]) throw new Error(`unknown pack ${p}; packs: ${Object.keys(idx.packs).join(', ')}`);
for (const o of optional) if (!idx.optional[o]) throw new Error(`unknown optional alert ${o}; optional: ${Object.keys(idx.optional).join(', ')}`);

const bodies = [];
for (const p of packs) {
  for (const a of idx.packs[p].alerts) {
    const b = JSON.parse(fs.readFileSync(path.join(__dirname, a.file), 'utf8'));
    b.expressions.find((e) => e.type === 'tag').expression.tag = tag;
    b.description = b.description.split(idx.tag).join(tag).slice(0, 500);
    bodies.push({ b, pack: p, channels: channelsFor('guard+notify') });
  }
}
// Placeholder values from the environment, checked before they go into a body.
const PLACEHOLDERS = {};
for (const [k, re] of [['TOKEN_ADDRESS', /^0x[0-9a-fA-F]{40}$/], ['HOLDER_ADDRESS', /^0x[0-9a-fA-F]{40}$/], ['SAFE_ADDRESS', /^0x[0-9a-fA-F]{40}$/], ['NETWORK_ID', /^[0-9]+$/], ['MIN_AMOUNT', /^[0-9]+$/]]) {
  if (!env[k]) continue;
  if (!re.test(env[k])) throw new Error(`${k} is not valid (${/\{40\}/.test(String(re)) ? 'a 0x address' : 'digits only'})`);
  PLACEHOLDERS[k] = /^0x/.test(env[k]) ? env[k].toLowerCase() : env[k];
}
for (const o of optional) {
  const meta = idx.optional[o];
  let text = fs.readFileSync(path.join(__dirname, meta.file), 'utf8');
  for (const [k, v] of Object.entries(PLACEHOLDERS)) text = text.split(`<${k}>`).join(v);
  const b = JSON.parse(text);
  if (meta.uses_tag) b.expressions.find((e) => e.type === 'tag').expression.tag = tag;
  if (meta.uses_admin_tag) b.expressions.find((e) => e.type === 'erc20_token_transfer').expression.address_tag = adminTag;
  if (meta.direction_override && direction) {
    b.expressions.find((e) => e.type === 'erc20_token_transfer').expression.direction = direction;
    if (direction === 'received') Object.assign(b, { name: meta.received.name, description: meta.received.description });
  } else if (direction && !meta.direction_override) console.log(`note: DIRECTION does not apply to ${o}, ignored`);
  if (dollarEnv) {
    const transfer = b.expressions.find((e) => e.type === 'erc20_token_transfer');
    if (meta.dollar_value_toggle && transfer) {
      transfer.expression.require_dollar_value = dollarEnv === '1';
      if (dollarEnv === '0') b.description = meta.unfiltered.description;
    } else console.log(`note: REQUIRE_DOLLAR_VALUE does not apply to ${o}, ignored`);
  }
  if (label) b.name = `${b.name} (${label})`;
  b.description = b.description.split(idx.tag).join(tag).split(idx.admin_tag).join(adminTag).slice(0, 500);
  const open = (text.match(/<[A-Z_]+>/g) || []).filter((x) => !['<PRIV_CHANGE_GUARD_ACTION_ID>', '<NOTIFY_CHANNEL_ID>'].includes(x));
  bodies.push({ b, pack: `optional/${o}`, channels: channelsFor(meta.deliver_to), unresolved: [...new Set(open)] });
}
// require_dollar_value is an any-token filter: accepted only together with match_non_project_contracts.
for (const x of bodies) {
  for (const e of x.b.expressions) {
    const v = e.type === 'erc20_token_transfer' ? e.expression.require_dollar_value : undefined;
    if (v === undefined) continue;
    if (typeof v !== 'boolean') throw new Error(`${x.pack}: require_dollar_value must be true or false`);
    if (!e.expression.match_non_project_contracts) throw new Error(`${x.pack}: require_dollar_value is accepted only together with match_non_project_contracts (any ERC20 token); refusing to create it`);
  }
}
for (const x of bodies) {
  x.b.name = prefix + x.b.name;
  x.b.delivery_channels = x.channels.map((id) => ({ id, enabled: true }));
}

async function api(method, p, body) {
  const r = await fetch(`${API}${p}`, {
    method,
    headers: { 'x-access-key': env.TENDERLY_ACCESS_KEY, 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`${method} ${p} -> HTTP ${r.status}: ${apiMessage(text)}`);
  return text ? JSON.parse(text) : {};
}

// The API's own error text: the "message" of a JSON error body when there is one, else the raw body.
function apiMessage(text) {
  try {
    const j = JSON.parse(text);
    const m = (j && j.error && (j.error.message || j.error)) || (j && j.message);
    if (m) return typeof m === 'string' ? m : JSON.stringify(m).slice(0, 500);
  } catch (e) {
    // not JSON: fall through to the raw text
  }
  return text.trim().slice(0, 500) || '(empty response)';
}

const summary = (b) => {
  const log = b.expressions.find((e) => e.type === 'emitted_log');
  return log && log.expression.event_id ? `event_id ${log.expression.event_id}` : b.expressions.map((e) => (e.type === 'erc20_token_transfer' && e.expression.require_dollar_value !== undefined ? `erc20_token_transfer (require_dollar_value ${e.expression.require_dollar_value})` : e.type)).join(' + ');
};

(async () => {
  console.log(`${bodies.length} alert(s): packs ${packs.join(', ') || '(none)'}${optional.length ? `, optional ${optional.join(', ')}` : ''}; tag ${tag}${optional.length ? `, admin tag ${adminTag}` : ''}`);
  const unresolved = bodies.filter((x) => x.unresolved && x.unresolved.length);
  if (DRY) {
    for (const x of bodies) console.log(`  would create: ${x.b.name}  ${summary(x.b)}  -> ${x.channels.length} channel(s)${x.unresolved && x.unresolved.length ? `  UNRESOLVED ${x.unresolved.join(' ')}` : ''}`);
    console.log('DRY RUN: nothing was created. Set DRY_RUN=0 to create.');
    if (bodies.length) console.log(`Before a real run: DRY_RUN=0 would create up to ${bodies.length} alert(s) (alerts that already exist by name are skipped). Check your alert quota in the Dashboard first.`);
    return;
  }
  for (const k of ['TENDERLY_ACCESS_KEY', 'ACCOUNT', 'PROJECT']) if (!env[k]) throw new Error(`${k} is required`);
  for (const x of bodies) if (!x.channels.length) throw new Error(`${x.pack}: no delivery channel (give ${x.channels === notifyIds ? 'NOTIFY_CHANNEL_IDS' : 'GUARD_ACTION_ID and/or NOTIFY_CHANNEL_IDS'}): an alert needs at least one destination`);
  if (unresolved.length) throw new Error(`unresolved placeholder(s) ${unresolved.map((x) => `${x.pack}: ${x.unresolved.join(' ')}`).join('; ')}: set them in the environment`);
  const base = `/account/${env.ACCOUNT}/project/${env.PROJECT}`;
  const existing = new Set(((await api('GET', `${base}/alerts`)).alerts || []).map((a) => a.name));
  const skipped = bodies.filter((x) => existing.has(x.b.name)).length;
  console.log(`${bodies.length - skipped} alert(s) will be created in project ${env.PROJECT} of account ${env.ACCOUNT}${skipped ? ` (${skipped} already exist by name and are skipped)` : ''}.`);
  console.log('Check your alert quota in the Dashboard: your plan may limit how many alerts the account can have. If the API refuses a create, its message is printed and the run stops.');
  const created = [];
  const saveCreated = () => fs.writeFileSync(path.join(process.cwd(), 'created-alerts.json'), JSON.stringify(created, null, 1));
  for (const { b, channels } of bodies) {
    if (existing.has(b.name)) {
      console.log(`  exists, skipped: ${b.name}`);
      continue;
    }
    let res;
    try {
      res = await api('POST', `${base}/alert`, b);
    } catch (e) {
      if (created.length) saveCreated();
      throw new Error(`could not create "${b.name}": ${e.message}\nstopped: ${created.length} alert(s) created before this error${created.length ? ' (ids in created-alerts.json)' : ''}, ${bodies.length - skipped - created.length} not created. Fix the cause and run again; alerts that already exist by name are skipped.`);
    }
    const id = (res.alert && res.alert.id) || res.id;
    console.log(`  created ${id} ${b.name}`);
    created.push({ id, name: b.name, channels, missingChannels: [] });
  }
  // Read every created alert back once through the documented list endpoint and confirm its delivery channels.
  if (created.length) {
    const listed = new Map(((await api('GET', `${base}/alerts`)).alerts || []).map((a) => [a.id, a]));
    for (const c of created) {
      const a = listed.get(c.id);
      const kept = ((a && a.delivery_channels) || []).map((x) => x.id || (x.delivery_channel && x.delivery_channel.id));
      c.missingChannels = a ? c.channels.filter((x) => !kept.includes(x)) : c.channels;
      if (!a) console.log(`  WARNING: ${c.id} ${c.name} not found in the alert list, check it in the Dashboard`);
      else if (c.missingChannels.length) console.log(`  WARNING: delivery channel(s) missing on ${c.id} ${c.name}: ${c.missingChannels.join(', ')}, check the alert in the Dashboard`);
      delete c.channels;
    }
  }
  saveCreated();
  console.log(`${created.length} created, ids in created-alerts.json`);
})().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
