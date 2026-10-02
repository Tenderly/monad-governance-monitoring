#!/usr/bin/env node
// Builds the `extended` and `monad-protocols` alert packs from the EVENTS tables of
// privChangeGuard.js and registers them in index.json. Run it again after editing the tables:
//   node alerts/build-extended-packs.js
// The rows of the core table are covered by the `core/` alerts (and the three timelock
// execution rows are context only); every other row that can change who holds power gets one
// Event Emitted alert, same shape as the core alerts: tag + emitted_log on the raw topic0.
// Safe ChangedMasterCopy belongs to the core `safe` pack (core/safe--changedmastercopy.json).
//
// WARNING: this script deletes the whole extended/ folder and regenerates it from scratch, and it
// rewrites the extended and monad-protocols entries (and the totals) in index.json. Hand edits to
// extended/*.json are lost on every run: change the EVENTS tables in privChangeGuard.js or this
// script instead, then run it again.
const fs = require('fs');
const path = require('path');
const G = require('../privChangeGuard.js');

const idxPath = path.join(__dirname, 'index.json');
const idx = JSON.parse(fs.readFileSync(idxPath, 'utf8'));
const have = new Set(Object.entries(idx.packs).filter(([k]) => !['extended', 'monad-protocols'].includes(k)).flatMap(([, p]) => p.alerts.map((a) => a.event_id.toLowerCase())));
const PROTOCOL = /Euler|Morpho|Uniswap V3|LayerZero|Curvance|Agora/;
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
const severityOf = ([, sig, kind, cls]) => {
  if (cls === 'notice') return 'info';
  if (/^PublicCapabilityUpdated/.test(sig)) return 'critical';
  if (cls === 'grant' && ['owner', 'proxy', 'proxy-admin', 'authority', 'minter', 'ward', 'timelock'].includes(kind)) return 'critical';
  return 'high';
};

const packs = { extended: { description: 'Less common standards: the rest of AccessManager, DefaultAdminRules, Solmate and Solady, DSGuard, Safe module and guard events, TimelockController and Compound scheduling, Circle MintController and token roles, Aave oracle and address registry, Diamond, Chainlink ConfirmedOwner.', alerts: [] }, 'monad-protocols': { description: 'Events of protocols deployed on Monad: Euler, Morpho Blue, Uniswap V3, LayerZero, Curvance, Agora.', alerts: [] } };
const dir = path.join(__dirname, 'extended');
fs.rmSync(dir, { recursive: true, force: true });
fs.mkdirSync(dir);
const used = new Set();
for (const row of G.EVENTS) {
  const [t0, sig, kind, cls, , family] = row;
  if (have.has(t0) || cls === 'trace') continue;
  if (['CallExecuted', 'ExecuteTransaction', 'OperationExecuted'].includes(sig.split('(')[0])) continue;
  const pack = PROTOCOL.test(family) ? 'monad-protocols' : 'extended';
  const event = sig.startsWith('LogNote') ? 'LogNote' : sig.split('(')[0];
  const shortFamily = family.split(',')[0];
  let file = `${pack}--${slug(event)}`;
  if (used.has(file)) file += `-${slug(shortFamily)}`;
  used.add(file);
  const sev = severityOf(row);
  const sigText = sig.length > 110 ? `${sig.slice(0, 107)}...` : sig;
  const body = {
    name: `GOV ${pack}: ${event} (${shortFamily})`,
    description: `${family}: ${sigText} emitted by a contract tagged ${idx.tag}. Default severity ${sev}. The privChangeGuard Web3 Action decodes the change, classifies the holder (EOA, EIP-7702, Safe, timelock) and checks for prior notice.`.slice(0, 500),
    enabled: true,
    expressions: [
      { type: 'tag', expression: { tag: idx.tag } },
      { type: 'emitted_log', expression: { address: '', match_any: true, match_non_project_contracts: false, event_name: event, event_id: t0.toLowerCase(), decode_events: false } },
    ],
    delivery_channels: [
      { id: '<PRIV_CHANGE_GUARD_ACTION_ID>', enabled: true },
      { id: '<NOTIFY_CHANNEL_ID>', enabled: true },
    ],
  };
  fs.writeFileSync(path.join(dir, `${file}.json`), JSON.stringify(body, null, 1) + '\n');
  packs[pack].alerts.push({ file: `extended/${file}.json`, event, event_id: t0.toLowerCase(), default_severity: sev });
}
for (const k of Object.keys(packs)) packs[k].count = packs[k].alerts.length; // keep a count on every pack, like the core packs
Object.assign(idx.packs, packs);
const count =(names) => names.reduce((n, k) => n + idx.packs[k].alerts.length, 0);
const core = Object.keys(idx.packs).filter((k) => !packs[k]);
idx.core_total = count(core);
idx.presets['everything in the core packs'] = core;
delete idx.presets.everything;
idx.presets['complete: every decoded family (core + extended + monad-protocols)'] = Object.keys(idx.packs);
idx.total = count(Object.keys(idx.packs));
fs.writeFileSync(idxPath, JSON.stringify(idx, null, 1) + '\n');
console.log(`extended ${packs.extended.alerts.length}, monad-protocols ${packs['monad-protocols'].alerts.length}, core ${idx.core_total}, total ${idx.total}`);
