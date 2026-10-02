#!/usr/bin/env node
// announce.js: build and sign a request for changeRegistry.js (runs on your machine, not in Tenderly).
//
//   npm install ethers@5.7.2        (once, next to this file)
//
//   # announce: prints the message to sign, or the ready request body when a key or signature is given
//   node announce.js announce --network 143 --contract 0x... --kind role --role MINTER_ROLE \
//        --holder 0x... --days 7 --note "new bridge minter, vote 42"
//   ANNOUNCER_PRIVATE_KEY=0x... node announce.js announce ...           signs with that key
//   node announce.js announce ... --signature 0x...                      uses a signature from a hardware wallet
//   # cancel
//   node announce.js cancel --id a1b2c3d4 [--signature 0x...]
//
// The private key is only read from the environment and never printed. Prefer a signing-only
// hardware wallet: sign the printed message with personal_sign (EIP-191), then pass --signature.
// Send the printed body with:
//   curl -X POST https://api.tenderly.co/api/v1/actions/<actionId>/webhook -H 'content-type: application/json' -d '<body>'
//
// Options for announce: --network (default 143), --contract, --kind, --role (a name such as
// MINTER_ROLE, a 0x 32-byte id, a number for AccessManager or Solmate roles, or @PAUSER for a fixed
// role), --holder, --value (new threshold or delay in seconds), --days (validity, default 7, max 30),
// --from (unix start in whole seconds, default now), --note, --nonce (default random).

const crypto = require('crypto');
let ethers;
try {
  ({ ethers } = require('ethers'));
} catch (e) {
  console.error('ethers v5 is required: npm install ethers@5.7.2');
  process.exit(1);
}

const KINDS = ['owner', 'pending-owner', 'role', 'role-admin', 'authority', 'ward', 'proxy', 'proxy-admin', 'safe', 'timelock', 'minter', 'pause', 'any'];
const [cmd, ...rest] = process.argv.slice(2);
const opt = {};
for (let i = 0; i < rest.length; i += 2) {
  if (!rest[i].startsWith('--')) fail(`unexpected argument ${rest[i]}`);
  opt[rest[i].slice(2)] = rest[i + 1];
}
function fail(m) {
  console.error(m);
  process.exit(1);
}

// Keep equal to announcementMessage() in changeRegistry.js and privChangeGuard.js.
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

function roleId(r) {
  if (r === undefined) return null;
  if (/^0x[0-9a-fA-F]{64}$/.test(r)) return r.toLowerCase();
  if (/^@[A-Za-z0-9_]{2,32}$/.test(r)) return r.toUpperCase();
  if (/^\d{1,78}$/.test(r)) return '0x' + BigInt(r).toString(16).padStart(64, '0');
  if (/^[A-Z0-9_]{2,64}$/.test(r)) return ethers.utils.id(r); // keccak256 of the role name
  return fail(`role "${r}" is not an upper case role name, a 32-byte hex id, a number or @NAME`);
}

async function sign(message) {
  if (opt.signature) return opt.signature;
  const k = (process.env.ANNOUNCER_PRIVATE_KEY || '').trim();
  if (!k) return null;
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(k)) fail('ANNOUNCER_PRIVATE_KEY is not a 32-byte hex key');
  return new ethers.Wallet(k.startsWith('0x') ? k : '0x' + k).signMessage(message);
}

(async () => {
  if (cmd === 'announce') {
    if (!KINDS.includes(opt.kind)) fail(`--kind must be one of ${KINDS.join(', ')}`);
    if (!/^0x[0-9a-fA-F]{40}$/.test(opt.contract || '')) fail('--contract must be a 0x address');
    if (opt.holder && !/^0x[0-9a-fA-F]{40}$/.test(opt.holder)) fail('--holder must be a 0x address');
    const now = Math.floor(Date.now() / 1000);
    if (opt.from !== undefined && !/^\d{1,12}$/.test(opt.from)) fail('--from must be a unix start time in seconds (a whole number, for example 1790000000)');
    const validFrom = opt.from !== undefined ? Number(opt.from) : now;
    const days = Number(opt.days || 7);
    if (!(days > 0 && days <= 30)) fail('--days must be greater than 0 and at most 30');
    const a = {
      network: String(opt.network || '143'),
      contract: opt.contract.toLowerCase(),
      kind: opt.kind,
      role: roleId(opt.role),
      holder: opt.holder ? opt.holder.toLowerCase() : null,
      value: opt.value === undefined ? null : String(BigInt(opt.value)),
      validFrom,
      validUntil: validFrom + Math.floor(days * 86400),
      nonce: opt.nonce || crypto.randomBytes(16).toString('hex'),
      note: opt.note || '',
    };
    const message = announcementMessage(a);
    const signature = await sign(message);
    if (!signature) {
      console.log('Message to sign (EIP-191 personal_sign):\n----\n' + message + '\n----');
      console.log(`Sign it, then run the same command again with  --nonce ${a.nonce} --from ${a.validFrom} --signature 0x...  so the message stays identical.`);
      return;
    }
    const signer = ethers.utils.verifyMessage(message, signature);
    console.error(`signed by ${signer}`);
    console.log(JSON.stringify({ op: 'announce', announcement: a, signature }));
  } else if (cmd === 'cancel') {
    if (!/^[0-9a-f]{8}$/.test(opt.id || '')) fail('--id must be the 8-hex id of the announcement');
    const message = `Monad privileged change announcement v1 cancel\nid: ${opt.id}`;
    const signature = await sign(message);
    if (!signature) {
      console.log('Message to sign (EIP-191 personal_sign):\n----\n' + message + '\n----\nThen run the same command again with --signature 0x...');
      return;
    }
    console.error(`signed by ${ethers.utils.verifyMessage(message, signature)}`);
    console.log(JSON.stringify({ op: 'cancel', id: opt.id, signature }));
  } else fail('usage: node announce.js announce|cancel [options] (see the top of this file)');
})().catch((e) => fail(String(e.message || e).replace(/(?:0x)?[0-9a-fA-F]{64}/g, '[hex value redacted]').slice(0, 200)));
