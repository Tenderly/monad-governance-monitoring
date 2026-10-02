/*
 * privPostureAudit: Web3 Action for Monad mainnet (chain 143), one file. Default trigger: a block
 * trigger with a block skip (every 25 blocks, about 7.5 s). A cron trigger works too.
 *
 * QUESTION IT ANSWERS, CONTINUOUSLY
 *   Which privileged roles of the contracts you watch rely on an EOA (or on a 1-of-N Safe)
 *   instead of a multisig or a timelock, and what changed since the last run?
 *
 * WHAT IT DOES FOR EVERY TARGET
 *   1. reads the current privileged holders: owner, pending owner, proxy admin, AccessControl and
 *      Aave ACL role members (and each role's admin role), DSAuth owner and authority, wards, Safe
 *      signers and modules, FiatToken owner / masterMinter / pauser / blacklister / rescuer / minters;
 *   2. classifies every holder: EOA, EIP-7702 delegated EOA, Safe (threshold, signers, modules),
 *      timelock (delay) or other contract, and follows ONE hop (a ProxyAdmin to its owner, a Safe to
 *      its signers and modules);
 *   3. diffs the result against the previous run and alerts on: a NEW privileged holder (critical
 *      when it is an EOA or a contract controlled by one), a Safe threshold dropping to 1, a holder
 *      that changes type (a Safe replaced by an EOA, an EOA newly delegated with EIP-7702), a
 *      lowered timelock delay, a new Safe module, changed implementation or admin pointers.
 *   The first complete run of a target is its baseline. With CONFIG.baselinePostureAlert (default on)
 *   the baseline posts the standing posture once, at alert level: every privileged role or slot held
 *   by an EOA, an EIP-7702 EOA or a 1-of-N Safe. After that only changes are posted, plus a digest of
 *   the same standing list every digestEveryHours (a week by default).
 *
 *   Event alerts catch a change in the block it happens. This audit is the layer that also sees
 *   changes that emit no event (a Safe singleton pointer, a guard, an owner slot written directly),
 *   rebuilds role sets that cannot be enumerated on chain (from logs, incrementally, with a cursor in
 *   Storage) and answers "who can do what" when nothing happened.
 *
 * TWO SPEEDS PER RUN (this is what keeps a run far below the 30 s limit)
 *   Every run takes the cheap snapshot of EVERY target: owner(), pendingOwner(), DSAuth owner() and
 *   authority(), the EIP-1967 admin and implementation slots, a Safe's slot 0 (singleton), guard and
 *   fallback handler slots, owners, threshold and modules, confirmations of known role members with
 *   hasRole, and the classification of every holder. It is batched through Multicall3 and
 *   eth_getStorageAt, runs on several targets at once and is read at ONE block (head minus
 *   snapshotLagBlocks), so a provider that lags is skipped, never trusted.
 *   The expensive part, eth_getLogs reconstruction of role members, runs incrementally and round robin:
 *   a target whose members come from logs is due every logPassEveryS seconds, the oldest first, within
 *   logBudgetMs per run. A baseline or a catch-up gets a log pass on every run until it is complete.
 *
 * LIMITS (read before relying on it)
 *   - One hop only. A Safe is judged by its threshold, signers and modules, a timelock by its delay;
 *     who may PROPOSE on a timelock is not read (an EOA proposer behind a timelock looks like a timelock)
 *     unless the timelock is itself a target with patterns ["access-control"] and roles ["PROPOSER_ROLE"]
 *     (the audit then lists its proposers, and the privileged change guard reads that stored set).
 *   - Role sets are rebuilt from RoleGranted logs from `fromBlock`. A grant before `fromBlock` stays
 *     hidden unless the holder is in `candidates` or holds another role: set `fromBlock` to the deployment block.
 *   - A target is silent until its baseline is complete (SYNCING). Lowering `fromBlock` or editing a
 *     target's roles, candidates or patterns rescans it and adopts the result silently, once.
 *   - Freshness: a change in the cheap snapshot is seen by the first run whose snapshot block comes after it:
 *     at most one trigger interval plus snapshotLagBlocks (8.2 s on Monad at 25 blocks), then the run itself
 *     (about 3 s); a role member that exists only in logs is refreshed every logPassEveryS seconds (event alerts cover it in real time).
 *
 * TRIGGER  block (default), network 143, `blocks: 25` on Monad: blocks are 0.30 s, so a run every
 *          7.5 s and 40 runs per 5 minutes against the limit of 400 executions per 5 minutes for a
 *          sequential action. In our tests the runs landed on block numbers that are multiples of
 *          `blocks`. actionFn takes a block event
 *          ({ blockHash, blockNumber, network }) and a periodic event ({ time }) alike: the event only
 *          means "snapshot now". A cron trigger works too (every 5 or 10 minutes), see the README.
 * OVERLAP  Runs normally execute one at a time, but they can overlap (parallel execution, a sequential
 *          action that Tenderly may switch to parallel when it lags, a cron next to a block trigger, a
 *          manual run). A storage lease (CONFIG.lease) makes a run that finds another one active skip,
 *          so two runs rarely write the same state. The Storage API has no compare-and-set, so
 *          the lease is best effort (read, write own id, wait, read back, the last writer wins).
 * SECRETS  (Dashboard > Web3 Actions > Secrets, all optional)
 *   SLACK_WEBHOOK_URL  Slack incoming webhook; without it findings are only logged
 *   RPC_URL            preferred RPC for reads
 *   LOG_RPC_URL        preferred RPC for eth_getLogs
 * STORAGE  one key per target plus one meta key and one lease key, all under a prefix made of chainId and
 *          CONFIG.deploymentName (storage is shared by every action of the project: use one
 *          deploymentName per deployed copy). Every value stays well under the 100 KB limit. An unchanged
 *          target state is rewritten only every stateHeartbeatS seconds.
 *
 * READING GUIDE (search for the banner)
 *   CONFIG, constants, then: RPC layer, log scan, holder classification, pattern readers,
 *   diff and severity, notify, per-target run, lease, entry point (actionFn).
 *   Support code at the end: families used by a minority of contracts (dsauth, wards, fiat-token),
 *   the keccak256 implementation, the Multicall3 decoder.
 *
 * STORED STATE per target (short keys keep it small)
 *   roles  { key: { l label, a [holders], s Safe signer, m Safe module, p pending, f base severity,
 *                   c "high" caps a single-key holder at high, g pattern, miss first run it was unreadable } }
 *   ptr    { key: { l label, v value, g pattern } }   implementation, threshold, role admins, ...
 *   cls    { holder: class }  k eoa|eoa7702|safe|timelock|contract|none, t/n threshold/signers, v version,
 *                             sg signer kinds, sl signer list, ml modules, d timelock delay, dg 7702 delegate,
 *                             via { a, k, ... } the one-hop owner or admin
 *   scan   { key: { from, next } } log cursors      cand { key: [addresses] } log-derived candidates
 *   fp config fingerprint, rescan, sync, baselined, at, ms (cheap snapshot) and msd (log pass) run times,
 *   logAt last log pass, wAt last write, err, hist
 */

"use strict";

// ================================ CONFIG ================================
const CONFIG = {
  // ---- 1. What you edit ---------------------------------------------------
  // One short name per deployed copy of this action ([a-z0-9-], at most 31 characters). Storage is
  // shared by all actions of a Tenderly project: two copies with the same name overwrite each other.
  deploymentName: "example",
  chainId: 143,
  chainName: "Monad",
  explorerAddressUrl: "https://monadscan.com/address/",

  // One entry per contract to audit.
  //   address    contract address
  //   label      name used in messages
  //   patterns   any of: ownable, access-control, aave-acl, eip1967, safe (everyday families)
  //              and dsauth, wards, fiat-token (less common, readers at the end of the file)
  //   roles      access-control only: role names ("MINTER_ROLE"), bytes32 ids, or "*" for every role
  //              seen in RoleGranted logs. Default: DEFAULT_ADMIN_ROLE plus "*".
  //   roleNames  optional extra role names, only used to label role ids found in logs
  //   candidates optional addresses to always check with hasRole / wards
  //   fromBlock  block to start log reconstruction from (the deployment block is ideal)
  // Replace the examples with your own contracts (uncomment and edit):
  targets: [
    // { label: "My lending market PoolAddressesProvider", address: "0x...", patterns: ["ownable", "aave-acl"], fromBlock: 0 },
    // { label: "My timelock", address: "0x...", patterns: ["access-control"], roles: ["DEFAULT_ADMIN_ROLE", "PROPOSER_ROLE", "EXECUTOR_ROLE", "CANCELLER_ROLE"], fromBlock: 0 },
    // { label: "My token", address: "0x...", patterns: ["fiat-token", "eip1967"], fromBlock: 0 },
    // { label: "My multisig", address: "0x...", patterns: ["safe"] },
    // { label: "My vault", address: "0x...", patterns: ["ownable", "eip1967"] },
    // { label: "My legacy contract", address: "0x...", patterns: ["dsauth"] },
    // { label: "My MCD style core", address: "0x...", patterns: ["wards"], fromBlock: 0 },
  ],

  // ---- 2. Notifications and acknowledgements -------------------------------
  notifyMinSeverity: "medium", // critical | high | medium | low | info. Findings below it are not posted; "low" posts every diff (a node hiccup then also posts a "role not readable this run" line)
  // A timelock whose delay is below this is a short-delay timelock (high, like a delay of 0), as in the guard's minNoticeSeconds.
  minNoticeSeconds: 3600,
  // When a target's first baseline completes, post every privileged role or slot held by an EOA, an
  // EIP-7702 EOA or a 1-of-N Safe, once, at alert level (same severities as a new holder would get).
  // false: the baseline stays silent and the first word is the digest below.
  baselinePostureAlert: true,
  digestEveryHours: 168, // standing posture digest to Slack (0 = off)
  unreadableAlertAfterHours: 6, // alert when a target could not be read (or baselined) for this long
  syncingAlertAfterHours: 6, // alert (with an ETA) when a log catch-up takes this long
  // Reviewed keys, for example a token issuer's operational keys. The acknowledgement matches the
  // holder itself or the key behind it (the owner of a ProxyAdmin or masterMinter contract).
  // It drops the standing-digest row and lowers a NEW holder with that exact key to "info". It never
  // hides a holder type change, a threshold drop, a lowered delay or a change of the controlling owner.
  // knownKeys: { "0xabc...": "issuer pauser key, reviewed 2026-10-01" },
  knownKeys: {},
  // EIP-7702 delegates you accept on Safe signers (a newly delegated signer is "low" instead of "medium").
  // knownDelegates: { "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b": "EIP7702StatelessDeleGator" },
  knownDelegates: {},

  // ---- 3. Advanced, rarely changed ------------------------------------------
  // Run sizing. Default deployment: block trigger, `blocks: 25` = about 7.5 s on Monad = 40 runs per 5 minutes.
  snapshotLagBlocks: 2, // every state read of a run is pinned to head minus this (0.6 s on Monad): one consistent block
  concurrency: 4, // targets snapshotted at the same time
  logPassEveryS: 30, // a target whose members come from logs gets a log pass at most this often (oldest first)
  logBudgetMs: 5000, // estimated time per run for log passes; at least one pass runs when one is due
  lease: true, // storage lease against overlapping runs, see OVERLAP at the top of the file
  leaseTtlMs: 32000, // a run that dies without releasing blocks the next ones for at most this long
  leaseSettleMs: 150, // wait after writing the lease before reading it back
  stateHeartbeatS: 600, // an unchanged target state or meta is rewritten only this often
  // Reads (eth_call, eth_getCode, eth_getStorageAt), tried in order.
  rpcUrls: ["https://rpc.monad.xyz", "https://rpc1.monad.xyz", "https://rpc2.monad.xyz"],
  // eth_getLogs, tried in order, biggest learned range first. The action shrinks the range
  // automatically when a provider refuses and remembers what each provider accepted for a day.
  logRpcUrls: ["https://rpc1.monad.xyz", "https://rpc2.monad.xyz", "https://rpc.monad.xyz"],
  multicall3: "0xcA11bde05977b3631167028862bE2a173976CA11",
  storagePrefix: "", // empty: privPosture:v1:<chainId>:<deploymentName>

  logChunkStart: 1000000, // first eth_getLogs range (blocks); grows x2 when results are small
  logChunkMax: 25000000,
  logChunkMin: 100,
  confirmations: 30, // log scans stop this many blocks behind head (about 9 s on Monad): providers differ by several blocks
  rpcTimeoutMs: 6000,

  runLimitMs: 30000, // the default Web3 Actions execution limit (30 s)
  // Keep a run shorter than the trigger interval (7.5 s): Tenderly may switch a sequential action whose
  // runs keep outlasting its triggers to parallel execution (docs.tenderly.co/troubleshooting/web3-actions).
  // A cron deployment can raise it to 18000.
  runBudgetMs: 9000, // stop starting new targets after this
  hardDeadlineMs: 22000, // RPC calls after this abort the current target, leaving time to notify and save
  minLeftForScanMs: 2500, // stop a log scan when less than this is left; it resumes next turn
  maxScanMsPerTarget: 5000, // log catch-up time per target per run, so one backfill cannot starve the others
  defaultTargetMs: 1500, // cost estimate for a target whose cheap snapshot was never measured
  defaultDeepMs: 2500, // same for a log pass
  slackTimeoutMs: 5000,
  storageOpMs: 150, // assumed worst case of one Storage call, used to reserve time for saving
  forgetRemovedAfterDays: 7, // state of a target that left CONFIG is deleted after this long

  maxMembersPerRole: 50, // enumerable roles: members read per role
  maxRoleIds: 100, // roles ["*"]: role ids audited per target
  maxCandidates: 300, // log-derived candidate addresses kept per target
  maxSigners: 20, // Safe signers classified per Safe
};

// ============================ constants ============================
// Selectors: `cast sig '<signature>'`. Topics and slots: `cast keccak`.
const SEL = {
  owner: "0x8da5cb5b", // owner()
  pendingOwner: "0xe30c3978", // pendingOwner()
  hasRole: "0x91d14854", // hasRole(bytes32,address)
  getRoleMemberCount: "0xca15c873", // getRoleMemberCount(bytes32)
  getRoleMember: "0x9010d07c", // getRoleMember(bytes32,uint256)
  defaultAdmin: "0x84ef8ffc", // defaultAdmin()
  pendingDefaultAdmin: "0xcf6eefb7", // pendingDefaultAdmin()
  getACLAdmin: "0x0e67178c", // getACLAdmin()
  getACLManager: "0x707cd716", // getACLManager()
  getPool: "0x026b1d5f", // getPool()
  getPoolConfigurator: "0x631adfca", // getPoolConfigurator()
  getPriceOracle: "0xfca513a8", // getPriceOracle()
  ADDRESSES_PROVIDER: "0x0542975c", // ADDRESSES_PROVIDER()
  authority: "0xbf7e214f", // authority()
  wards: "0xbf353dbb", // wards(address)
  masterMinter: "0x35d99f35", // masterMinter()
  pauser: "0x9fd0506d", // pauser()
  blacklister: "0xbd102430", // blacklister()
  rescuer: "0x38a63183", // rescuer()
  isMinter: "0xaa271e1a", // isMinter(address)
  minterAllowance: "0x8a6db9c3", // minterAllowance(address)
  getThreshold: "0xe75235b8", // getThreshold()
  getOwners: "0xa0e67e2b", // getOwners()
  VERSION: "0xffa1ad74", // VERSION()
  getModulesPaginated: "0xcc2f8452", // getModulesPaginated(address,uint256)
  getMinDelay: "0xf27a0c92", // getMinDelay()
  delay: "0x6a42b8f8", // delay()
  admin: "0xf851a440", // admin()
  aggregate3: "0x82ad56cb", // aggregate3((address,bool,bytes)[])
  getRoleAdmin: "0x248a9ca3", // getRoleAdmin(bytes32)
  PROPOSER_ROLE: "0x8f61f4f5", // PROPOSER_ROLE()
  GRACE_PERIOD: "0xc1a287e2", // GRACE_PERIOD()
};

const TOPIC = {
  RoleGranted: "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d", // RoleGranted(bytes32,address,address)
  RoleRevoked: "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b", // RoleRevoked(bytes32,address,address)
  Rely: "0xdd0e34038ac38b2a1ce960229778ac48a8719bc900b6c4f8d0475c6e8b385a60", // Rely(address)
  Deny: "0x184450df2e323acec0ed3b5c7531b81f9b4cdef7914dfd4c0a4317416bb5251b", // Deny(address)
  // Maker LibNote: anonymous log, topic0 = function selector left-aligned, topic2 = usr
  NoteRely: "0x65fae35e00000000000000000000000000000000000000000000000000000000", // rely(address)
  NoteDeny: "0x9c52a7f100000000000000000000000000000000000000000000000000000000", // deny(address)
  MinterConfigured: "0x46980fca912ef9bcdbd36877427b6b90e860769f604e89c0e67720cece530d20", // MinterConfigured(address,uint256)
  MinterRemoved: "0xe94479a9f7e1952cc78f2d6baab678adc1b772d936c6583def489e524cb66692", // MinterRemoved(address)
};

const SLOT = {
  implementation: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", // EIP-1967
  admin: "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", // EIP-1967
  beacon: "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", // EIP-1967
  zosImplementation: "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3", // zos / Circle FiatTokenProxy
  zosAdmin: "0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b",
  safeSingleton: "0x0000000000000000000000000000000000000000000000000000000000000000",
  safeGuard: "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8",
  safeFallbackHandler: "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5",
};

const ZERO = "0x0000000000000000000000000000000000000000";
const SENTINEL = "0x0000000000000000000000000000000000000001";
const ZERO32 = "0x" + "0".repeat(64);
const PATTERNS = ["ownable", "access-control", "aave-acl", "dsauth", "wards", "eip1967", "safe", "fiat-token"];
const SEV = ["info", "low", "medium", "high", "critical"];
const sevRank = (s) => Math.max(0, SEV.indexOf(s));
const PROPOSER_ROLE_ID = "0xb09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1"; // keccak256("PROPOSER_ROLE")
const SAFE_VERSION = /^1\.\d+\.\d+/;
// Roles whose holder, even a single key, is a high but not a critical finding.
const LOW_RISK_ROLES = new Set(["PAUSER_ROLE", "KEEPER_ROLE", "OPERATOR_ROLE", "FLASH_BORROWER", "EMERGENCY_ADMIN", "RISK_ADMIN", "ASSET_LISTING_ADMIN"]);

// ============================ hex / ABI ============================
const strip0x = (h) => (String(h).startsWith("0x") ? String(h).slice(2) : String(h));
const pad32 = (h) => strip0x(h).padStart(64, "0");
const encAddr = (a) => pad32(String(a).toLowerCase());
const encUint = (n) => pad32(BigInt(n).toString(16));
const hexNum = (n) => "0x" + Number(n).toString(16);
const isAddr = (a) => typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a);
const lc = (a) => String(a).toLowerCase();
const short = (a) => (a && a.length === 42 ? a.slice(0, 6) + "..." + a.slice(-4) : String(a));
const sha = (s) => require("crypto").createHash("sha1").update(String(s)).digest("hex");

function words(hex) {
  const h = strip0x(hex || "");
  const out = [];
  for (let i = 0; i + 64 <= h.length; i += 64) out.push(h.slice(i, i + 64));
  return out;
}
const wordToBig = (w) => BigInt("0x" + w);
const wordIsAddr = (w) => /^0{24}[0-9a-f]{40}$/i.test(w);
const wordToAddr = (w) => "0x" + w.slice(24).toLowerCase();

// Typed readers over a multicall result {ok, data}. A revert, an empty return or a
// return of the wrong shape all mean "this function is not there": null.
function rAddr(r) {
  if (!r || !r.ok) return null;
  const w = words(r.data);
  if (w.length < 1 || !wordIsAddr(w[0])) return null;
  return wordToAddr(w[0]);
}
function rUint(r) {
  if (!r || !r.ok) return null;
  const w = words(r.data);
  return w.length ? wordToBig(w[0]) : null;
}
function rBool(r) {
  const v = rUint(r);
  return v === null ? null : v !== 0n;
}
function rWord(r) {
  if (!r || !r.ok) return null;
  const w = words(r.data);
  return w.length ? "0x" + w[0] : null;
}
function rAddrArray(r) {
  if (!r || !r.ok) return null;
  const w = words(r.data);
  if (w.length < 2) return null;
  const off = Number(wordToBig(w[0])) / 32;
  if (!Number.isInteger(off) || off >= w.length) return null;
  const n = Number(wordToBig(w[off]));
  if (!Number.isFinite(n) || n < 0 || n > 1000 || off + 1 + n > w.length) return null;
  const out = [];
  for (let i = 0; i < n; i++) {
    if (!wordIsAddr(w[off + 1 + i])) return null;
    out.push(wordToAddr(w[off + 1 + i]));
  }
  return out;
}
function rString(r) {
  if (!r || !r.ok) return null;
  try {
    const w = words(r.data);
    if (w.length < 2) return null;
    const off = Number(wordToBig(w[0])) / 32;
    const len = Number(wordToBig(w[off]));
    if (!Number.isFinite(len) || len > 64) return null;
    const raw = strip0x(r.data).slice((off + 1) * 64, (off + 1) * 64 + len * 2);
    return Buffer.from(raw, "hex").toString("utf8").replace(/[^\x20-\x7e]/g, "");
  } catch (e) {
    return null;
  }
}
const normWord = (v) => "0x" + strip0x(v || "0").toLowerCase().padStart(64, "0");
const slotAddr = (w) => (/^0x0{24}[0-9a-f]{40}$/.test(w) ? "0x" + w.slice(26) : null);

// ============================ role ids ============================
// Aave hashes the bare name ("POOL_ADMIN"); OpenZeppelin conventions use "<NAME>_ROLE".
const AAVE_ROLES = ["DEFAULT_ADMIN_ROLE", "POOL_ADMIN", "EMERGENCY_ADMIN", "RISK_ADMIN", "ASSET_LISTING_ADMIN", "BRIDGE", "FLASH_BORROWER"];
const KNOWN_ROLE_NAMES = [
  "POOL_ADMIN", "EMERGENCY_ADMIN", "RISK_ADMIN", "ASSET_LISTING_ADMIN", "BRIDGE", "FLASH_BORROWER",
  "TIMELOCK_ADMIN_ROLE", "PROPOSER_ROLE", "EXECUTOR_ROLE", "CANCELLER_ROLE",
  "MINTER_ROLE", "PAUSER_ROLE", "BURNER_ROLE", "UPGRADER_ROLE", "ADMIN_ROLE", "GUARDIAN_ROLE",
  "OPERATOR_ROLE", "MANAGER_ROLE", "KEEPER_ROLE",
];
let ROLE_LABEL; // built on first use (needs keccak256)
function roleLabels() {
  if (!ROLE_LABEL) {
    ROLE_LABEL = new Map([[ZERO32, "DEFAULT_ADMIN_ROLE"]]);
    for (const n of KNOWN_ROLE_NAMES) ROLE_LABEL.set(keccakText(n), n);
  }
  return ROLE_LABEL;
}
function roleId(spec) {
  if (spec === "DEFAULT_ADMIN_ROLE") return ZERO32;
  if (/^0x[0-9a-fA-F]{64}$/.test(spec)) return lc(spec);
  return keccakText(spec);
}
function roleLabel(id, extra) {
  if (extra && extra.has(id)) return extra.get(id);
  if (roleLabels().has(id)) return roleLabels().get(id);
  // Some protocols use a function selector, left-aligned, as the role id.
  if (/^0x[0-9a-f]{8}0{56}$/.test(id) && id !== ZERO32) return "selector role " + id.slice(0, 10);
  return "role " + id.slice(0, 10) + "...";
}

// ============================ RPC layer ============================
function tag(err, kind) {
  err.kind = kind;
  return err;
}
const isRateMsg = (m) => /rate.?limit|too many requests|-32005|capacity|throttl/i.test(m);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// A revert is a real answer ("this function is not there"). Any other node error is not an answer.
const isRevert = (e) => !!e && e.kind === "rpc" && /revert|"code":3[,}]|invalid opcode|out of gas|stack (under|over)flow/i.test(e.message);
// A node that has not reached the requested block yet (it lags the head another provider reported). Monad
// providers answer "Block requested not found. Request might be querying historical state that is not available".
const isAheadErr = (e) => !!e && (e.kind === "rpc" || e.kind === "http") && /beyond (the )?(current )?head|not (yet )?available|after (the )?(latest|head)|future block|block requested not found|header not found|unknown block/i.test(e.message);

async function postJson(url, payload, timeoutMs) {
  let r;
  let text;
  try {
    r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs || CONFIG.rpcTimeoutMs),
    });
    text = await r.text();
  } catch (e) {
    // The URL is never put in the message: a provider URL can carry an API key.
    throw tag(new Error(e && e.name === "TimeoutError" ? "rpc timeout" : "rpc transport error"), "transport");
  }
  if (r.status === 429) throw tag(new Error("HTTP 429"), "rate");
  if (r.status >= 500) throw tag(new Error("HTTP " + r.status), "transport");
  let j;
  try {
    j = JSON.parse(text);
  } catch (e) {
    throw tag(new Error("HTTP " + r.status + " non-JSON body"), r.ok ? "transport" : "http");
  }
  if (!r.ok && !(j && (j.error || Array.isArray(j)))) throw tag(new Error("HTTP " + r.status), "http");
  return j;
}

// knownCaps: log range limits learned on earlier runs, { urlHash: { c: blocks, t: unix seconds } }.
function makeRpc(secretCallUrl, secretLogUrl, deadlineAt, knownCaps) {
  const down = new Set();
  // Every request is bounded by the run's hard deadline, so a slow provider can never
  // push the execution past the platform limit with state still unsaved.
  const budget = () => {
    const left = deadlineAt - Date.now();
    if (left < 250) throw tag(new Error("run deadline reached"), "deadline");
    return Math.min(CONFIG.rpcTimeoutMs, left);
  };
  // Hosts that failed at transport level this run go last.
  const order = (list) => [...list.filter((u) => !down.has(u)), ...list.filter((u) => down.has(u))];
  const callUrls = [...(secretCallUrl ? [secretCallUrl] : []), ...CONFIG.rpcUrls];
  const logUrls = [...(secretLogUrl ? [secretLogUrl] : []), ...CONFIG.logRpcUrls];
  const stats = { requests: 0 };
  // State reads ask for "latest"; setBlock pins them all to one block number for the run, so every read of
  // a run sees the same block and a provider that has not reached it answers "not found" and is skipped.
  let block = "latest";
  const pin = (params) => (Array.isArray(params) ? params.map((p) => (p === "latest" ? block : p)) : params);
  const nowS = () => Math.floor(Date.now() / 1000);
  const keyOf = (u) => sha(u).slice(0, 10); // caps are stored by hash: a provider URL can carry an API key

  async function request(urls, method, params) {
    let last;
    const pinned = pin(params);
    for (const url of order(urls)) {
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          stats.requests++;
          const j = await postJson(url, { jsonrpc: "2.0", id: 1, method, params: pinned }, budget());
          if (j.error) {
            const m = JSON.stringify(j.error).slice(0, 240);
            throw tag(new Error(method + ": " + m), isRateMsg(m) ? "rate" : "rpc");
          }
          return j.result;
        } catch (e) {
          last = e;
          if (e.kind === "rpc" && isAheadErr(e) && !isRevert(e)) {
            down.add(url); // this provider has not reached the pinned block: it goes last, ask the next one
            break;
          }
          if (e.kind === "rpc" || e.kind === "deadline") throw e; // the node answered, or time is up
          if (e.kind === "rate") {
            await sleep(400 * (attempt + 1)); // rate limited: back off, retry the same provider
            continue;
          }
          if (e.kind === "transport") down.add(url);
          break;
        }
      }
    }
    throw last;
  }

  // JSON-RPC batch; falls back to single requests when a provider does not batch.
  async function batch(method, paramsList) {
    const out = new Array(paramsList.length);
    for (let s = 0; s < paramsList.length; s += 40) {
      const part = paramsList.slice(s, s + 40);
      let done = false;
      for (const url of order(callUrls)) {
        try {
          stats.requests++;
          const j = await postJson(url, part.map((p, i) => ({ jsonrpc: "2.0", id: i + 1, method, params: pin(p) })), budget());
          if (!Array.isArray(j)) break; // batching not supported here: go single
          const byId = new Map(j.map((x) => [x.id, x]));
          if (part.some((p, i) => !byId.has(i + 1) || byId.get(i + 1).error)) break;
          part.forEach((p, i) => (out[s + i] = byId.get(i + 1).result));
          done = true;
          break;
        } catch (e) {
          if (e.kind === "deadline") throw e;
          if (e.kind === "transport") down.add(url);
          if (e.kind === "rate") await sleep(300);
        }
      }
      if (!done) for (let i = 0; i < part.length; i++) out[s + i] = await request(callUrls, method, part[i]);
    }
    return out;
  }

  // Multicall3.aggregate3 with allowFailure: a revert comes back as {ok:false}. Only a revert
  // means "function absent": any other node error (for example -32603 internal error) is not an
  // answer, so the target becomes unreadable and its stored posture is kept.
  async function multicall(calls) {
    const out = [];
    for (let s = 0; s < calls.length; s += 100) {
      const part = calls.slice(s, s + 100);
      const tuples = part.map((c) => {
        const d = strip0x(c.data);
        const padded = d.padEnd(Math.ceil(d.length / 64) * 64, "0");
        return encAddr(c.to) + encUint(1) + encUint(0x60) + encUint(d.length / 2) + padded;
      });
      let offsets = "";
      let cursor = part.length * 32;
      for (const t of tuples) {
        offsets += encUint(cursor);
        cursor += t.length / 2;
      }
      const payload = SEL.aggregate3 + encUint(0x20) + encUint(part.length) + offsets + tuples.join("");
      let ret;
      try {
        ret = await request(callUrls, "eth_call", [{ to: CONFIG.multicall3, data: payload }, "latest"]);
      } catch (e) {
        if (e.kind !== "rpc") throw e;
        ret = null; // Multicall3 itself failed: single calls below
      }
      const decoded = ret ? decodeAggregate3(ret, part.length) : null;
      if (decoded) {
        out.push(...decoded);
        continue;
      }
      for (const c of part) {
        try {
          const r = await request(callUrls, "eth_call", [{ to: c.to, data: c.data }, "latest"]);
          out.push({ ok: !!r && r !== "0x", data: r || "0x" });
        } catch (e) {
          if (isRevert(e)) {
            out.push({ ok: false, data: "0x" }); // a revert is an answer: the function is absent
            continue;
          }
          throw e.kind === "rpc" ? tag(new Error(e.message), "transport") : e;
        }
      }
    }
    return out;
  }

  // eth_getLogs over [from, to] limited to `want` blocks. Each provider keeps its own learned
  // range limit (from its error message, or halved), remembered for a day, and the provider
  // that accepts the widest ranges goes first. Returns the logs and the last block covered.
  const logCap = new Map();
  for (const [h, v] of Object.entries(knownCaps || {})) if (v && nowS() - v.t < 86400) logCap.set(h, { c: v.c, t: v.t });
  const capOf = (u) => (logCap.has(keyOf(u)) ? logCap.get(keyOf(u)).c : Infinity);
  async function logs(address, topics, from, to, want) {
    let last;
    // Providers that failed or lag this run go last, then the widest learned range first.
    const ranked = logUrls.map((u, i) => ({ u, i })).sort((a, b) => down.has(a.u) - down.has(b.u) || (capOf(b.u) > capOf(a.u)) - (capOf(b.u) < capOf(a.u)) || a.i - b.i).map((x) => x.u);
    for (const url of ranked) {
      let range = Math.min(want, capOf(url));
      let rateTries = 0;
      for (;;) {
        const end = Math.min(to, from + range - 1);
        try {
          stats.requests++;
          const j = await postJson(url, { jsonrpc: "2.0", id: 1, method: "eth_getLogs", params: [{ address, topics, fromBlock: hexNum(from), toBlock: hexNum(end) }] }, budget());
          if (j.error) {
            const m = JSON.stringify(j.error).slice(0, 240);
            throw tag(new Error("eth_getLogs: " + m), isRateMsg(m) ? "rate" : "rpc");
          }
          if (!Array.isArray(j.result)) throw tag(new Error("eth_getLogs: malformed result"), "transport");
          return { logs: j.result, end };
        } catch (e) {
          last = e;
          if (e.kind === "deadline") throw e;
          if (isAheadErr(e)) {
            e.ahead = true; // this provider lags: not a range limit. It goes last for the rest of the run; if all lag, the scan waits.
            down.add(url);
            break;
          }
          if (isRangeErr(e) && range > CONFIG.logChunkMin) {
            const lim = rangeLimitFrom(e);
            range = Math.max(CONFIG.logChunkMin, lim && lim < range ? lim : Math.floor(range / 2));
            logCap.set(keyOf(url), { c: range, t: nowS() });
            continue; // same provider, smaller range
          }
          if (e.kind === "rate" && rateTries++ < 2) {
            await sleep(400 * rateTries); // rate limited: back off, retry the same provider
            continue;
          }
          if (e.kind === "transport") down.add(url);
          break; // next provider
        }
      }
    }
    throw last;
  }

  return {
    stats,
    request,
    batch,
    multicall,
    logs,
    setBlock: (n) => {
      block = hexNum(n);
    },
    block: () => block,
    call: (method, params) => request(callUrls, method, params),
    caps: () => Object.fromEntries([...logCap.entries()].filter(([, v]) => nowS() - v.t < 86400)), // for meta
  };
}

function decodeAggregate3(ret, n) {
  try {
    const w = words(ret);
    if (!w.length) return null;
    const base = Number(wordToBig(w[0])) / 32;
    if (Number(wordToBig(w[base])) !== n) return null;
    const out = [];
    for (let i = 0; i < n; i++) {
      const ts = base + 1 + Number(wordToBig(w[base + 1 + i])) / 32;
      const success = wordToBig(w[ts]) !== 0n;
      const bytesOff = Number(wordToBig(w[ts + 1])) / 32;
      const len = Number(wordToBig(w[ts + bytesOff]));
      const start = (ts + bytesOff + 1) * 64;
      const data = "0x" + strip0x(ret).slice(start, start + len * 2);
      out.push({ ok: success && len > 0, data: len ? data : "0x" });
    }
    return out;
  } catch (e) {
    return null;
  }
}
// ============================ storage ============================
// A missing key reads back as "": that is not an error. A failing Storage call is one, and must
// never be mistaken for "missing" (the target would be silently re-baselined).
async function loadJson(context, key) {
  const raw = await context.storage.getStr(key);
  return raw ? JSON.parse(raw) : null;
}
async function saveJson(context, key, val) {
  await context.storage.putStr(key, JSON.stringify(val));
}
async function secret(context, name) {
  try {
    const v = await context.secrets.get(name);
    return typeof v === "string" && v.trim() ? v.trim() : null;
  } catch (e) {
    return null; // SecretNotFound
  }
}
const prefix = () => CONFIG.storagePrefix || "privPosture:v1:" + CONFIG.chainId + ":" + CONFIG.deploymentName;
const metaKey = () => prefix() + ":meta";
const targetKey = (addr) => prefix() + ":t:" + addr;

// ============================ log reconstruction ============================
function isRangeErr(e) {
  if (!e || (e.kind !== "rpc" && e.kind !== "http")) return false;
  return /range|limit|exceed|more than|too large|response size|HTTP 4(00|13)/i.test(e.message);
}
function rangeLimitFrom(e) {
  const m = /limited to a (\d+)|up to a (\d+)(k?) block|(\d+) block range/i.exec(e.message);
  if (!m) return null;
  const n = Number(m[1] || m[2] || m[4]);
  return m[3] ? n * 1000 : n;
}

// Scans logs of `address` with any of `topic0s` from the stored cursor to head. The cursor
// { from, next } lives in w.scan[key]: it moves forward, so each run reads only new blocks, and a
// LOWER configured fromBlock moves it back (a rescan). At least one range is read per call
// (progress is guaranteed); after that it stops when the run budget or this target's scan time
// is used up, and the target's next turn resumes from the cursor.
// A target on the cheap snapshot only (w.fast) reads no logs: its candidates stay as stored and are
// confirmed with hasRole / wards / isMinter; its log pass comes on a later run (see wantsLogs).
async function scanLogs(ctx, w, key, address, topic0s, fromBlock) {
  if (w.fast) return { logs: [], done: true, skipped: true };
  let cur = w.scan[key];
  if (!cur || !Number.isInteger(cur.next)) cur = { from: fromBlock, next: fromBlock };
  if (!Number.isInteger(cur.from)) cur.from = fromBlock;
  if (fromBlock < cur.from) {
    cur.from = fromBlock;
    cur.next = fromBlock; // the configured start moved back: read the older blocks too
    w.rescan = true;
  } else if (cur.next < fromBlock) cur.next = fromBlock;
  w.scan[key] = cur;
  const to = ctx.head - CONFIG.confirmations;
  const logs = [];
  let calls = 0;
  while (cur.next <= to) {
    if (calls > 0 && (ctx.left() < CONFIG.minLeftForScanMs || Date.now() > w.scanUntil)) return { logs, done: false };
    let res;
    try {
      res = await ctx.rpc.logs(address, [topic0s], cur.next, to, ctx.chunk);
    } catch (e) {
      if (e.ahead) return { logs, done: false }; // the providers have not reached these blocks yet: wait for the next run
      // Progress was made: keep it and finish this target's turn as a partial scan.
      if (calls > 0 && (e.kind === "rate" || e.kind === "transport")) return { logs, done: false };
      throw e;
    }
    logs.push(...res.logs);
    ctx.logCalls++;
    calls++;
    cur.next = res.end + 1;
    if (res.logs.length < 2000 && ctx.chunk < CONFIG.logChunkMax) ctx.chunk = Math.min(CONFIG.logChunkMax, ctx.chunk * 2);
  }
  return { logs, done: true };
}

function addCand(w, key, addr) {
  if (!isAddr(addr)) return;
  const list = w.cand[key] || (w.cand[key] = []);
  if (!list.includes(addr)) list.push(addr);
}
const topicAddr = (t) => (t && t.length === 66 ? "0x" + t.slice(26).toLowerCase() : null);

// ============================ holder classification ============================
// Basic class of one address: eoa | eoa7702 | safe | timelock | contract | none.
// Safe: VERSION() 1.x.y, getThreshold() >= 1 and a non-empty getOwners() at least as long as the
// threshold (the Safe singleton and look-alikes fail one of them). Timelock: getMinDelay() with the
// OZ PROPOSER_ROLE() constant, or the Compound trio admin(), delay(), GRACE_PERIOD(). A bare
// delay() getter is only a contract.
async function probeBasic(ctx, addrs) {
  const todo = [...new Set(addrs.map(lc))].filter((a) => a !== ZERO && !ctx.basic.has(a));
  if (!todo.length) return;
  const codes = await ctx.rpc.batch("eth_getCode", todo.map((a) => [a, "latest"]));
  const contracts = [];
  todo.forEach((a, i) => {
    const code = typeof codes[i] === "string" ? codes[i].toLowerCase() : null;
    if (code === null) throw tag(new Error("eth_getCode returned nothing for " + a), "transport");
    if (code === "0x" || code === "0x0") ctx.basic.set(a, { k: "eoa" });
    else if (code.startsWith("0xef0100") && code.length === 48) ctx.basic.set(a, { k: "eoa7702", dg: "0x" + code.slice(8) });
    else contracts.push(a);
  });
  if (!contracts.length) return;
  const probes = [SEL.getThreshold, SEL.getOwners, SEL.VERSION, SEL.getMinDelay, SEL.PROPOSER_ROLE, SEL.delay, SEL.admin, SEL.GRACE_PERIOD, SEL.owner];
  const modCall = SEL.getModulesPaginated + encAddr(SENTINEL) + encUint(10);
  const stride = probes.length + 1;
  const res = await ctx.rpc.multicall(contracts.flatMap((a) => [...probes.map((p) => ({ to: a, data: p })), { to: a, data: modCall }]));
  contracts.forEach((a, i) => {
    const [thr, own, ver, minDelay, proposer, delay, admin, grace, owner, mods] = res.slice(i * stride, (i + 1) * stride);
    const t = rUint(thr);
    const owners = rAddrArray(own);
    const v = rString(ver);
    if (t !== null && owners && owners.length && t >= 1n && t <= BigInt(owners.length) && owners.length <= 500 && v && SAFE_VERSION.test(v)) {
      const ml = readModules(mods);
      ctx.basic.set(a, { k: "safe", t: Number(t), n: owners.length, v, owners, mods: ml.filter((m) => !/^0xf{40}$/.test(m)).sort(), modsTrunc: ml.some((m) => /^0xf{40}$/.test(m)) });
      return;
    }
    const md = rUint(minDelay);
    if (md !== null && md < 315360000n && rWord(proposer) === PROPOSER_ROLE_ID) {
      ctx.basic.set(a, { k: "timelock", d: Number(md) });
      return;
    }
    const dl = rUint(delay);
    const ad = rAddr(admin);
    const gp = rUint(grace);
    if (dl !== null && dl < 315360000n && ad && gp !== null && gp > 0n) {
      ctx.basic.set(a, { k: "timelock", d: Number(dl), via: ad }); // Compound-style: admin queues
      return;
    }
    const ow = rAddr(owner);
    ctx.basic.set(a, ow && ow !== ZERO ? { k: "contract", via: ow } : { k: "contract" });
  });
}

// Full class with one hop: Safe signers and modules, and the owner / admin of a contract.
async function classify(ctx, addrs) {
  const list = [...new Set(addrs.map(lc))];
  await probeBasic(ctx, list);
  const hop = [];
  for (const a of list) {
    const b = ctx.basic.get(a);
    if (!b) continue;
    if (b.k === "safe") hop.push(...b.owners.slice(0, CONFIG.maxSigners), ...b.mods.slice(0, 5));
    if (b.via) hop.push(b.via);
  }
  await probeBasic(ctx, hop);
  const out = {};
  for (const a of list) out[a] = assemble(ctx, a);
  return out;
}

function assemble(ctx, a) {
  if (a === ZERO) return { k: "none" };
  const b = ctx.basic.get(a);
  if (!b) return { k: "unknown" };
  const c = { k: b.k };
  if (b.dg) c.dg = b.dg;
  if (b.k === "safe") {
    c.t = b.t;
    c.n = b.n;
    if (b.v) c.v = b.v;
    c.sg = {};
    c.sl = [];
    for (const s of b.owners.slice(0, CONFIG.maxSigners)) {
      const sb = ctx.basic.get(s);
      const k = sb ? sb.k : "unknown";
      c.sg[k] = (c.sg[k] || 0) + 1;
      c.sl.push(s + ":" + k + (sb && sb.k === "safe" ? ":" + sb.t + "/" + sb.n : ""));
    }
    if (b.owners.length > CONFIG.maxSigners) c.sg.unclassified = b.owners.length - CONFIG.maxSigners;
    if (b.mods.length) {
      c.ml = b.mods.slice(0, 5).map((m) => m + ":" + (ctx.basic.has(m) ? ctx.basic.get(m).k : "unknown"));
      c.mc = b.mods.length;
    }
  }
  if (b.k === "timelock") c.d = b.d;
  if (b.via) {
    const vb = ctx.basic.get(b.via);
    c.via = { a: b.via, k: vb ? vb.k : "unknown" };
    if (vb && vb.k === "safe") {
      c.via.t = vb.t;
      c.via.n = vb.n;
    }
    if (vb && vb.k === "timelock") c.via.d = vb.d;
    if (vb && vb.dg) c.via.dg = vb.dg;
  }
  return c;
}

// A timelock is only notice if its delay is: 0 is no timelock, below minNoticeSeconds is a short one.
const tlCtl = (d) => (d === 0 ? "timelock-0" : d < CONFIG.minNoticeSeconds ? "timelock-short" : "timelock");

// What actually controls the role, after one hop.
function control(c) {
  if (!c) return "unknown";
  switch (c.k) {
    case "none":
      return "none";
    case "eoa":
    case "eoa7702":
      return "eoa";
    case "safe":
      if ((c.ml || []).some((m) => /:(eoa|eoa7702)$/.test(m))) return "safe-eoa-module"; // a module acts without the signers
      return c.t <= 1 ? "safe-1" : "multisig";
    case "timelock":
      return tlCtl(c.d);
    case "contract": {
      if (!c.via) return "contract";
      const v = c.via;
      if (v.k === "eoa" || v.k === "eoa7702") return "eoa-via-contract";
      if (v.k === "safe") return v.t <= 1 ? "safe-1" : "multisig";
      if (v.k === "timelock") return tlCtl(v.d);
      return "contract";
    }
    default:
      return "unknown";
  }
}
const singleKey = (ctl) => ctl === "eoa" || ctl === "eoa-via-contract" || ctl === "safe-eoa-module";
// A Safe with threshold 1 is one key too: both templates rank it like an EOA. It is still reported as what it is
// (singleKey() stays for the wording "single EOA key").
const weakCtl = (ctl) => singleKey(ctl) || ctl === "safe-1";

function fmtDur(s) {
  if (!Number.isFinite(s)) return "?";
  if (s === 0) return "0s";
  if (s % 86400 === 0) return s / 86400 + "d";
  if (s % 3600 === 0) return s / 3600 + "h";
  if (s % 60 === 0) return s / 60 + "m";
  return s + "s";
}
function describe(c) {
  if (!c) return "unknown";
  switch (c.k) {
    case "none":
      return "zero address";
    case "eoa":
      return "EOA";
    case "eoa7702":
      return "EOA with EIP-7702 delegation to " + short(c.dg);
    case "safe": {
      const sg = c.sg ? Object.entries(c.sg).map(([k, n]) => n + " " + (k === "eoa" ? "EOA" : k === "eoa7702" ? "EIP-7702 EOA" : k)) : [];
      const mods = c.mc ? ", " + c.mc + " module(s)" + ((c.ml || []).some((m) => /:(eoa|eoa7702)$/.test(m)) ? " including an EOA" : "") : "";
      return "Safe " + c.t + "/" + c.n + (c.v ? " v" + c.v : "") + (sg.length ? " (signers: " + sg.join(", ") + mods + ")" : mods ? " (" + mods.slice(2) + ")" : "");
    }
    case "timelock":
      return "timelock, delay " + fmtDur(c.d) + (c.via ? ", admin " + short(c.via.a) + " " + describe(c.via) : "");
    case "contract":
      return c.via ? "contract owned by " + describe(c.via) + " " + short(c.via.a) : "contract (not a Safe or timelock, no owner())";
    default:
      return c.k;
  }
}

// ============================ pattern readers ============================
// Each reader fills w.roles / w.ptr / w.info. A role is {l: label, a: [holders]}
// with optional flags: s (Safe signer), m (Safe module), p (pending), f (base severity), c (cap).
// A reader never guesses: a node error that is not a revert aborts the target (see multicall).
function setRole(w, key, label, addrs, flags) {
  w.roles[key] = Object.assign({ l: label, a: [...new Set(addrs.filter(isAddr).map(lc))].sort() }, flags || {});
}
function setPtr(w, key, label, value) {
  w.ptr[key] = { l: label, v: value };
}
// A role that was readable before and now is not at all is not "removed": the target is unreadable.
const hadRole = (prev, key) => !!(prev.roles && prev.roles[key] && prev.roles[key].a.length);

const READERS = {
  async ownable(ctx, t, w, prev) {
    const [o, p] = await ctx.rpc.multicall([
      { to: t.address, data: SEL.owner },
      { to: t.address, data: SEL.pendingOwner },
    ]);
    const owner = rAddr(o);
    if (owner === null) {
      if (hadRole(prev, "owner")) throw tag(new Error("ownable: owner() answered before and does not now"), "config");
      w.warn.push("ownable: owner() not found");
    } else setRole(w, "owner", "owner", [owner], { f: "high" });
    const pending = rAddr(p);
    if (pending !== null) setRole(w, "pendingOwner", "pending owner", pending === ZERO ? [] : [pending], { p: 1 });
  },

  async eip1967(ctx, t, w) {
    const slots = [SLOT.implementation, SLOT.admin, SLOT.beacon];
    let [impl, admin, beacon] = (await ctx.rpc.batch("eth_getStorageAt", slots.map((s) => [t.address, s, "latest"]))).map(normWord);
    let flavor = "EIP-1967";
    if (impl === ZERO32 && admin === ZERO32 && beacon === ZERO32) {
      [impl, admin] = (await ctx.rpc.batch("eth_getStorageAt", [SLOT.zosImplementation, SLOT.zosAdmin].map((s) => [t.address, s, "latest"]))).map(normWord);
      flavor = "zos";
    }
    if (impl === ZERO32 && admin === ZERO32 && beacon === ZERO32) {
      w.warn.push("eip1967: no EIP-1967 or zos proxy slots set");
      return;
    }
    setPtr(w, "implementation", "implementation (" + flavor + " slot)", slotAddr(impl) || impl);
    if (admin !== ZERO32) setRole(w, "proxyAdmin", "proxy admin (" + flavor + " admin slot)", [slotAddr(admin) || ZERO], { f: "high" });
    if (beacon !== ZERO32) {
      setPtr(w, "beacon", "beacon", slotAddr(beacon) || beacon);
      setRole(w, "beacon", "beacon (its owner can upgrade the proxy)", [slotAddr(beacon) || ZERO], { f: "high" });
    }
  },

  async "access-control"(ctx, t, w, prev) {
    const wanted = t.roles && t.roles.length ? t.roles : ["DEFAULT_ADMIN_ROLE", "*"]; // omitted roles: the admin role and every role seen in logs
    const specs = wanted.filter((r) => r !== "*");
    const all = wanted.includes("*");
    const [da, pda] = await ctx.rpc.multicall([
      { to: t.address, data: SEL.defaultAdmin },
      { to: t.address, data: SEL.pendingDefaultAdmin },
    ]);
    if (rAddr(da) !== null) setRole(w, "defaultAdmin", "defaultAdmin()", [rAddr(da)], { f: "high" });
    if (rAddr(pda) !== null) setRole(w, "pendingDefaultAdmin", "pending defaultAdmin", rAddr(pda) === ZERO ? [] : [rAddr(pda)], { p: 1 });
    await auditRoles(ctx, t, w, prev, t.address, specs.map(roleId), { all, keyPrefix: "role", where: "" });
  },

  async "aave-acl"(ctx, t, w, prev) {
    const r = await ctx.rpc.multicall([
      { to: t.address, data: SEL.getACLManager },
      { to: t.address, data: SEL.getACLAdmin },
      { to: t.address, data: SEL.owner },
      { to: t.address, data: SEL.getPool },
      { to: t.address, data: SEL.getPoolConfigurator },
      { to: t.address, data: SEL.getPriceOracle },
      { to: t.address, data: SEL.ADDRESSES_PROVIDER },
    ]);
    let manager = rAddr(r[0]);
    if (manager && manager !== ZERO) {
      // Target is a PoolAddressesProvider.
      setPtr(w, "aclManager", "ACLManager", manager);
      if (rAddr(r[1]) !== null) setRole(w, "aclAdmin", "ACL admin", [rAddr(r[1])], { f: "high" });
      if (rAddr(r[2]) !== null && !w.roles.owner) setRole(w, "owner", "owner", [rAddr(r[2])], { f: "high" });
      if (rAddr(r[3])) setPtr(w, "pool", "Pool", rAddr(r[3]));
      if (rAddr(r[4])) setPtr(w, "poolConfigurator", "PoolConfigurator", rAddr(r[4]));
      if (rAddr(r[5])) setPtr(w, "priceOracle", "price oracle", rAddr(r[5]));
    } else if (rAddr(r[6])) {
      manager = t.address; // Target is the ACLManager itself.
    } else {
      if (hadRole(prev, "aclAdmin") || prev.ptr && prev.ptr.aclManager) throw tag(new Error("aave-acl: getACLManager() answered before and does not now"), "config");
      throw tag(new Error("aave-acl: target is neither a PoolAddressesProvider nor an ACLManager"), "config");
    }
    const where = manager === t.address ? "" : " on ACLManager " + short(manager);
    await auditRoles(ctx, t, w, prev, manager, AAVE_ROLES.map(roleId), { all: false, keyPrefix: "acl", where });
  },

  async safe(ctx, t, w) {
    const [thr, own, ver, mods] = await ctx.rpc.multicall([
      { to: t.address, data: SEL.getThreshold },
      { to: t.address, data: SEL.getOwners },
      { to: t.address, data: SEL.VERSION },
      { to: t.address, data: SEL.getModulesPaginated + encAddr(SENTINEL) + encUint(50) },
    ]);
    const owners = rAddrArray(own);
    const tv = rUint(thr);
    if (!owners || tv === null) throw tag(new Error("safe: getOwners()/getThreshold() not answered"), "config");
    setPtr(w, "safe.threshold", "Safe threshold", tv + "/" + owners.length);
    if (rString(ver)) setPtr(w, "safe.version", "Safe version", rString(ver));
    setRole(w, "signer", "Safe signer", owners, { s: 1 });
    const modules = readModules(mods);
    setRole(w, "module", "Safe module (can execute without signatures)", modules, { m: 1, f: "high" });
    const [single, guard, fallback] = (await ctx.rpc.batch("eth_getStorageAt", [SLOT.safeSingleton, SLOT.safeGuard, SLOT.safeFallbackHandler].map((s) => [t.address, s, "latest"]))).map(normWord);
    setPtr(w, "safe.singleton", "Safe singleton (implementation)", slotAddr(single) || single);
    setPtr(w, "safe.guard", "Safe guard", slotAddr(guard) || guard);
    setPtr(w, "safe.fallbackHandler", "Safe fallback handler", slotAddr(fallback) || fallback);
  },
};
// Less common families (dsauth, wards, fiat-token) are defined at the end of the file.

function readModules(r) {
  // getModulesPaginated returns (address[] array, address next). The first page of 50
  // covers every Safe in practice; a longer list is flagged, not silently cut.
  const arr = rAddrArray(r);
  if (!arr) return [];
  const w = words(r.data);
  const next = w.length > 1 ? wordToAddr(w[1]) : SENTINEL;
  if (next !== SENTINEL && next !== ZERO && arr.length >= 50) arr.push("0x" + "f".repeat(40)); // marker: list truncated
  return arr;
}

// Members of AccessControl roles: enumerated when the contract supports it, otherwise
// rebuilt from RoleGranted/RoleRevoked logs and confirmed with hasRole(). Also reads each role's
// admin role (getRoleAdmin): the role that may grant it.
async function auditRoles(ctx, t, w, prev, manager, ids, opt) {
  const counts = await ctx.rpc.multicall(ids.map((id) => ({ to: manager, data: SEL.getRoleMemberCount + strip0x(id) })));
  const enumerable = counts.some((r) => rUint(r) !== null);
  if (!enumerable || opt.all) {
    const scan = await scanLogs(ctx, w, manager + ":roles", manager, [TOPIC.RoleGranted, TOPIC.RoleRevoked], t.fromBlock);
    for (const l of scan.logs) if (l.topics && l.topics.length >= 3) addCand(w, opt.keyPrefix + ":" + lc(l.topics[1]), topicAddr(l.topics[2]));
    if (!scan.done) w.syncing = true;
  }
  if (opt.all) {
    for (const k of Object.keys(w.cand)) if (k.startsWith(opt.keyPrefix + ":0x")) ids.push(k.slice(opt.keyPrefix.length + 1));
    ids = [...new Set(ids)];
    if (ids.length > CONFIG.maxRoleIds) {
      w.warn.push("roles *: " + ids.length + " role ids seen, the first " + CONFIG.maxRoleIds + " are audited (CONFIG.maxRoleIds)");
      ids = ids.slice(0, CONFIG.maxRoleIds);
    }
  }
  const extraNames = new Map((t.roleNames || []).map((n) => [roleId(n), n]));
  // Addresses always checked with hasRole, so a holder is re-confirmed even if logs miss it.
  const extra = new Set([...t.candidates, t.address, manager]);
  for (const r of Object.values(w.roles)) r.a.forEach((a) => extra.add(a));
  const memberCalls = [];
  const plan = [];
  for (const id of ids) {
    const key = opt.keyPrefix + ":" + id;
    const ci = ids.indexOf(id);
    const cnt = enumerable && ci < counts.length ? rUint(counts[ci]) : null;
    if (cnt !== null) {
      const n = Math.min(Number(cnt), CONFIG.maxMembersPerRole);
      if (Number(cnt) > n) w.warn.push(roleLabel(id, extraNames) + ": " + cnt + " members, first " + n + " read");
      plan.push({ id, key, mode: "enum", start: memberCalls.length, n });
      for (let i = 0; i < n; i++) memberCalls.push({ to: manager, data: SEL.getRoleMember + strip0x(id) + encUint(i) });
    } else {
      const prevHolders = (prev.roles && prev.roles[key] && prev.roles[key].a) || [];
      const cands = [...new Set([...(w.cand[key] || []), ...extra, ...prevHolders])];
      plan.push({ id, key, mode: "has", start: memberCalls.length, cands });
      for (const c of cands) memberCalls.push({ to: manager, data: SEL.hasRole + strip0x(id) + encAddr(c) });
    }
  }
  const res = await ctx.rpc.multicall(memberCalls);
  if (memberCalls.length && res.every((r) => !r.ok)) throw tag(new Error("access control: hasRole/getRoleMember not answered on " + manager), "config");
  const admins = await ctx.rpc.multicall(ids.map((id) => ({ to: manager, data: SEL.getRoleAdmin + strip0x(id) })));
  const empty = [];
  for (const p of plan) {
    const members = p.mode === "enum" ? res.slice(p.start, p.start + p.n).map(rAddr).filter(Boolean) : p.cands.filter((c, i) => rBool(res[p.start + i]) === true);
    const id = p.id;
    const label = roleLabel(id, extraNames);
    const floor = id === ZERO32 ? "high" : "medium";
    setRole(w, p.key, label + opt.where, members, Object.assign({ f: floor }, LOW_RISK_ROLES.has(label) ? { c: "high" } : {}));
    const adminRole = rWord(admins[ids.indexOf(id)]);
    if (adminRole) setPtr(w, p.key + ":admin", label + " admin role (the role that may grant it)", adminRole);
    if (p.mode === "has" && !members.length) empty.push(label + (id === ZERO32 ? " (renounced?)" : ""));
  }
  // One warning, not one per role: an empty set is normal for a role nobody uses, and the
  // symptom of a fromBlock that is later than the grants.
  if (empty.length) w.warn.push("no member found for " + empty.join(", ") + opt.where + ": nobody holds " + (empty.length > 1 ? "them" : "it") + ", or fromBlock (" + t.fromBlock + ") is later than the grants. Set fromBlock to the deployment block.");
}

// ============================ diff ============================
function finding(t, sev, kind, holder, roles, msg) {
  return { sev, kind, target: t.label, address: t.address, holder: holder || null, roles: roles || [], msg };
}
const maxSev = (a, b) => (sevRank(a) >= sevRank(b) ? a : b);

function addSeverity(role, ctl) {
  if (role.p) return "high"; // a pending handover
  if (role.s) return "medium"; // a Safe signer: EOAs are expected there
  if (role.m) return weakCtl(ctl) ? "critical" : "high";
  if (weakCtl(ctl)) return role.c === "high" ? "high" : "critical"; // an EOA or a 1-of-N Safe; pauser, blacklister, keeper... are capped at high
  if (ctl === "timelock-0" || ctl === "timelock-short") return "high";
  if (ctl === "none") return "low";
  return role.f || "medium";
}

// Changes in how one holder is controlled between two runs.
function classDelta(p, c, signerOnly) {
  const out = [];
  if (!p || !c) return out;
  const pc = control(p);
  const cc = control(c);
  const delegate = (dg) => (CONFIG.knownDelegates && CONFIG.knownDelegates[dg] ? " (known delegate: " + CONFIG.knownDelegates[dg] + ")" : "");
  const sevDelegate = (dg) => (signerOnly ? (CONFIG.knownDelegates && CONFIG.knownDelegates[dg] ? "low" : "medium") : "high");
  if (!signerOnly && !singleKey(pc) && singleKey(cc)) out.push(["critical", "now relies on a single EOA key (was " + describe(p) + ", now " + describe(c) + ")"]);
  if (p.k !== c.k && !(p.k === "eoa" && c.k === "eoa7702") && !(p.k === "eoa7702" && c.k === "eoa")) out.push(["high", "holder type changed: " + describe(p) + " -> " + describe(c)]);
  if (p.k === "safe" && c.k === "safe") {
    if (p.t > 1 && c.t === 1) out.push(["critical", "Safe threshold dropped to 1 (" + p.t + "/" + p.n + " -> " + c.t + "/" + c.n + "), any single signer can act"]);
    else if (c.t < p.t) out.push(["high", "Safe threshold lowered " + p.t + "/" + p.n + " -> " + c.t + "/" + c.n]);
    else if (c.t > p.t) out.push(["low", "Safe threshold raised " + p.t + "/" + p.n + " -> " + c.t + "/" + c.n]);
    else if (c.n !== p.n) out.push(["low", "Safe signer count changed " + p.t + "/" + p.n + " -> " + c.t + "/" + c.n]);
    const ps = new Set(p.sl || []);
    const added = (c.sl || []).filter((s) => !ps.has(s));
    if (added.length && c.n === p.n) out.push(["low", "Safe signer set changed: " + added.map((s) => s.split(":").slice(0, 2).map(short).join(" ")).join(", ")]);
    const pm = new Set((p.ml || []).map((m) => m.split(":")[0]));
    for (const m of (c.ml || []).filter((x) => !pm.has(x.split(":")[0]))) {
      const [a, k] = m.split(":");
      out.push([k === "eoa" || k === "eoa7702" ? "critical" : "high", "Safe module added: " + short(a) + " (" + (k === "eoa7702" ? "EIP-7702 EOA" : k) + "), it can execute without the signers"]);
    }
  }
  if (p.k === "eoa" && c.k === "eoa7702") out.push([sevDelegate(c.dg), "EOA is now EIP-7702 delegated to " + c.dg + delegate(c.dg)]);
  if (p.k === "eoa7702" && c.k === "eoa7702" && p.dg !== c.dg) out.push([sevDelegate(c.dg), "EIP-7702 delegation re-pointed " + p.dg + " -> " + c.dg + delegate(c.dg)]);
  if (p.k === "eoa7702" && c.k === "eoa") out.push(["low", "EIP-7702 delegation removed"]);
  if (p.k === "timelock" && c.k === "timelock") {
    if (c.d < p.d) out.push([c.d === 0 ? "critical" : "high", "timelock delay lowered " + fmtDur(p.d) + " -> " + fmtDur(c.d)]);
    else if (c.d > p.d) out.push(["low", "timelock delay raised " + fmtDur(p.d) + " -> " + fmtDur(c.d)]);
  }
  const pv = p.via && p.via.a;
  const cv = c.via && c.via.a;
  if (pv !== cv && (pv || cv)) {
    out.push([weakCtl(cc) && !signerOnly ? "critical" : "high", "controlling owner changed " + (pv ? short(pv) + " (" + describe(p.via) + ")" : "none") + " -> " + (cv ? short(cv) + " (" + describe(c.via) + ")" : "none")]);
  } else if (pv && cv) {
    for (const [s, m] of classDelta(p.via, c.via, true)) out.push([s === "medium" ? "high" : s, "owner " + short(cv) + ": " + m]);
    if (!signerOnly && !singleKey(pc) && singleKey(cc) && !out.some((x) => x[0] === "critical")) out.push(["critical", "now controlled by a single EOA key"]);
  }
  return out;
}

// opts.adopt: the target's configuration changed (or a rescan is running). Holders found by the new
// configuration are adopted silently; type changes of holders seen before and pointer changes still alert.
function diffTarget(t, prev, cur, opts) {
  const adopt = !!(opts && opts.adopt);
  const F = [];
  const P = prev.roles || {};
  const C = cur.roles || {};
  const added = new Map();
  const removed = new Map();
  const kept = new Map();
  const push = (m, a, k) => (m.get(a) || m.set(a, []).get(a)).push(k);
  const active = new Set(prev.patterns || []);
  for (const k of Object.keys(C)) {
    // A role that appears for the first time is a change only if its pattern was already
    // audited last run (for example a brand-new role id granted for the first time). A pattern
    // or role that was just added to CONFIG is adopted silently.
    if (!P[k] && (!active.has(C[k].g) || adopt)) continue;
    const pa = new Set(P[k] ? P[k].a : []);
    const ca = new Set(C[k].a);
    for (const a of ca) {
      if (pa.has(a)) push(kept, a, k);
      else if (!adopt) push(added, a, k);
    }
    if (!adopt) for (const a of pa) if (!ca.has(a)) push(removed, a, k);
  }
  for (const [a, keys] of added) {
    const c = cur.cls[a];
    const ctl = control(c);
    let sev = "info";
    for (const k of keys) sev = maxSev(sev, addSeverity(C[k], ctl));
    const labels = keys.map((k) => C[k].l);
    const pending = keys.every((k) => C[k].p);
    const tail = pending
      ? " (pending: takes effect when accepted)"
      : ctl === "safe-eoa-module" && !keys.every((k) => C[k].s)
        ? ". This Safe has an EOA enabled as a module: that key can move funds alone."
        : singleKey(ctl) && !keys.every((k) => C[k].s)
          ? ". This privileged role now relies on a single EOA key."
          : ctl === "safe-1"
            ? ". Any one signer of this Safe can act alone."
            : "";
    const kind = singleKey(ctl) && !pending && !keys.every((k) => C[k].s) ? "new-eoa-holder" : "new-holder";
    F.push(finding(t, sev, kind, a, labels, labels.join(", ") + ": new holder " + a + " (" + describe(c) + ")" + tail));
  }
  for (const [a, keys] of removed) {
    const sev = keys.some((k) => P[k].s || P[k].m) ? "medium" : "low";
    const labels = keys.map((k) => P[k].l);
    F.push(finding(t, sev, "holder-removed", a, labels, labels.join(", ") + ": holder removed " + a + " (" + describe(prev.cls && prev.cls[a]) + ")"));
  }
  for (const [a, keys] of kept) {
    const signerOnly = keys.every((k) => C[k].s);
    const deltas = classDelta(prev.cls && prev.cls[a], cur.cls[a], signerOnly);
    if (!deltas.length) continue;
    let sev = deltas.reduce((s, d) => maxSev(s, d[0]), "info");
    const labels = keys.map((k) => C[k].l);
    const kind = deltas.some((d) => /threshold dropped to 1/.test(d[1])) ? "threshold-to-1" : deltas.some((d) => /single EOA/.test(d[1])) ? "now-eoa" : "holder-changed";
    if (kind === "now-eoa" && sev === "critical" && keys.every((k) => C[k].c === "high")) sev = "high"; // a pauser or keeper moving to an EOA is not a critical finding
    F.push(finding(t, sev, kind, a, labels, labels.join(", ") + ": holder " + a + " " + deltas.map((d) => d[1]).join("; ")));
  }
  for (const k of Object.keys(cur.ptr || {})) {
    const pp = (prev.ptr && prev.ptr[k]) || (active.has(cur.ptr[k].g) && !adopt ? { v: "unset" } : null);
    if (!pp) continue;
    const a = pp.v;
    const b = cur.ptr[k].v;
    if (a === b) continue;
    if (k === "safe.threshold") {
      const [pt, pn] = String(a).split("/").map(Number);
      const [ct, cn] = String(b).split("/").map(Number);
      const sev = pt > 1 && ct === 1 ? "critical" : ct < pt ? "high" : ct > pt ? "low" : "low";
      F.push(finding(t, sev, pt > 1 && ct === 1 ? "threshold-to-1" : "threshold-changed", null, [cur.ptr[k].l], "Safe threshold " + a + " -> " + b + (pt > 1 && ct === 1 ? ", any single signer can now act" : "") + (cn !== pn ? " (signer count changed)" : "")));
      continue;
    }
    if (k === "safe.version") continue; // follows safe.singleton
    // A new Safe singleton or a new ACLManager replaces the whole permission system at once.
    const sev = k === "safe.singleton" || k === "aclManager" ? "critical" : "high";
    F.push(finding(t, sev, "pointer-changed", null, [cur.ptr[k].l], cur.ptr[k].l + " changed " + a + " -> " + b));
  }
  return F;
}

// A role that was set last run and cannot be read now keeps its last-known holders (so the next
// good run does not see "new" holders). After 24 hours the loss is reported once and the role dropped.
function carryOver(t, prev, cur, now) {
  const F = [];
  const active = new Set(prev.patterns || []);
  for (const k of Object.keys(prev.roles || {})) {
    const pr = prev.roles[k];
    if (cur.roles[k] || !pr.a.length || !active.has(pr.g) || !(cur.patterns || []).includes(pr.g)) continue;
    const since = pr.miss || now;
    if (now - since < 86400) {
      cur.roles[k] = Object.assign({}, pr, { miss: since });
      for (const a of pr.a) if (!cur.cls[a] && prev.cls && prev.cls[a]) cur.cls[a] = prev.cls[a];
      if (!pr.miss) F.push(finding(t, "low", "role-unreadable", null, [pr.l], pr.l + ": not readable this run, last-known holders kept (was " + pr.a.map(short).join(", ") + ")"));
    } else F.push(finding(t, "medium", "role-unreadable", null, [pr.l], pr.l + ": no longer set or readable for 24 hours, dropped (was " + pr.a.map(short).join(", ") + ")"));
  }
  // A role-admin pointer that could not be read this run is kept, so the next run does not see it "appear".
  for (const k of Object.keys(prev.ptr || {})) if (/:admin$/.test(k) && !cur.ptr[k] && cur.roles[k.slice(0, -6)]) cur.ptr[k] = prev.ptr[k];
  return F;
}

// Standing posture: privileged roles that rely on a single key right now. `sev` is what a NEW holder
// like this one would be raised at, so the baseline message and a later change read the same.
function ackOf(a, c) {
  const k = CONFIG.knownKeys || {};
  return k[a] || (c && c.via && k[c.via.a]) || null;
}
function standing(t, st) {
  const out = [];
  for (const [k, r] of Object.entries(st.roles || {})) {
    if (r.p) {
      for (const a of r.a) out.push({ target: t.label, address: t.address, role: r.l, holder: a, desc: describe(st.cls[a]), flag: "pending handover", sev: "high" });
      continue;
    }
    for (const a of r.a) {
      const c = st.cls[a];
      const ctl = control(c);
      if (r.s) {
        continue; // EOAs are expected as Safe signers
      }
      let flag = null;
      if (ctl === "safe-eoa-module") flag = "Safe with an EOA as module";
      else if (singleKey(ctl)) flag = ctl === "eoa" ? (c.k === "eoa7702" ? "EOA (EIP-7702 delegated)" : "EOA") : "contract controlled by an EOA";
      else if (ctl === "safe-1") flag = "1-of-N Safe";
      else if (ctl === "timelock-0") flag = "timelock with 0 delay";
      else if (ctl === "timelock-short") flag = "timelock with a short delay (below " + fmtDur(CONFIG.minNoticeSeconds) + ")";
      else if (r.m) flag = "Safe module";
      if (flag) out.push({ target: t.label, address: t.address, role: r.l, holder: a, desc: describe(c), flag, ack: ackOf(a, c), key: k, sev: addSeverity(r, ctl) });
    }
  }
  const th = st.ptr && st.ptr["safe.threshold"];
  if (th && String(th.v).startsWith("1/")) out.push({ target: t.label, address: t.address, role: "Safe threshold", holder: t.address, desc: "threshold " + th.v, flag: "1-of-N Safe", sev: "critical" });
  return out;
}

// The baseline message: the standing posture of a target whose first baseline just completed, as findings.
// Acknowledged rows (CONFIG.knownKeys) are left out, as in the digest.
function baselineFindings(t, st) {
  const rows = standing(t, st);
  const open = rows.filter((r) => !r.ack);
  return { F: open.map((r) => finding(t, r.sev, "baseline-standing", r.holder, [r.role], r.role + ": " + r.holder + " (" + r.desc + ") [" + r.flag + "]")), acknowledged: rows.length - open.length };
}

// ============================ notify ============================
const EMOJI = { critical: ":red_circle:", high: ":large_orange_circle:", medium: ":large_yellow_circle:", low: ":white_circle:", info: ":information_source:" };
const link = (a) => (isAddr(a) ? "<" + CONFIG.explorerAddressUrl + a + "|" + short(a) + ">" : String(a));

const slackLine = (f) => EMOJI[f.sev] + " *" + f.sev.toUpperCase() + "* | " + f.target + " " + link(f.address) + "\n    " + f.msg.replace(/0x[0-9a-f]{40}/g, (a) => link(a));

function slackText(title, findings) {
  const lines = ["*" + title + "*"];
  let n = 0;
  for (const f of findings) {
    const line = slackLine(f);
    if (lines.join("\n").length + line.length > 3500) break;
    lines.push(line);
    n++;
  }
  if (n < findings.length) lines.push("... and " + (findings.length - n) + " more (see the action logs)");
  return lines.join("\n");
}

// The baseline message is the first thing a team reads and must not be cut: it goes out in up to maxParts messages.
function slackParts(title, findings, maxParts) {
  const parts = [];
  let cur = [];
  let len = 0;
  for (const f of findings) {
    const line = slackLine(f);
    if (cur.length && len + line.length > 3300) {
      parts.push(cur);
      cur = [];
      len = 0;
    }
    cur.push(line);
    len += line.length + 1;
  }
  if (cur.length) parts.push(cur);
  const shown = parts.slice(0, maxParts);
  const rest = parts.slice(maxParts).reduce((n, p) => n + p.length, 0);
  return shown.map((p, i) => "*" + title + (parts.length > 1 ? " (part " + (i + 1) + " of " + parts.length + ")" : "") + "*\n" + p.join("\n") + (i === shown.length - 1 && rest ? "\n... and " + rest + " more (see the action logs)" : ""));
}

// Returns {sent, failed}. No webhook configured = log only, which is not a failure.
async function postSlack(url, text) {
  if (!url) return { sent: false, failed: false };
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
      signal: AbortSignal.timeout(CONFIG.slackTimeoutMs),
    });
    const body = await r.text();
    if (r.status === 200 && body.trim() === "ok") return { sent: true, failed: false };
    return { sent: false, failed: true, error: "slack HTTP " + r.status + " " + body.slice(0, 60) };
  } catch (e) {
    return { sent: false, failed: true, error: "slack " + (e && e.name === "TimeoutError" ? "timeout" : "transport error") };
  }
}

// ============================ per-target run ============================
function emptyState(t) {
  return { v: 1, address: t.address, label: t.label, baselined: false, roles: {}, ptr: {}, cls: {}, info: {}, scan: {}, cand: {}, hist: [] };
}

// opts.fast: the cheap snapshot only, no eth_getLogs. A target that still owes its log pass (baseline,
// catch-up, rescan after a configuration edit) stays pending, so the baseline can never complete without it.
async function auditTarget(ctx, t, prev, opts) {
  const started = Date.now();
  const fast = !!(opts && opts.fast);
  const w = { fast, roles: {}, ptr: {}, info: {}, warn: [], syncing: false, rescan: false, scanUntil: started + CONFIG.maxScanMsPerTarget, scan: JSON.parse(JSON.stringify(prev.scan || {})), cand: JSON.parse(JSON.stringify(prev.cand || {})) };
  try {
    for (const p of t.patterns) {
      await READERS[p](ctx, t, w, prev);
      for (const o of [...Object.values(w.roles), ...Object.values(w.ptr)]) if (!o.g) o.g = p;
    }
    if (fast && mayScan(t) && owesLogPass(t, prev)) w.syncing = true;
    const holders = new Set();
    for (const r of Object.values(w.roles)) r.a.forEach((a) => /^0xf{40}$/.test(a) || holders.add(a));
    w.cls = await classify(ctx, [...holders]);
  } catch (e) {
    return { ok: false, error: e.message, kind: e.kind || "error", w, ms: Date.now() - started, deep: !fast };
  }
  return { ok: true, w, ms: Date.now() - started, deep: !fast };
}

// Which targets can rebuild role members from logs, and which of them get a log pass on this run.
const LOG_PATTERNS = new Set(["access-control", "aave-acl", "wards", "fiat-token"]);
const mayScan = (t) => t.patterns.some((p) => LOG_PATTERNS.has(p));
// A log pass that cannot wait: the baseline, a catch-up in progress, a rescan, or a configuration edit.
const owesLogPass = (t, prev) => !prev.baselined || !!prev.rescan || !!prev.sync || !!(prev.fp && prev.fp !== t.fp);
// Otherwise a target that has log cursors (its members come from logs) is due every logPassEveryS seconds;
// the oldest log pass goes first. Targets whose members are enumerable on chain have no cursors: never due.
function wantsLogs(t, prev, now) {
  if (!mayScan(t)) return false;
  if (owesLogPass(t, prev)) return true;
  if (!Object.keys(prev.scan || {}).length) return false;
  return now - (prev.logAt || 0) >= CONFIG.logPassEveryS;
}

// Keeps the candidate lists bounded: current members always stay, and the oldest
// non-members (the front of each list, which is in discovery order) are dropped first.
function trimCandidates(st) {
  const members = new Set();
  for (const r of Object.values(st.roles || {})) r.a.forEach((a) => members.add(a));
  const total = Object.values(st.cand).reduce((n, l) => n + l.length, 0);
  if (total <= CONFIG.maxCandidates) return;
  const old = [];
  for (const [k, l] of Object.entries(st.cand)) l.forEach((a, i) => !members.has(a) && old.push({ k, a, i }));
  old.sort((x, y) => x.i - y.i); // lowest index = discovered first
  const drop = new Set(old.slice(0, total - CONFIG.maxCandidates).map((x) => x.k + "|" + x.a));
  for (const k of Object.keys(st.cand)) st.cand[k] = st.cand[k].filter((a) => !drop.has(k + "|" + a));
}

function boundState(st) {
  trimCandidates(st);
  st.hist = (st.hist || []).slice(-10);
  const size = () => JSON.stringify(st).length;
  while (size() > 90000 && st.hist.length) st.hist = st.hist.slice(Math.ceil(st.hist.length / 2));
  for (const c of Object.values(st.cls)) if (size() > 90000 && c.sl) delete c.sl;
  if (size() > 95000) throw new Error("state of " + st.label + " is " + size() + " bytes (limit 100,000): audit fewer roles per target");
  return st;
}

// ============================ entry point ============================
function normTargets(list, warn) {
  const out = [];
  const seen = new Set();
  for (const raw of list || []) {
    if (!raw || !isAddr(raw.address)) {
      warn("WARN skipped target " + JSON.stringify(raw && raw.label) + ": invalid address");
      continue;
    }
    const address = lc(raw.address);
    if (seen.has(address)) {
      warn("WARN skipped duplicate target " + address);
      continue;
    }
    seen.add(address);
    const unknown = (raw.patterns || []).filter((p) => !PATTERNS.includes(p));
    if (unknown.length) warn("WARN " + (raw.label || address) + ": unknown pattern(s) " + unknown.join(", ") + " ignored. Known: " + PATTERNS.join(", "));
    const patterns = (raw.patterns || []).filter((p) => PATTERNS.includes(p));
    if (!patterns.length) {
      warn("WARN skipped " + (raw.label || address) + ": no known pattern");
      continue;
    }
    const tgt = {
      ...raw,
      address,
      label: String(raw.label || address).slice(0, 80),
      patterns,
      roles: Array.isArray(raw.roles) ? raw.roles : [],
      roleNames: Array.isArray(raw.roleNames) ? raw.roleNames : [],
      candidates: (raw.candidates || []).filter(isAddr).map(lc),
      fromBlock: Number.isInteger(raw.fromBlock) && raw.fromBlock >= 0 ? raw.fromBlock : 0,
    };
    // Fingerprint of what decides which holders are looked for: when it changes, the new result is adopted silently once.
    tgt.fp = sha(JSON.stringify([tgt.patterns, tgt.roles, tgt.roleNames, [...tgt.candidates].sort(), tgt.fromBlock])).slice(0, 12);
    out.push(tgt);
  }
  return out;
}

const hoursOf = (s) => Math.round(s / 360) / 10;

// What woke the action: a block event ({ blockHash, blockNumber, network }) or a periodic one ({ time }).
// The audit does not depend on the event, either one means "snapshot now"; it is only reported.
function describeEvent(event) {
  const e = event && typeof event === "object" ? event : {};
  if (e.blockNumber !== undefined && e.blockNumber !== null) return { type: "block", blockNumber: Number(e.blockNumber), network: e.network === undefined || e.network === null ? null : String(e.network) };
  return { type: e.time ? "periodic" : "unknown", network: null };
}

// Stored values are compared without the fields that change on every run (or are only informational: `info`
// holds FiatToken minter allowances, which move whenever a minter mints), so an unchanged target is not rewritten.
const STATE_VOLATILE = new Set(["at", "ms", "msd", "logAt", "wAt", "info"]);
const META_VOLATILE = new Set(["lastRunAt", "cycle", "cycleAt", "savedAt"]);
const stableState = (s) => JSON.stringify(s, (k, v) => (STATE_VOLATILE.has(k) ? undefined : v));
const stableMeta = (m) => JSON.stringify(m, (k, v) => (META_VOLATILE.has(k) ? undefined : v));

// ============================ lease ============================
// Block-triggered runs normally execute one at a time, but they can overlap: parallel execution, a
// sequential action that Tenderly may switch to parallel when it lags, a cron trigger next to a block
// trigger, a manual run from the Dashboard. The Storage API has no compare-and-set, so the lease is best effort:
// read the lease, write our id, wait leaseSettleMs, read it back, and the last writer wins. A run that
// loses or finds a live lease skips (it touches no target state). A crashed run leaves a lease that
// expires after leaseTtlMs.
const leaseKey = () => prefix() + ":lease";
async function takeLease(context, id) {
  if (!CONFIG.lease) return { ok: true, held: false };
  let cur = null;
  try {
    const raw = await context.storage.getStr(leaseKey());
    try {
      cur = raw ? JSON.parse(raw) : null;
    } catch (e) {
      cur = null; // a corrupt value counts as free
    }
  } catch (e) {
    return { ok: true, held: false, note: "lease not used, Storage read failed (" + e.message + ")" };
  }
  const left = cur && cur.id && cur.id !== id ? Number(cur.until) - Date.now() : 0;
  if (left > 0) return { ok: false, leftMs: left };
  let wrote = false;
  try {
    await context.storage.putStr(leaseKey(), JSON.stringify({ id, until: Date.now() + CONFIG.leaseTtlMs }));
    wrote = true;
    await sleep(CONFIG.leaseSettleMs);
    const raw = await context.storage.getStr(leaseKey());
    const back = raw ? JSON.parse(raw) : null;
    if (!back || back.id !== id) return { ok: false, lost: true, leftMs: back && back.until ? Math.max(0, Number(back.until) - Date.now()) : 0 };
    return { ok: true, held: true };
  } catch (e) {
    return { ok: true, held: wrote, note: "lease not verified, Storage failed (" + e.message + ")" };
  }
}
async function dropLease(context, id) {
  try {
    const raw = await context.storage.getStr(leaseKey());
    const cur = raw ? JSON.parse(raw) : null;
    if (cur && cur.id === id) await context.storage.putStr(leaseKey(), JSON.stringify({ id: "", until: 0 }));
  } catch (e) {
    /* best effort: the lease expires by itself after leaseTtlMs */
  }
}

const actionFn = async (context, event) => {
  const t0 = Date.now();
  const now = Math.floor(t0 / 1000);
  if (!/^[a-z0-9][a-z0-9-]{0,30}$/.test(String(CONFIG.deploymentName || ""))) throw new Error("CONFIG.deploymentName must be 1 to 31 characters of [a-z0-9-], unique per deployed copy of this action");
  const trig = describeEvent(event);
  const log = [];
  const problems = []; // failures that must fail the execution, after everything that can be saved is saved
  const report = { at: new Date(t0).toISOString(), trigger: trig, processed: [], findings: [], notified: null, standing: null, warnings: [] };
  const warn = (m) => {
    log.push(m);
    report.warnings.push(m);
  };
  if (trig.network && /^\d+$/.test(trig.network) && trig.network !== String(CONFIG.chainId)) {
    // A block trigger that lists more than one network: this copy audits one chain.
    report.skipped = "block event for network " + trig.network + ", this copy audits chain " + CONFIG.chainId;
    console.log("posture audit: " + report.skipped);
    return report;
  }
  const targets = normTargets(CONFIG.targets, warn);
  const ack = Object.fromEntries(Object.entries(CONFIG.knownKeys || {}).map(([k, v]) => [lc(k), v]));
  CONFIG.knownKeys = ack;
  CONFIG.knownDelegates = Object.fromEntries(Object.entries(CONFIG.knownDelegates || {}).map(([k, v]) => [lc(k), v]));
  if (!targets.length) {
    console.log("no targets configured");
    return report;
  }

  const runId = t0.toString(36) + Math.random().toString(36).slice(2, 8);
  const lease = await takeLease(context, runId);
  if (!lease.ok) {
    report.skipped = "another run is active" + (lease.lost ? " (lost the race for the lease)" : "") + ", its lease expires in at most " + Math.ceil(lease.leftMs / 1000) + " s; no target state was read or written";
    report.ms = Date.now() - t0;
    console.log("posture audit: SKIPPED, " + report.skipped);
    return report;
  }
  if (lease.note) log.push("NOTE " + lease.note);
  try {
    return await auditRun(context, { t0, now, trig, targets, log, problems, report, warn });
  } finally {
    if (lease.held) await dropLease(context, runId);
  }
};

async function auditRun(context, E) {
  const { t0, now, trig, targets, log, problems, report, warn } = E;
  let loaded = null;
  let metaReadable = true;
  try {
    loaded = await loadJson(context, metaKey());
  } catch (e) {
    metaReadable = false;
    problems.push("meta read failed (" + e.message + ")"); // audit with a fresh meta, never overwrite the stored one, fail the run at the end
  }
  const meta = Object.assign({ v: 1, next: 0, cycle: 0, sent: [], lastDigestAt: 0, firstRunAt: now, known: {}, caps: {}, done: [] }, loaded || {});
  if (Array.isArray(meta.known)) meta.known = Object.fromEntries(meta.known.map((a) => [a, now])); // older state
  let metaSer = stableMeta(loaded || {});
  const rpc = makeRpc(await secret(context, "RPC_URL"), await secret(context, "LOG_RPC_URL"), t0 + CONFIG.hardDeadlineMs, meta.caps);
  const ctx = { rpc, basic: new Map(), chunk: CONFIG.logChunkStart, logCalls: 0, left: () => CONFIG.runBudgetMs - (Date.now() - t0) };
  try {
    ctx.head = Number(BigInt(await rpc.call("eth_blockNumber", [])));
  } catch (e) {
    // Nothing can be audited without a working RPC. Failing the execution makes the
    // outage visible in the execution history (and in failure notifications).
    throw new Error("posture audit: no RPC answered eth_blockNumber (" + e.message + ")");
  }
  report.head = ctx.head;
  // Every state read of this run asks for the same block.
  const lag = Number.isInteger(CONFIG.snapshotLagBlocks) && CONFIG.snapshotLagBlocks >= 0 ? CONFIG.snapshotLagBlocks : 2;
  report.snapshotBlock = Math.max(0, ctx.head - lag);
  rpc.setBlock(report.snapshotBlock);

  // Load every target's state at once. A failing Storage read is not "missing": auditing that target
  // now would re-baseline it silently, so it is skipped and the run fails at the end.
  const plan = (
    await Promise.all(
      targets.map(async (t) => {
        try {
          return { t, prev: (await loadJson(context, targetKey(t.address))) || emptyState(t) };
        } catch (e) {
          problems.push("storage read failed for " + t.label + " (" + e.message + ")");
          return { t, skip: true };
        }
      }),
    )
  ).map((x, idx) => Object.assign(x, { idx }));

  // Two lanes. The cheap snapshot (fast lane) covers every target on every run, concurrency targets at a
  // time, round robin from meta.next when the budget does not fit them all. The log lane runs beside it:
  // the targets whose log pass is due, oldest first, as many as fit in logBudgetMs (at least one).
  const due = plan.filter((x) => !x.skip && wantsLogs(x.t, x.prev, now)).sort((a, b) => (a.prev.logAt || 0) - (b.prev.logAt || 0) || a.idx - b.idx);
  const deep = [];
  let deepEst = 0;
  for (const x of due) {
    const est = Number(x.prev.msd) || CONFIG.defaultDeepMs;
    if (deep.length && deepEst + est > CONFIG.logBudgetMs) break;
    deep.push(x);
    deepEst += est;
  }
  const deepIdx = new Set(deep.map((x) => x.idx));
  const start = Number(meta.next) % targets.length || 0;
  const fastList = [];
  for (let n = 0; n < targets.length; n++) {
    const i = (start + n) % targets.length;
    if (!deepIdx.has(i)) fastList.push(i);
  }
  const done = new Array(targets.length);
  const started = new Set();
  let halted = false;
  const fastLane = async () => {
    let cursor = 0;
    const worker = async () => {
      while (!halted && cursor < fastList.length) {
        const x = plan[fastList[cursor++]];
        if (x.skip) {
          started.add(x.idx);
          done[x.idx] = { idx: x.idx, t: x.t, skip: true };
          continue;
        }
        const est = Number(x.prev.ms) || CONFIG.defaultTargetMs;
        if (started.size > 0 && Date.now() - t0 + est > CONFIG.runBudgetMs) {
          halted = true; // the rest waits for the next run, which starts with it
          return;
        }
        started.add(x.idx);
        done[x.idx] = { idx: x.idx, t: x.t, prev: x.prev, res: await auditTarget(ctx, x.t, x.prev, { fast: true }) };
      }
    };
    await Promise.all(Array.from({ length: Math.max(1, Math.floor(CONFIG.concurrency) || 1) }, worker));
  };
  const logLane = async () => {
    for (const x of deep) {
      started.add(x.idx);
      done[x.idx] = { idx: x.idx, t: x.t, prev: x.prev, res: await auditTarget(ctx, x.t, x.prev, { fast: false }) };
    }
  };
  await Promise.all([fastLane(), logLane()]);
  const results = done.filter(Boolean);
  const unstarted = fastList.filter((i) => !started.has(i));
  meta.next = unstarted.length ? unstarted[0] : start;
  // A cycle ends when every target has been audited since the previous boundary: with the cheap snapshot
  // covering all targets, that is every run (a long target list that does not fit takes several).
  const seen = new Set((meta.done || []).filter((a) => targets.some((t) => t.address === a)));
  for (const r of results) seen.add(r.t.address);
  const wrapped = targets.every((t) => seen.has(t.address));
  if (wrapped) {
    meta.cycle = (meta.cycle || 0) + 1;
    meta.cycleAt = now;
    meta.done = [];
  } else meta.done = [...seen];

  // Diff each processed target against its stored state.
  const pendingSave = [];
  let quiet = 0;
  for (const { t, prev, res, skip } of results) {
    if (skip) {
      report.processed.push({ label: t.label, address: t.address, ms: 0, status: "SKIPPED (storage read failed)", warnings: [] });
      continue;
    }
    const st = JSON.parse(JSON.stringify(prev));
    st.label = t.label;
    if (res.deep) {
      st.msd = res.ms;
      st.logAt = now;
    } else st.ms = res.ms;
    st.scan = res.w.scan; // log cursors and candidates only move forward (or back on purpose), keep them even on errors
    st.cand = res.w.cand;
    let F = [];
    let status;
    if (!res.ok) {
      st.err = { since: (prev.err && prev.err.since) || now, msg: String(res.error).slice(0, 200), notifiedAt: prev.err && prev.err.notifiedAt };
      status = "UNREADABLE " + res.error;
      const blindH = (now - st.err.since) / 3600;
      if (blindH >= CONFIG.unreadableAlertAfterHours && now - (st.err.notifiedAt || 0) > 86400) {
        F.push(finding(t, "high", "unreadable", null, [], prev.baselined
          ? "posture audit could not read this target for " + Math.round(blindH) + "h (" + st.err.msg + "). Changes cannot be ruled out."
          : "posture audit could not baseline this target for " + Math.round(blindH) + "h (" + st.err.msg + "). It is NOT monitored."));
        st.err.notifiedAt = now;
      }
    } else {
      const cur = { roles: res.w.roles, ptr: res.w.ptr, cls: res.w.cls, patterns: t.patterns };
      const fpChanged = !!(prev.baselined && prev.fp && prev.fp !== t.fp);
      const adopt = fpChanged || !!prev.rescan || res.w.rescan;
      if (prev.baselined) {
        if (!adopt) F = carryOver(t, prev, cur, now);
        F.push(...diffTarget(t, prev, cur, { adopt }));
        if (adopt) log.push("NOTE " + t.label + ": configuration changed or a rescan is running, role membership adopted silently this run");
      }
      st.roles = cur.roles;
      st.ptr = cur.ptr;
      st.cls = cur.cls;
      st.patterns = t.patterns;
      st.fp = t.fp;
      st.info = res.w.info;
      st.warn = res.w.warn;
      st.at = now;
      delete st.err;
      const wasBaselined = !!prev.baselined;
      if (!res.w.syncing) st.baselined = true;
      if (res.w.syncing && (res.w.rescan || prev.rescan || fpChanged)) st.rescan = true;
      else delete st.rescan;
      // Catch-up progress: a target that stays silent for hours needs a word, with an ETA.
      if (res.w.syncing) {
        const behind = Object.values(res.w.scan).reduce((n, c) => n + Math.max(0, ctx.head - CONFIG.confirmations - c.next), 0);
        st.sync = prev.sync || { since: now, behind0: behind };
        const hrs = (now - st.sync.since) / 3600;
        if (hrs >= CONFIG.syncingAlertAfterHours && now - (st.sync.notifiedAt || 0) > 86400) {
          const rate = (st.sync.behind0 - behind) / Math.max(1, now - st.sync.since); // net blocks per second
          F.push(finding(t, "high", "syncing", null, [], "log catch-up has taken " + hoursOf(now - st.sync.since) + "h and this target is " + (wasBaselined ? "not fully re-audited" : "NOT monitored yet") + "; " + behind + " blocks left, " + (rate > 0 ? "about " + hoursOf(behind / rate) + "h at the current pace" : "the pace does not catch up with the chain: use a log provider with a wider range (LOG_RPC_URL)")));
          st.sync.notifiedAt = now;
        }
      } else delete st.sync;
      status = !wasBaselined ? (res.w.syncing ? "SYNCING (baseline pending)" : "BASELINE") : F.length ? "CHANGED" : res.w.syncing ? "ok (log catch-up continues)" : "ok";
      // The first complete baseline: post the standing posture once, at alert level.
      if (!wasBaselined && st.baselined && CONFIG.baselinePostureAlert) {
        const b = baselineFindings(t, st);
        F.push(...b.F);
        log.push("NOTE " + t.label + ": baseline complete, " + b.F.length + " role(s) held by an EOA, an EIP-7702 EOA or a 1-of-N Safe" + (b.acknowledged ? ", " + b.acknowledged + " acknowledged in knownKeys and left out" : ""));
      }
    }
    for (const f of F) {
      // An acknowledged key only lowers a NEW holder with that exact key (or the key behind a contract).
      const cl = st.cls || {};
      if (f.holder && (f.kind === "new-holder" || f.kind === "new-eoa-holder") && ackOf(f.holder, cl[f.holder])) {
        f.sev = "info";
        f.msg += " (acknowledged: " + ackOf(f.holder, cl[f.holder]) + ")";
      }
      // Same diff against the same stored snapshot = same fingerprint (a re-run after a
      // lost storage write); the same change happening again later is a new finding.
      f.fp = sha(t.address + "|" + (prev.at || 0) + "|" + f.msg).slice(0, 12);
    }
    const changes = F.filter((f) => f.kind !== "baseline-standing");
    const nBase = F.length - changes.length;
    st.hist = [...(st.hist || []), ...changes.map((f) => ({ at: now, sev: f.sev, msg: f.msg.slice(0, 300) })), ...(nBase ? [{ at: now, sev: "info", msg: "baseline complete, " + nBase + " role(s) rely on a single key or a 1-of-N Safe" }] : [])];
    report.findings.push(...F);
    report.processed.push({ label: t.label, address: t.address, ms: res.ms, status, warnings: res.ok ? res.w.warn : [], deep: res.deep });
    pendingSave.push({ t, prev, st, F });
    // Routine runs stay quiet: a target that is simply ok, with the same warnings as before, is only counted.
    const sameWarn = !res.ok || JSON.stringify(prev.warn || []) === JSON.stringify(res.w.warn);
    if (/^ok$/.test(status) && !F.length && sameWarn) quiet++;
    else log.push(status.padEnd(12) + " " + t.label + " " + short(t.address) + " " + res.ms + " ms" + (F.length ? "\n  " + F.map((f) => f.sev.toUpperCase() + " " + f.msg).join("\n  ") : "") + (res.ok && res.w.warn.length ? "\n  " + res.w.warn.map((m) => "warning: " + m).join("\n  ") : ""));
  }

  // Notify: one Slack message per run with every change at or above the threshold, and one for the
  // standing posture of targets whose baseline just completed.
  const sentRecent = (meta.sent || []).filter((s) => now - s.t < 6 * 3600);
  const sentSet = new Set(sentRecent.map((s) => s.f));
  const toSend = report.findings.filter((f) => sevRank(f.sev) >= sevRank(CONFIG.notifyMinSeverity) && !sentSet.has(f.fp)).sort((a, b) => sevRank(b.sev) - sevRank(a.sev));
  const slackUrl = await secret(context, "SLACK_WEBHOOK_URL");
  const groups = [
    { name: "changes", list: toSend.filter((f) => f.kind !== "baseline-standing"), title: (n) => "Privileged posture audit, " + CONFIG.chainName + " (" + CONFIG.chainId + "): " + n + " change(s)" },
    { name: "baseline", list: toSend.filter((f) => f.kind === "baseline-standing"), title: (n) => "Privileged posture baseline, " + CONFIG.chainName + " (" + CONFIG.chainId + "): " + n + " role(s) held by an EOA, an EIP-7702 EOA or a 1-of-N Safe" },
  ].filter((g) => g.list.length);
  const failedFps = new Set();
  for (const g of groups) {
    const texts = g.name === "baseline" ? slackParts(g.title(g.list.length), g.list, 5) : [slackText(g.title(g.list.length), g.list)];
    let d = { sent: false, failed: false };
    for (let i = 0; i < texts.length && !d.failed; i++) {
      if (i && slackUrl) await sleep(1000); // Slack incoming webhooks take about one message per second
      d = await postSlack(slackUrl, texts[i]);
    }
    const text = texts.join("\n\n");
    const rec = { count: g.list.length, text, parts: texts.length, delivery: d };
    if (g.name === "changes") report.notified = rec;
    else report.notifiedBaseline = rec;
    if (!slackUrl) log.push("SLACK_WEBHOOK_URL not set: " + g.name + " logged only");
    if (d.failed) {
      log.push("NOTIFY FAILED " + d.error + ": the " + g.name + " stay pending and are reported again next run");
      problems.push("notification failed (" + d.error + ")");
      for (const f of g.list) failedFps.add(f.fp);
    } else for (const f of g.list) sentRecent.push({ f: f.fp, t: now });
  }
  meta.sent = sentRecent.slice(-200);

  // Persist. If the notification failed, targets with unsent findings keep their old
  // posture (only scan progress is saved) so the same diff is raised again next run. An unchanged target is
  // rewritten only every stateHeartbeatS seconds.
  let written = 0;
  for (const { t, prev, st, F } of pendingSave) {
    const held = F.some((f) => failedFps.has(f.fp));
    const out = held ? Object.assign(JSON.parse(JSON.stringify(prev)), { scan: st.scan, cand: st.cand, ms: st.ms, msd: st.msd, logAt: st.logAt }) : st;
    if (!held && !F.length && prev.baselined && out.baselined && now - (prev.wAt || 0) < CONFIG.stateHeartbeatS && stableState(prev) === stableState(out)) continue;
    out.wAt = now;
    try {
      await saveJson(context, targetKey(t.address), boundState(out));
      written++;
    } catch (e) {
      log.push("STORAGE write failed for " + t.label + ": " + e.message);
      problems.push("storage write failed for " + t.label + " (" + e.message + ")");
    }
  }
  report.stateWrites = written;
  // The round-robin position and the sent list are saved BEFORE the optional work below, so a run
  // that dies later (a timeout at the 30 s limit, slow Storage) cannot pin the same batch of targets forever.
  const live = new Set(targets.map((t) => t.address));
  for (const a of live) if (!meta.known[a] || now - meta.known[a] > 3600) meta.known[a] = now;
  meta.lastRunAt = now;
  meta.caps = rpc.caps();
  const saveMeta = async () => {
    if (!metaReadable) return; // the stored meta could not be read: do not replace it with defaults
    const ser = stableMeta(meta);
    if (ser === metaSer && now - (meta.savedAt || 0) < CONFIG.stateHeartbeatS) return;
    meta.savedAt = now;
    try {
      await saveJson(context, metaKey(), meta);
      metaSer = ser;
    } catch (e) {
      log.push("STORAGE write failed for meta: " + e.message);
      problems.push("storage write failed for meta (" + e.message + ")");
    }
  };
  await saveMeta();

  // Targets that left CONFIG: their state is deleted only after forgetRemovedAfterDays, because
  // another copy of this action sharing the deploymentName looks the same as a removal.
  const gone = Object.keys(meta.known).filter((a) => !live.has(a));
  if (gone.length) warn("WARN " + gone.length + " stored target(s) are not in this CONFIG (removed, or another copy shares deploymentName \"" + CONFIG.deploymentName + "\"); their state is kept for " + CONFIG.forgetRemovedAfterDays + " days");
  for (const a of gone) {
    if (now - meta.known[a] > CONFIG.forgetRemovedAfterDays * 86400) {
      try {
        await context.storage.delete(targetKey(a));
      } catch (e) {
        /* best effort */
      }
      delete meta.known[a];
    }
  }

  // Standing posture digest, once per digestEveryHours, after a full cycle, only when there is time
  // left for loading the other targets and one Slack post.
  const tailLeft = () => CONFIG.runLimitMs - (Date.now() - t0) - CONFIG.slackTimeoutMs - CONFIG.storageOpMs * (results.length + 3);
  if (CONFIG.digestEveryHours > 0 && wrapped && meta.cycle >= 1) {
    if (!meta.lastDigestAt) meta.lastDigestAt = now; // the first cycle is the baseline: no digest
    else if (now - meta.lastDigestAt >= CONFIG.digestEveryHours * 3600) {
      const items = [];
      let complete = true;
      for (const t of targets) {
        const s = pendingSave.find((p) => p.t.address === t.address);
        if (!s && tailLeft() < CONFIG.storageOpMs * 2) {
          complete = false; // not enough time to read every target: postpone the digest to a quieter run
          break;
        }
        let st = s ? s.st : null;
        if (!st) {
          try {
            st = await loadJson(context, targetKey(t.address));
          } catch (e) {
            st = null;
          }
        }
        if (st && st.baselined) items.push(...standing(t, st));
      }
      if (complete) {
        const rows = items.filter((i) => !i.ack).map((i) => ({ sev: "info", target: i.target, address: i.address, msg: i.role + ": " + i.holder + " (" + i.desc + ") [" + i.flag + "]" }));
        const d = await postSlack(slackUrl, slackText("Privileged posture digest, " + CONFIG.chainName + ": " + rows.length + " role(s) rely on a single key or a 1-of-N Safe", rows));
        if (!d.failed) meta.lastDigestAt = now;
        else problems.push("digest notification failed (" + d.error + ")");
        report.digest = { rows: rows.length, delivery: d };
      } else log.push("digest postponed: not enough time left in this run to read every target");
    }
  }

  report.standing = pendingSave.filter((p) => p.st.baselined).flatMap((p) => standing(p.t, p.st));
  await saveMeta();
  report.ms = Date.now() - t0;
  report.rpcRequests = rpc.stats.requests;
  report.logCalls = ctx.logCalls;
  report.next = meta.next;
  report.cycle = meta.cycle;
  report.logPasses = deep.map((x) => x.t.label);
  console.log("posture audit (" + (trig.type === "block" ? "block event " + trig.blockNumber : trig.type + " event") + "): head " + ctx.head + ", read at " + report.snapshotBlock + ", " + results.length + "/" + targets.length + " target(s), " + deep.length + " log pass(es), " + quiet + " ok, " + report.findings.length + " finding(s), " + report.ms + " ms, " + rpc.stats.requests + " rpc requests, " + written + " state write(s)" + (log.length ? "\n" + log.join("\n") : ""));
  if (problems.length) {
    // Everything that could be saved is saved. Failing the execution makes the problem visible in the
    // execution history and in failure notifications (a permanent Slack error or a failing Storage
    // call would otherwise go unnoticed).
    throw Object.assign(new Error("posture audit finished with problems: " + problems.join("; ")), { report });
  }
  return report;
}

// ============================ support code ============================
// Families used by a minority of contracts. They are separate from the everyday READERS above
// and are enabled per target through `patterns`.
Object.assign(READERS, {
  async dsauth(ctx, t, w, prev) {
    const [o, a] = await ctx.rpc.multicall([
      { to: t.address, data: SEL.owner },
      { to: t.address, data: SEL.authority },
    ]);
    if (rAddr(o) !== null && !w.roles.owner) setRole(w, "owner", "owner (DSAuth)", [rAddr(o)], { f: "high" });
    if (rAddr(a) !== null) setRole(w, "authority", "authority (decides who may call auth functions)", [rAddr(a)], { f: "high" });
    if (rAddr(o) === null && rAddr(a) === null) {
      if (hadRole(prev, "owner") || hadRole(prev, "authority")) throw tag(new Error("dsauth: owner() and authority() answered before and do not now"), "config");
      w.warn.push("dsauth: neither owner() nor authority() found");
    }
  },

  async wards(ctx, t, w, prev) {
    const scan = await scanLogs(ctx, w, t.address + ":wards", t.address, [TOPIC.Rely, TOPIC.Deny, TOPIC.NoteRely, TOPIC.NoteDeny], t.fromBlock);
    for (const l of scan.logs) {
      const t0 = lc(l.topics[0]);
      const who = t0 === TOPIC.NoteRely || t0 === TOPIC.NoteDeny ? topicAddr(l.topics[2]) : topicAddr(l.topics[1]);
      addCand(w, "ward", who);
    }
    if (!scan.done) w.syncing = true;
    const cands = [...new Set([...(w.cand.ward || []), ...t.candidates, ...((prev.roles && prev.roles.ward && prev.roles.ward.a) || [])])];
    const res = await ctx.rpc.multicall(cands.map((c) => ({ to: t.address, data: SEL.wards + encAddr(c) })));
    if (cands.length && res.every((r) => rUint(r) === null)) {
      if (hadRole(prev, "ward")) throw tag(new Error("wards: wards(address) answered before and does not now"), "config");
      w.warn.push("wards: wards(address) not found");
    }
    setRole(w, "ward", "ward (full admin)", cands.filter((c, i) => rUint(res[i]) === 1n), { f: "high" });
  },

  async "fiat-token"(ctx, t, w, prev) {
    const r = await ctx.rpc.multicall([SEL.owner, SEL.masterMinter, SEL.pauser, SEL.blacklister, SEL.rescuer].map((s) => ({ to: t.address, data: s })));
    const names = [["owner", "owner", "high"], ["masterMinter", "masterMinter (configures minters)", "high"], ["pauser", "pauser", "medium"], ["blacklister", "blacklister", "medium"], ["rescuer", "rescuer", "medium"]];
    names.forEach(([k, l, f], i) => {
      if (rAddr(r[i]) !== null && !(k === "owner" && w.roles.owner)) setRole(w, k, l, [rAddr(r[i])], f === "medium" ? { f, c: "high" } : { f });
    });
    if (rAddr(r[1]) === null) {
      if (hadRole(prev, "masterMinter")) throw tag(new Error("fiat-token: masterMinter() answered before and does not now"), "config");
      w.warn.push("fiat-token: masterMinter() not found");
    }
    const scan = await scanLogs(ctx, w, t.address + ":minters", t.address, [TOPIC.MinterConfigured, TOPIC.MinterRemoved], t.fromBlock);
    for (const l of scan.logs) addCand(w, "minter", topicAddr(l.topics[1]));
    if (!scan.done) w.syncing = true;
    const cands = [...new Set([...(w.cand.minter || []), ...t.candidates, ...((prev.roles && prev.roles.minter && prev.roles.minter.a) || [])])];
    const res = await ctx.rpc.multicall(cands.flatMap((c) => [
      { to: t.address, data: SEL.isMinter + encAddr(c) },
      { to: t.address, data: SEL.minterAllowance + encAddr(c) },
    ]));
    const minters = [];
    w.info.minterAllowance = {};
    cands.forEach((c, i) => {
      if (rBool(res[2 * i]) === true) {
        minters.push(c);
        const al = rUint(res[2 * i + 1]);
        w.info.minterAllowance[c] = al === null ? "?" : al.toString();
      }
    });
    setRole(w, "minter", "minter", minters, { f: "high" });
  },
});

// ============================ keccak256 ============================
// Ethereum keccak256 (not NIST SHA3), used to turn role names into role ids.
// Round constants and rotation offsets are derived (FIPS 202), not typed in.
const M64 = (1n << 64n) - 1n;
const KROT = new Array(25).fill(0n);
const KRC = [];
(() => {
  let x = 1;
  let y = 0;
  for (let t = 0; t < 24; t++) {
    KROT[x + 5 * y] = BigInt((((t + 1) * (t + 2)) / 2) % 64);
    [x, y] = [y, (2 * x + 3 * y) % 5];
  }
  let r = 1;
  const bit = () => {
    const b = r & 1;
    r <<= 1;
    if (r & 0x100) r ^= 0x171;
    return b;
  };
  for (let i = 0; i < 24; i++) {
    let c = 0n;
    for (let j = 0; j < 7; j++) if (bit()) c |= 1n << BigInt((1 << j) - 1);
    KRC.push(c);
  }
})();
const rotl = (v, n) => (n === 0n ? v : ((v << n) | (v >> (64n - n))) & M64);
function keccakF(A) {
  const C = new Array(5);
  const B = new Array(25);
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    for (let x = 0; x < 5; x++) {
      const d = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1n);
      for (let y = 0; y < 25; y += 5) A[x + y] ^= d;
    }
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[x + 5 * y], KROT[x + 5 * y]);
    for (let y = 0; y < 25; y += 5) for (let x = 0; x < 5; x++) A[x + y] = B[x + y] ^ (~B[((x + 1) % 5) + y] & M64 & B[((x + 2) % 5) + y]);
    A[0] ^= KRC[round];
  }
}
function keccak256(bytes) {
  const rate = 136;
  const msg = Buffer.concat([bytes, Buffer.alloc(rate - (bytes.length % rate))]);
  msg[bytes.length] ^= 0x01;
  msg[msg.length - 1] ^= 0x80;
  const A = new Array(25).fill(0n);
  for (let off = 0; off < msg.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) A[i] ^= msg.readBigUInt64LE(off + 8 * i);
    keccakF(A);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeBigUInt64LE(A[i], 8 * i);
  return "0x" + out.toString("hex");
}
const keccakText = (s) => keccak256(Buffer.from(String(s), "utf8"));
// _internals is exported for local tests only (the tests are not included in this repository); Tenderly calls actionFn.
module.exports = { actionFn, CONFIG, _internals: { keccakText, roleId, control, addSeverity, describe, classDelta, diffTarget, carryOver, standing, baselineFindings, slackParts, normTargets, boundState, trimCandidates, isRangeErr, rangeLimitFrom, isRevert, isAheadErr, prefix, makeRpc, classify, describeEvent, wantsLogs, mayScan, takeLease, dropLease, stableState, stableMeta, SEL, TOPIC, SLOT, AAVE_ROLES } };
