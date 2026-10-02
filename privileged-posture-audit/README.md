# Privileged posture audit

A Tenderly Web3 Action that answers one question all the time: which privileged roles of the contracts you watch rely on an EOA, or on a 1-of-N Safe, instead of a multisig or a timelock, and what changed since the last run? It runs on a block trigger (a snapshot every 25 blocks, about 7.5 seconds on Monad). A cron trigger works too.

Event alerts (the [privileged change guard](../privileged-change-guard/)) tell you about a change in the block it happens. This audit is the complete layer next to them: it also sees changes that emit no event (a Safe singleton pointer, a guard, an owner slot written directly), rebuilds role sets that cannot be enumerated on chain, and gives a standing answer to "who can do what" when nothing happened.

## What it reads

For every target it reads the current privileged holders and classifies each one:

| pattern | reads |
|---|---|
| `ownable` | `owner()` and `pendingOwner()` (OpenZeppelin `Ownable`, `Ownable2Step`) |
| `eip1967` | implementation, admin and beacon slots (and the zos / Circle proxy slots); the proxy admin is a privileged holder |
| `access-control` | `defaultAdmin()`, the members of the roles you list or of every role seen in `RoleGranted` logs (rebuilt from logs and confirmed with `hasRole`, or enumerated when the contract supports it), and each role's admin role (`getRoleAdmin`) |
| `aave-acl` | Aave V3 `PoolAddressesProvider` or `ACLManager`: ACL admin, owner, pool, configurator, oracle, and the pool admin, emergency admin, risk admin, asset listing admin, bridge and flash borrower roles |
| `safe` | signers, threshold, version, modules, guard, fallback handler, singleton (storage slot 0) |
| `dsauth` | dapptools `owner()` and `authority()` |
| `wards` | Maker style wards (rebuilt from `Rely`, `Deny` and the anonymous `LogNote`, confirmed with `wards(address)`) |
| `fiat-token` | Circle FiatToken `owner`, `masterMinter`, `pauser`, `blacklister`, `rescuer` and the minters |

Each holder is classified as EOA, EIP-7702 delegated EOA (with the delegate), Safe (version, threshold, signers, modules), timelock (delay) or other contract. Classification follows ONE hop: a ProxyAdmin or a `masterMinter` contract to its owner, a Safe to its signers and modules. A Safe answers `VERSION()` with 1.x.y, `getThreshold()` of at least 1 and a non-empty `getOwners()`; an OpenZeppelin timelock answers `getMinDelay()` and the `PROPOSER_ROLE()` constant; a Compound timelock `admin()`, `delay()` and `GRACE_PERIOD()`. Look-alikes are plain contracts. A 1-of-N Safe counts as one key, like an EOA, and a timelock whose delay is below `minNoticeSeconds` (default 3600 s, the same minimum the guard uses) counts as a short-delay timelock, like a delay of 0.

## How a run works

Every run does two things at two speeds. This is what keeps a typical run far below the 30 second limit (median 1.34 s when deployed on Monad testnet; 2 of 224 runs did not finish within the limit, see Tested).

**The snapshot: every target, on every run.** The current holders of every target are read, and every holder is classified again:

| what | how |
|---|---|
| `owner()`, `pendingOwner()`, DSAuth `owner()` and `authority()`, Aave ACL pointers, FiatToken roles | one Multicall3 call per target |
| EIP-1967 implementation, admin and beacon slots; Safe slot 0 (singleton), guard slot, fallback handler slot | `eth_getStorageAt`, batched |
| Safe owners, threshold, modules | the same Multicall3 call |
| role members | `getRoleMember` when the contract is enumerable, otherwise `hasRole` (`wards`, `isMinter`) on the members and candidates stored from the logs |
| every holder found | `eth_getCode` plus one Multicall3 probe: EOA, EIP-7702 EOA, Safe, timelock, contract; one hop |

The reads run for four targets at a time (`concurrency`) and all of them ask for the same block: the head minus 2 (`snapshotLagBlocks`, 0.6 s on Monad). One block per run means a diff compares two real states, and a provider that has not reached that block answers "block not found" and is skipped instead of trusted, so a lagging node cannot make a posture flip back and forth.

**The log pass: incremental and round robin.** Role members that cannot be enumerated on chain are rebuilt from `RoleGranted` and `RoleRevoked` logs (Maker `Rely` and `Deny`, FiatToken minter logs), with a cursor in Storage so each pass reads only new blocks. A target with such roles gets a log pass every 30 seconds (`logPassEveryS`), the oldest first, within about 5 seconds of estimated work per run (`logBudgetMs`). A baseline or a catch-up gets a log pass on every run until it is complete. A long backfill therefore never delays the snapshot of the other targets.

### The block trigger

| | |
|---|---|
| Block time on Monad mainnet | 0.302 s (timestamps of the last 1,000 up to 10,000,000 blocks) |
| Default | `blocks: 25`, a run about every 7.5 s (in our tests the runs landed on block numbers that are multiples of `blocks`) |
| Runs per 5 minutes | 40. The limits are 400 executions per 5 minutes for a sequential action and 2,000 for a parallel one; executions above the limit are skipped ([usage rate limits](https://docs.tenderly.co/monitoring/web3-actions/usage-rate-limits)) |
| Runs per day | about 11,400 |
| Other skips | 17 blocks is 5 s, 33 blocks is 10 s |
| Run time | about 3 s for the ten-target test mix (median 3.1 s, longest 4.0 s of 40 runs, see "Tested"), against the 7.5 s interval and the 30 s limit |
| JSON-RPC requests per run | 66 to 112 for those ten targets, about 7 to 11 per target |

`actionFn` takes a block event (`{ blockHash, blockNumber, network }`) and a periodic event (`{ time }`) alike: the event only means "snapshot now". A block event for another network (a trigger that lists several networks) is skipped.

Keep a run shorter than the trigger interval. Tenderly may switch a sequential action that keeps lagging behind its triggers to parallel execution ([docs](https://docs.tenderly.co/troubleshooting/web3-actions)). A steady run takes about 3 seconds; the 9 second run budget and the 5 second log budget only bound the extra work of a baseline or a catch-up. With many targets the run budget stops new targets from starting and the next run begins with the first one left (round robin, cursor in Storage), so every target still gets a snapshot every run or two.

### Overlapping runs: the storage lease

A block-triggered action runs sequentially by default: a run waits for the previous one ([execution types](https://docs.tenderly.co/monitoring/web3-actions/references/functions-events-triggers)). Runs can still overlap: an action set to parallel execution, a sequential action that Tenderly may switch to parallel when it lags, a periodic trigger next to the block trigger (periodic and webhook triggers always run in parallel), a manual run. Two runs that write the same state could baseline a target twice or post the same alert twice, so a run takes a short lease in Storage first (`lease: true`):

1. read the lease; if another run holds a live one, skip;
2. write the run's id with an expiry (`leaseTtlMs`, 32 s), wait `leaseSettleMs` (150 ms), read it back; the last writer wins and the others skip;
3. release it when the run ends, also when the run fails.

A skipped run touches no target state and reports why (`another run is active`). A run that dies without releasing blocks the next ones for at most 32 s. The Storage API has no compare-and-set operation, so the lease is best effort: two runs that start within the settle time of each other can both pass in rare cases, and the expected worst outcome is a repeated message. If Storage fails on the lease key the run goes on without a lease.

## What it alerts on

The first complete run of a target is its baseline. The baseline is not silent about the standing posture: right after it completes, with `baselinePostureAlert` (default on), the audit posts every privileged role or slot that is held by an EOA, an EIP-7702 EOA or a 1-of-N Safe, once, at alert level. A role held by a contract that a single EOA controls counts as well (a ProxyAdmin or a `masterMinter` contract owned by an EOA). Each row carries the severity a new holder like it would get, so the baseline and a later change read the same: critical for an EOA, an EIP-7702 EOA, a 1-of-N Safe (one signature moves it, like an EOA), a contract controlled by an EOA or a Safe with an EOA module; high for a pending ownership handover, a timelock with a short delay, and roles that are capped at high (pauser, keeper and similar). Safe signers are not listed (EOAs are expected there), acknowledged keys (`knownKeys`) are left out, and a message longer than Slack takes is split into up to five parts. Set `baselinePostureAlert: false` for a silent baseline.

After the baseline, a diff against the previous run raises:

| severity | finding |
|---|---|
| critical | a new holder of a privileged role (owner, proxy admin, default admin, minters, upgrader, ...) that is an EOA, an EIP-7702 EOA, a 1-of-N Safe or a contract controlled by an EOA; a holder that now relies on a single EOA key; a Safe threshold dropped to 1; a timelock delay set to 0; a new Safe singleton or ACLManager; a controlling owner changed to a single key; an EOA enabled as a Safe module |
| high | a new multisig or timelock holder of an owner, proxy admin or default admin role; a new holder that is a timelock with a short delay or a module; a pending ownership handover; a holder type change (for example a Safe replaced by a contract); a lowered threshold or timelock delay; a changed implementation, admin or role-admin pointer; a new Safe module; a pauser, blacklister, rescuer, keeper, operator or risk, emergency or listing admin that is a single key or a 1-of-N Safe (these roles are capped at high) |
| medium | a new multisig or timelock holder of any other role (including a role id granted for the first time); a Safe signer newly delegated with EIP-7702 (low when the delegate is in `knownDelegates`); a role that stayed unreadable for 24 hours and was dropped |
| low | a holder removed, a raised threshold, a changed signer set, a removed delegation, a role that was not readable for one run |
| high (operations) | a target that could not be read, or could not be baselined, for `unreadableAlertAfterHours`; a log catch-up that takes longer than `syncingAlertAfterHours` (with the blocks left and an ETA) |

Findings at or above `notifyMinSeverity` (default `medium`) go to one Slack message per run, so the audit reports every material diff. The low findings stay below the default: a raised threshold or timelock delay, a changed signer set or count of a holder Safe, a removed EIP-7702 delegation, a holder that was removed, and a role that was not readable for one run (an operational line). Set `notifyMinSeverity: "low"` to post all of them too; expect a line whenever a node hiccups. The baseline posture is its own message. Once a week (`digestEveryHours`) a digest lists the roles that rely on a single key right now, the same list as the baseline message.

Acknowledging a key: `knownKeys` takes reviewed addresses, for example a token issuer's operational keys. The acknowledgement matches the holder or the key behind a contract (the owner of a ProxyAdmin or masterMinter contract). It removes the baseline and digest row and lowers a NEW holder with that exact key to `info`. It never hides a holder type change, a threshold drop, a lowered delay or a change of the controlling owner.

## Limits

- **One hop.** A timelock that holds a privileged role of a target is judged by its delay: a delay of 0 is high and one below `minNoticeSeconds` is flagged as short, but who may propose on it is not read at that point, so a timelock with a long delay whose proposer is an EOA still looks like a timelock. To see its proposers, list the timelock as a target of its own (`patterns: ["access-control"]`, `roles: ["PROPOSER_ROLE"]`): an EOA proposer then appears in the standing posture and a new one raises a critical finding, and the guard reads the same stored set when a change hands a power to that timelock.
- **Logs decide the role sets.** Roles that cannot be enumerated are rebuilt from `RoleGranted` logs starting at `fromBlock`. A grant before `fromBlock` can stay hidden indefinitely unless the holder is listed in `candidates` or holds another role. Set `fromBlock` to the deployment block. A warning names every role whose member set came back empty.
- **A target is silent until its baseline is complete.** A long log backfill (a public endpoint that serves 100 blocks per call can take weeks) leaves the target in SYNCING; the audit then alerts with an ETA, and `LOG_RPC_URL` should point to a provider with a wide `eth_getLogs` range. The action remembers the range each provider accepted for a day and asks the widest one first.
- **Config edits.** Lowering `fromBlock` rescans the target. Editing a target's `patterns`, `roles`, `roleNames` or `candidates` adopts the new result silently, once. A real membership change that happens in the same interval as the edit is adopted with it.
- **Freshness.** A change in the snapshot (owner, pending owner, admin and implementation slots, the Safe slots, owners, threshold and modules, DSAuth) is seen by the first run whose snapshot block comes after it: at most one trigger interval plus the 2 block snapshot lag (8.2 seconds on Monad), then the run itself (about 3 seconds). A role member that exists only in logs is refreshed every 30 seconds; event alerts cover those grants in real time.
- **Pointers are diffed, not classified.** An implementation, singleton, guard, fallback handler or ACLManager that changes is a finding; the audit does not judge what it changed to.
- A node error that is not a revert is not an answer: the target becomes unreadable for that run and its stored posture is kept, so a flaky node cannot produce false "new holder" alerts afterwards.

## Setup

1. Add the action with a block trigger (the default). With the REST API ([create Web3 Action](https://docs.tenderly.co/api-reference/actions/create-web3-action), `publishFile`):

   ```json
   {
     "action": {
       "name": "privPostureAudit",
       "description": "Privileged posture audit, snapshot every 25 blocks",
       "deliveryChannels": [],
       "source": "<the contents of privPostureAudit.js, with your CONFIG>",
       "triggerType": "BLOCK",
       "runtime": "V2",
       "function": "actionFn",
       "invocationType": "SYNC",
       "trigger": { "type": "block", "block": { "network": ["143"], "blocks": 25 } }
     },
     "deploy": true
   }
   ```

   The API reference lists `invocationType` (`SYNC` or `ASYNC`) as a required field, so always set it. In our tests `SYNC` went with sequential runs (the testnet deployment below used it for its block trigger), and the API reported `ASYNC` for a periodic action, which the docs say always runs in parallel. A request that left the field out was created as `SYNC` in our tests, but do not rely on that. The lease makes either value safe. With the CLI, the documented `execution_type` field ([execution types](https://docs.tenderly.co/monitoring/web3-actions/references/functions-events-triggers)) chooses sequential or parallel execution:

   ```yaml
   actions:
     your-account/your-project:
       runtime: v2
       sources: actions
       specs:
         privPostureAudit:
           description: Privileged posture audit, snapshot every 25 blocks
           function: privPostureAudit:actionFn
           execution_type: sequential
           trigger:
             type: block
             block:
               network:
                 - 143
               blocks: 25
   ```

   **Cron as an alternative.** A periodic trigger gives the same audit with a slower snapshot. With the CLI:

   ```yaml
   actions:
     your-account/your-project:
       runtime: v2
       sources: actions
       specs:
         privPostureAudit:
           description: Privileged posture audit, every 5 minutes
           function: privPostureAudit:actionFn
           trigger:
             type: periodic
             periodic:
               interval: 5m
   ```

   The CLI takes `5m`, `10m`, `15m`, `30m`, `1h` and longer; with `publishFile` use `"triggerType": "PERIODIC"` and `"trigger": { "type": "periodic", "periodic": { "cron": "*/5 * * * *" } }`. A cron run is rarer, so give it more time per run in `CONFIG`: `runBudgetMs: 18000`, `logBudgetMs: 12000` and `maxScanMsPerTarget: 8000`. Findings are then as fresh as the interval.

2. Edit `CONFIG`. Set `deploymentName` (one short name per deployed copy: [Storage is shared by every action of a Tenderly project](https://docs.tenderly.co/monitoring/web3-actions/references/context), and two copies with the same name overwrite each other's `meta`) and list your `targets`:

   ```js
   targets: [
     { label: "My lending market PoolAddressesProvider", address: "0x...", patterns: ["ownable", "aave-acl"], fromBlock: 0 },
     { label: "My timelock", address: "0x...", patterns: ["access-control"], roles: ["DEFAULT_ADMIN_ROLE", "PROPOSER_ROLE", "EXECUTOR_ROLE", "CANCELLER_ROLE"], fromBlock: 0 },
     { label: "My token", address: "0x...", patterns: ["fiat-token", "eip1967"], fromBlock: 0 },
     { label: "My multisig", address: "0x...", patterns: ["safe"] },
   ],
   ```

   With `roles` omitted an `access-control` target audits the default admin plus every role seen in `RoleGranted` logs. The shipped `CONFIG` has no targets, so it does nothing until you add yours.
   **Another chain.** One copy of the audit reads one chain (`chainId`, default 143 Monad). For an Ethereum contract, or for the guard's Ethereum proposer hint ("proposers not readable, add the timelock to the posture audit"), deploy a second copy with `chainId: 1`, `chainName: "Ethereum"`, `explorerAddressUrl: "https://etherscan.io/address/"`, Ethereum `rpcUrls` and `logRpcUrls` (a provider that serves `eth_getLogs` over a wide range), and a block trigger on network `1`. Give both copies the same `deploymentName`: the stored keys carry the chain id (`privPosture:v1:1:<deploymentName>` on Ethereum), so the copies do not collide, and the guard's `CONFIG.postureAudit.deploymentName` is one value for every chain. Several settings count blocks and were sized for 0.3 s blocks: `confirmations` (30 blocks is 9 s on Monad, 6 minutes on Ethereum) and `snapshotLagBlocks` (2 blocks is 24 s on Ethereum), and `blocks` is the skip of the trigger (12 s per block on Ethereum). Checked: a local, read only run of a `chainId: 1` copy against two Ethereum contracts (an Ownable factory and a Safe 3/5) baselined both in one run, and the next run was clean with no state write. It has not run as a deployed Ethereum action.
3. Add the Secrets in the Dashboard under Web3 Actions > Secrets, all optional: `SLACK_WEBHOOK_URL`, `RPC_URL` (preferred RPC for reads), `LOG_RPC_URL` (preferred RPC for `eth_getLogs`). A run sends 66 to 112 JSON-RPC requests for ten targets, about 8 to 15 per second at the default skip; point `RPC_URL` at a dedicated provider for a block-cadence deployment, public endpoints rate limit. Keep a provider URL that carries an API key in these Secrets, not in `CONFIG`.
4. The first runs baseline. Targets without log-derived members baseline in the first run; the others when their log pass completes, a few runs later. Each baseline posts its standing posture. Read the execution log: every run prints one summary line, and a line for every target that is not simply ok (`BASELINE`, `SYNCING`, `CHANGED`, `UNREADABLE`, new warnings).

## Failures are loud

An execution that finishes with a problem fails on purpose, after saving everything it could: a notification that could not be delivered (the changes are held and raised again on the next run), a failing Storage read or write, a Storage value that cannot be made smaller than the 100 KB limit. A failing read is never treated as "missing", so a target is not silently re-baselined. No RPC answering `eth_blockNumber` also fails the execution. A run that is skipped because another run holds the lease is not a failure.

## Storage

One key per target, one meta key and one lease key, under `privPosture:v1:<chainId>:<deploymentName>` (override with `storagePrefix`). Values stay well under the 100 KB per-value [Storage limit](https://docs.tenderly.co/monitoring/web3-actions/references/context#storage-limits): candidate lists are trimmed oldest first, history is bounded, `roles: ["*"]` audits at most `maxRoleIds` roles, sent-finding fingerprints are hashes. A state that did not change is rewritten only every `stateHeartbeatS` seconds (600), so a steady run writes only the lease. The state of a target that leaves `CONFIG` is kept for `forgetRemovedAfterDays` (7), then deleted.

## Tested

The real action ran against Monad mainnet in a local harness with a mock Web3 Actions context (Storage with the platform limits and a modeled 100 ms per operation, Secrets, Slack captured, nothing sent), on ten real contracts that cover all eight patterns. 140 checks pass:

- **Baseline at block cadence.** The ten targets baseline in 3 runs; the standing posture of each baseline is posted once (critical rows for EOAs, 1-of-N Safes and a contract controlled by an EOA) and the following runs post nothing. Crafted states cover an EIP-7702 holder, a pending handover, a capped role, an acknowledged key and the off switch; a Slack failure at the baseline holds it and the next run delivers it once.
- **The two speeds.** 40 runs on a virtual clock at the default skip (7.55 s apart, 40 runs per 5 minutes): every run took the cheap snapshot of all ten targets, the log passes of the five log-based targets were spread over the runs (none, one or two per run, each target every 30 s), 0 findings and 0 posts. A run took a median of 3.1 s, 3.6 s at the 90th percentile and 4.0 s at most, end to end including the lease (real reads from a development machine to the public Monad endpoints and a modeled 100 ms per Storage operation; Tenderly's runtime will differ).
- **Events.** A block event, a periodic event and an empty event run the same audit; a block event for another network is skipped before any Storage or RPC call.
- **The lease.** Two and three overlapping runs from empty storage: one audits, the others skip; without the lease the same overlap baselines every target twice and posts the baseline twice. A dead run's lease blocks until it expires, an expired or corrupt lease counts as free, a Storage failure on the lease key lets the run go on, and a failing run releases it.
- **Pinned reads.** All state reads of a run carry one block number (head minus 2); a provider that answers "block not found" is skipped; with every provider behind, the targets are unreadable for that run, nothing is posted and the next run is clean.
- **Silent changes.** An `eth_getStorageAt` answer rewritten at the RPC layer, as if a slot had been written without an event (Safe slot 0, an EIP-1967 implementation slot, an EIP-1967 admin slot moved to an EOA), is raised by the very next run, posted once, not repeated, and its reversal is reported too.
- **The earlier checks.** Simulated changes in the stored baseline, fault injection (a failing RPC, a lagging log provider, failing Storage, a hanging RPC), configuration edits, two copies in one project, acknowledgements, the digest and a log provider capped at 100 blocks.
- **The snippets above.** The block and cron YAML pass the CLI's local check, `tenderly actions validate` (optional, no login needed; see the [CLI cheat sheet](https://docs.tenderly.co/monitoring/web3-actions/references/cli-cheatsheet)), and the block `publishFile` body was accepted by the API and deployed on Monad testnet (below).

The test harness is not included in this repository, so the results above are a report, not something you can rerun here. The changes it raises are simulated (edits of the stored baseline and of RPC answers), not real on-chain changes.

**Deployed on Monad testnet (block trigger, `blocks: 25`, 29 minutes, three targets).** 224 executions, 40 per 5 minutes. The standing posture was posted once per target and never repeated. 18 of 18 real owner changes, 17 of them without an event, were reported exactly once; block to report p50 7.3 s, 2.5 to 9.9 s. 0 false positives, 0 overlapping runs, 0 Storage errors. Run time median 1.34 s, p99 5.9 s. 2 of the 224 runs did not finish within the 30 s limit, and each left about 40 s without a snapshot because the runs queued behind it saw its lease. A silent change undone between two snapshots is not seen.

## Test contract

`probe/SilentProbe.sol` is a test-only contract for Monad testnet. `owner()` reads one storage slot. `setOwnerLoudly(address)` writes it and emits `OwnershipTransferred`. `setOwnerSilently(address)` writes it and emits nothing, which is the shape of a takeover that event alerts cannot see. Only the deployer and the current owner can write, and it holds no funds. Deploy it with Foundry, add it to your project, list it as a target (`patterns: ["ownable"]`), let the audit baseline it, then call `setOwnerSilently` from the deployer and read the next run of the audit.
