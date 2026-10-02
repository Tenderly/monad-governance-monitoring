# Privileged change guard

A Tenderly Web3 Action plus a set of Event alerts that watch the contracts you choose for changes of ownership, roles, proxy admins, authorities, wards, minters, Safe signers and timelock settings, on every chain the tagged contracts live on (Monad and Ethereum are configured out of the box). For every change it tells you how dangerous it is: who gets the power (EOA, EIP-7702 delegated EOA, Safe with its threshold, timelock with its delay and who may propose on it), and whether the change was announced in advance. It can optionally pause a contract when a minter changes without notice.

It covers the patterns Monad teams use: OpenZeppelin `Ownable` and `AccessControl` (roles, `DefaultAdminRules`, `TimelockController`, `AccessManager`), Safe, Solmate and Solady auth, dapptools `DSAuth` and `DSGuard`, Maker style wards including the anonymous `LogNote`, Circle FiatToken minters, Aave V3 forks (ACL admin, ACL manager, pool and configurator implementations, oracles), EIP-1967 proxies, and a few protocols deployed on Monad. 108 events are decoded by layout (100 can produce a message; 8 are context only), and every topic0 equals `keccak256` of its signature; no ABI is needed and unverified contracts work.

The guard follows five steps. Each has its own section below.

| step | what it is | where |
|---|---|---|
| 1. Role and ownership changes | one Event alert per signal, scoped to the tag `mf-privileged`, real time | `alerts/` |
| 2. EOA vs Safe | this Web3 Action decodes the log and classifies the new holder | `privChangeGuard.js` |
| 3. Silent changes and EOA posture | the posture audit (`privileged-posture-audit/`, a separate template) snapshots and diffs; the guard also reads Safe delegatecalls; one optional alert | `alerts/optional/` |
| 4. Where the ERC20 Token Transfer alert fits | three optional alerts: admin wallet tripwire, minter case, outflow of one token from the address that holds it (an Aave V3 aToken) | `alerts/optional/` |
| 5. Auto pause | optional pause rules, and the check for "without prior notice" | `CONFIG.autoPause` |

## Files

| file | what it is |
|---|---|
| `privChangeGuard.js` | the Web3 Action: decode, classify holders (and timelock proposers), check notice, score, pause, post to Slack. One file, `CONFIG` on top. |
| `changeRegistry.js` | optional second action: registry of announced changes, accepts signed announcements. |
| `announce.js` | command line helper that builds and signs an announcement (runs on your machine). |
| `alerts/` | the alert bodies (one Event Emitted alert per event), `index.json` with the packs, `create-alerts.js` to create them, an alternative with a single catch-all alert, an alternative with a transaction trigger. |
| `alerts/optional/` | four optional alerts: Safe delegatecall to a non-library target, admin wallet tripwire, token mint from 0x0, outflow of one token from a liquidity holder. |
| `tenderly.yaml.example` | CLI deployment of both actions. |
| `test-contract/GovProbe.sol` | a small contract that emits the governance events, for testing on Monad testnet. |

## 1. Role and ownership changes (event alerts, real time)

Tag every contract you want covered (this package's default tag is `mf-privileged`; the name is only a label, and `TAG=` sets any other) and create one alert per signal scoped to that tag, not one per contract. Leave the network filter off and the same alert covers every chain the tagged contracts live on, Ethereum and Monad included. New projects then only need the tag. The match is on the raw topic0, so no ABI is needed; the contract just has to be added to the Tenderly project.

The tag is one value: the `tag` of `alerts/index.json`, overridden with `TAG=` when you run `create-alerts.js`. Add the tag in the Dashboard (**Add Tag** on a contract, or on the Wallets list for a wallet) or with the API (`POST /api/v1/account/{account}/project/{project}/tag`, [add tag to multiple contracts](https://docs.tenderly.co/api-reference/contracts/add-tag-to-mutiple-contracts)). To confirm a tag, emit a test event on a tagged testnet contract and check that the alert fires.

Tag only quiet admin contracts (address registries, ACL managers, proxy admins, timelocks, Safes, master minters). The alerts consider the transactions that touch a tagged contract, so a busy pool or token adds load and noise, and a sequential Web3 Action runs at most 400 times per 5 minutes; executions above that are skipped ([usage rate limits](https://docs.tenderly.co/monitoring/web3-actions/usage-rate-limits)). Do not tag a busy pool or token.

The signals (the core packs; every one is a single alert on the topic0):

| family | events |
|---|---|
| OpenZeppelin Ownable, Ownable2Step | `OwnershipTransferred`, `OwnershipTransferStarted` |
| AccessControl | `RoleGranted`, `RoleRevoked`, `RoleAdminChanged` |
| proxies | `Upgraded`, `AdminChanged`, `BeaconUpgraded`. For a transparent proxy, whoever owns the ProxyAdmin is the real admin: the guard classifies a ProxyAdmin by its owner. |
| dapptools DSAuth | `LogSetOwner(address)` `0xce241d7c...ed94`, `LogSetAuthority(address)` `0x1abebea8...ada4` |
| dss style wards | `Rely` and `Deny` on newer modules. Older ones emit only the anonymous `LogNote`, whose topic0 is the padded function selector (`rely` is `0x65fae35e` followed by zeros). It matches the same way, and it was fire-tested on Monad testnet. |
| Safe | `AddedOwner`, `RemovedOwner`, `ChangedThreshold`, `EnabledModule`, `ChangedGuard`, `ChangedFallbackHandler` (the handler can answer signature checks on the Safe's behalf), and `ChangedMasterCopy` for the singleton change of Safe 1.1.1 and 1.2.0 (their `changeMasterCopy`) and of Safe's own migration helpers. A Safe 1.3.0 or newer whose singleton pointer is overwritten by a delegatecall emits no `ChangedMasterCopy` or other configuration event (its `execTransaction` still emits `ExecutionSuccess`), and neither does the `changeMasterCopy` of Safe 1.0.0, which is what step 3 is for. |
| AccessManager, Solmate, Solady, Circle minters, Aave V3 forks, timelocks | see the packs below |

`alerts/index.json` lists the packs. Create only what you need.

| pack | alerts | covers |
|---|---|---|
| `base` | 10 | OwnershipTransferred, OwnershipTransferStarted, RoleGranted, RoleRevoked, RoleAdminChanged, Upgraded, AdminChanged, BeaconUpgraded, Paused, Unpaused |
| `safe` | 7 | signers, threshold, modules, guard, fallback handler, singleton (ChangedMasterCopy) |
| `timelock` | 4 | MinDelayChange, Compound NewAdmin, NewPendingAdmin, NewDelay |
| `dapptools-maker` | 6 | LogSetOwner, LogSetAuthority, Rely, Deny, anonymous LogNote rely and deny |
| `solmate-solady` | 3 | Solmate Auth and RolesAuthority, Solady OwnableRoles |
| `oz-accessmanager` | 3 | AccessManager role and authority changes |
| `minter` | 4 | Circle style minters, master minter, pauser |
| `aave-fork` | 5 | ACL admin and manager, pool and configurator implementations, price oracle |
| `extended` | 49 | the rest of AccessManager, DefaultAdminRules, Solmate and Solady, DSGuard, Safe module guard, TimelockController and Compound scheduling, Circle MintController and token roles, Aave oracle sources and address registry, Diamond, Chainlink ConfirmedOwner |
| `monad-protocols` | 9 | Euler, Morpho Blue, Uniswap V3, LayerZero, Curvance, Agora |

Presets: universal minimum `base` (10 alerts), Aave V3 fork `base + timelock + aave-fork + safe` (26 alerts), stablecoin issuer `base + minter + safe` (21 alerts), dapptools or Maker style `base + dapptools-maker + safe` (23 alerts), all core packs (42 alerts), everything (100 alerts). The guard decodes all 108 events even when only some alerts exist, so a decoded event only produces a message when an alert (or the catch-all) delivers its transaction. The `extended` and `monad-protocols` packs are needed for events such as `PublicCapabilityUpdated`, `ChangedModuleGuard`, AccessManager `RoleRevoked` and delay changes, `DefaultAdmin*` scheduling, Aave `AssetSourceUpdated` and `AddressSet*`, and the Euler, Morpho and Uniswap V3 owner events.

Create the alerts with `alerts/create-alerts.js` (dry run by default; it calls the [Alerts API](https://docs.tenderly.co/monitoring/alerts/api)). Your plan may limit how many alerts an account can have, so check your alert quota in the Dashboard before a live run. If the API refuses a create, the script prints its message and stops; the alerts created so far are listed in `created-alerts.json` and are skipped by name when you run it again.

```
TENDERLY_ACCESS_KEY=... ACCOUNT=<account slug> PROJECT=<project slug> \
PACKS=base,timelock,aave-fork,safe GUARD_ACTION_ID=<guard action id> \
NOTIFY_CHANNEL_IDS=<email or Slack destination id> DRY_RUN=0 node alerts/create-alerts.js
```

Alternatives with fewer alerts:

- `alerts/alt-catchall.json`: ONE alert on every successful transaction that touches a tagged contract. The action runs on every such transaction. Sequential actions are rate limited (400 executions per 5 minutes), so on a busy contract governance transactions can be skipped. Anyone can send transactions that touch a tagged contract, so on the catch-all a flood of them can push the action over its rate limit; the per-event alerts are not affected. Use it on quiet admin contracts only.
- `alerts/alt-tx-trigger.tenderly.yaml`: no alerts, a transaction trigger pinned to your contracts and the governance topics (CLI deployment only). One entry per contract and chain; never leave the contract address empty.

## 2. EOA vs Safe (the Web3 Action on those alerts)

The alerts send their transaction to this action. The action receives the transaction and its raw logs (the `AlertEvent` payload), so it decodes the event itself: indexed arguments are in the topics, the rest in the data. It then classifies the new holder on chain:

- `eth_getCode` empty: **EOA**. A failed read is reported as "could not classify", never as EOA.
- code starting `0xef0100`: **EIP-7702 delegated EOA**. A naive "has code" check calls it a contract, but it is still one key.
- `getThreshold()`, `getOwners()` and `VERSION()` answer, the threshold is at least 1 and not above the number of owners: **Safe**, and a 1 of N Safe counts as an EOA. `VERSION()` must return a 1.x version and the owner list must be non-empty and at least as long as the threshold; the Safe singleton (no owners) and look-alikes fail one of these checks.
- `getMinDelay()` and the `PROPOSER_ROLE()` constant (OpenZeppelin), or `admin()`, `delay()` and `GRACE_PERIOD()` (Compound style): **timelock**, then the guard checks who the proposers are (below). A bare `delay()` getter is not a timelock.
- a contract whose `owner()` is one of the above counts as controlled by it (a contract owned by an EOA is single key).

Role hashes are mapped to names, so the message reads "`MINTER_ROLE` granted to 0xabc...def (EOA)". Roles the table cannot name are shown by id; `CONFIG.roleNames` adds your own.

### Timelock proposers

When a holder is a timelock the message also says who may propose on it, for example `timelock (OZ TimelockController, delay 86400 s (1d)), proposers: Safe 3/6 0x1111...1111`. Each proposer is classified like any other holder (EOA, EIP-7702, Safe m of n, contract). The standard OpenZeppelin `TimelockController` cannot list its role members, so the guard tries, in this order:

1. `getRoleMemberCount` and `getRoleMember`, when the timelock answers them;
2. the role set the posture audit (step 3) keeps in project Storage, each member confirmed live with `hasRole`. The key is `privPosture:v1:<chainId>:<deploymentName>:t:<timelock address>` (`CONFIG.postureAudit.deploymentName` is the audit's `deploymentName`; set `storagePrefix` if you changed the audit's own). The audit must list the timelock with `patterns: ["access-control"]` and `roles: ["PROPOSER_ROLE"]`;
3. otherwise the message says `proposers not readable, add the timelock to the posture audit`.

A Compound style timelock has no role set: its proposer side is `admin()`, which is classified.

What it changes in the severity. A timelock keeps its delay as notice, but if a single key can propose on it, the delay is the only protection: any one proposer can queue a call alone. So a timelock with a single-key proposer (all proposers, or one among several) is ranked **high and never quieter**, even when the change was announced, and the message says "every proposer is a single key, so the delay is only notice" (or "N of M proposers are single keys, any one of them can queue a call"). It stays below critical on purpose: the delay still gives people time to react, which a bare EOA owner (critical) does not. A critical-role policy still makes an unannounced change to it critical. A timelock listed in `knownHolders` is your explicit decision and stays info. Proposers that cannot be read change nothing: missing information raises no severity, it is only said.

### How a change is judged

| severity | when |
|---|---|
| critical | a privileged power goes to a weak holder: an EOA, an EIP-7702 delegated EOA, a 1-of-N Safe, a contract owned by one key, a timelock with a short delay. Also structural risks: Safe threshold set to 1, owner added while the Safe stays 1-of-N, a single-key Safe module, a Safe guard removed, a Safe singleton changed to an address that is not a canonical Safe implementation, a Safe delegatecall to a non-library target, timelock delay lowered, a function opened to everyone, an implementation without code, a proxy upgraded without notice by a single-key admin, the last multi-signature holder of a role removed, an owner set from `0x0` on a contract that already existed (a re-initialisation takeover). |
| high | a privileged change without prior notice to a strong holder (a Safe above threshold 1, a timelock), to a plain contract that no single key owns (the message says so: it is not a Safe or timelock and its controller is not known), or a setting change with no holder (a role admin), a timelock with a single-key proposer, a pause or unpause, a holder the guard could not classify (RPC down, or a chain without an RPC in `CONFIG.networks`), a Safe or timelock losing a power when no other strong holder could be confirmed. |
| info | an announced change to a strong holder, a change executed by a linked trusted timelock, routine roles, renounces, scheduled operations, a revoke while another strong holder remains, an initial assignment in a deployment (the owner, the first implementation and the first role grants of a contract that had no code in the previous block, or of a creation transaction). |

Which roles count as privileged is configurable: `privilegedRoles`, `routineRoles`, `unknownRolesArePrivileged`, and per contract `roles: { MINTER_ROLE: 'critical', KEEPER_ROLE: 'ignore' }` (values `critical`, `high`, `info`, `ignore`) or `strictUnannounced: true`. A keeper or operator role does not page as critical just because nobody announced it.

A `ChangedMasterCopy` to a canonical Safe implementation (`CONFIG.safe.singletons`, 1.0.0 to 1.5.0, checked on chain) is judged like any other change, so a planned upgrade is high, not critical. Any other singleton is critical.

### Deploy

1. **Edit `CONFIG`** at the top of `privChangeGuard.js`: the contracts you watch (with labels and role policies), `knownHolders` (keys you accept, such as an issuer operations key), `trustedTimelocks`, `announcers`, `postureAudit.deploymentName`, the Slack settings, the auto-pause rules.
2. **Deploy the guard** with an alert trigger, sequential (see below), and add it as a destination of the alerts.
3. **Add the Secrets** in the Dashboard under Web3 Actions > Secrets. All are optional: `SLACK_WEBHOOK_URL` (without it the message is only written to the execution log), `MONAD_RPC_URL` and `ETHEREUM_RPC_URL` (each tried before the public RPCs of its chain), `GUARDIAN_PRIVATE_KEY` (live auto-pause only).
4. **Check it**: wait about 5 minutes after creating the alerts, emit a test change on a testnet contract you control (`test-contract/GovProbe.sol` emits the events) and read the execution in the action's history.

Run the guard sequentially. The docs state that alert-triggered actions run sequentially ([triggers](https://docs.tenderly.co/monitoring/web3-actions/references/functions-events-triggers)) and that strict ordering is best effort under sustained load: Tenderly may switch a lagging action to parallel ([troubleshooting](https://docs.tenderly.co/troubleshooting/web3-actions)). The dedupe list and the pause store are single storage keys, so the guard is written for sequential runs, and you should treat alert delivery as at least once (a redelivery is possible). With the CLI, `tenderly.yaml.example` sets `execution_type: sequential`. With the REST `publishFile` endpoint, `invocationType` is `SYNC` or `ASYNC` ([API reference](https://docs.tenderly.co/api-reference/actions/create-web3-action)); in our tests an action published without it defaulted to `SYNC`, and we recommend leaving it at `SYNC`. If two runs ever overlap, expect a duplicate Slack post rather than a second pause: a live pause is signed once and stored with its nonce.

### Chains

The network id comes from the payload and is looked up in `CONFIG.networks`:

| chain | RPCs (tried in order, after the optional secret) | Tenderly slug | explorer |
|---|---|---|---|
| 1 Ethereum | `rpc.mevblocker.io`, `ethereum-rpc.publicnode.com`, `eth-pokt.nodies.app` (each answers `eth_getCode`, `eth_call` and a 9 call batch; publicnode does not serve old blocks without a token, so the guard asks the next URL when it says so) | `mainnet` | etherscan.io |
| 143 Monad | the public Monad RPCs | `monad` | monadscan.com |
| 10143 Monad testnet | the public testnet RPCs | `monad-testnet` | testnet.monadscan.com |

The public Ethereum endpoints rate limit: set `ETHEREUM_RPC_URL` for production. A chain that is not in `CONFIG.networks` never fails the run. The events are decoded and reported at severity high with the holder marked `holder not classified: no RPC configured for chain N`, the message links the transaction by its numeric id, structural risks stay critical, and auto-pause is skipped. Add the chain to `CONFIG.networks` (RPCs, explorer, Tenderly slug) to classify it. Everything in `CONFIG` that names an address (`contracts`, `knownHolders`, `trustedTimelocks`) applies on every chain.

## 3. Silent changes and EOA posture

Events only catch changes that emit something. In the publicly reported Safe singleton-swap takeovers of 2024 and 2025 no owner, threshold or module event fired, only the Safe singleton pointer in storage slot 0 changed. The **posture audit** (separate template in `privileged-posture-audit/`, with its own README) snapshots and diffs for that reason: Safe slot 0, the fallback handler and guard slots, owners, threshold and modules; `owner()`, `pendingOwner()`, DSAuth `owner()` and `authority()`, the EIP-1967 admin and implementation slots; AccessControl members (`getRoleMember` when the contract is enumerable, otherwise rebuilt from `RoleGranted` and `RoleRevoked` logs and confirmed with `hasRole`). It alerts on every material diff (a new privileged holder that is an EOA, or a 1-of-N Safe, is critical) and reports every privileged slot held by an EOA or a 1-of-N Safe: once, right after a target's baseline, and again in a weekly digest. It classifies a holder like step 2 for EOAs, EIP-7702 EOAs, Safes and contracts owned by one key; a 1-of-N Safe is ranked critical like an EOA in both templates. Its trigger and first report are described in its README. It is also what feeds the timelock proposers above.

What it does not do, so you know where step 2 and step 3 differ: findings below `notifyMinSeverity` (default `medium`) are not posted (a raised threshold, a changed signer set of a holder Safe, a removed EIP-7702 delegation, a holder that was removed; set `notifyMinSeverity: "low"` to see them); it does not read who may propose on a timelock that holds a power (a timelock is judged by its delay: 0 or below `minNoticeSeconds`, default 3600 s, is flagged), which the guard does at the moment a change hands power to one (to see proposers standing, list the timelock as a target of the audit with `roles: ["PROPOSER_ROLE"]`); and by default it reads Monad only. For an Ethereum contract run a second copy of the audit with `chainId: 1` and Ethereum `rpcUrls` and `logRpcUrls`, with the same `deploymentName` (the stored keys carry the chain id, and the guard reads the stored proposer set per chain).

### Optional extra: Safe delegatecall to a non-library target

`alerts/optional/safe-delegatecall-non-library.json` is a Function Call alert on Safe `execTransaction` with `operation == 1` (DELEGATECALL) whose `to` is not a canonical Safe library. It needs one alert per Safe: a Function Call alert takes an explicit contract address ([Alerts API](https://docs.tenderly.co/monitoring/alerts/api)), so set `SAFE_ADDRESS` (and a `LABEL`) per Safe. It needs the call decoded with the Safe ABI, and normal Safes delegatecall MultiSend all the time, so the canonical libraries are excluded: MultiSend, MultiSendCallOnly, CreateCall and SignMessageLib of Safe 1.3.0 (canonical and eip155 deployments), 1.4.1 and 1.5.0, 16 addresses. All 16 have code on Monad (143) and on Ethereum (1), checked with `eth_getCode` (the list is `CONFIG.safe.libraries`; the alert and the guard use the same one). Safe's own migration contracts (`SafeMigration`, `SafeToL2Migration`) are not libraries, so a planned singleton migration also matches; that is intended, and the guard names the helper in a note. The slot 0 snapshot of the posture audit stays the main guard.

Create it per Safe with `OPTIONAL=safe-delegatecall-non-library SAFE_ADDRESS=0x... LABEL=<safe name> node alerts/create-alerts.js` (same environment as in step 1), then put the ids of the created alerts into `CONFIG.safe.delegatecallAlertIds`. The guard handles its deliveries on its own:

- if the transaction input is `execTransaction` (`0x6a761202`) on a Safe, it decodes `to` and `operation`; operation 1 to a target outside the libraries is **critical**, "Safe delegatecall to a non-library target" (the singleton-swap route), with the target's code size and the Safe's threshold. A delegatecall to a MultiSend is opened to look for a nested delegatecall to a non-library target (`CONFIG.safe.inspectMultiSend`). This also works when no alert delivered it: any delivery whose input is such a call is checked, and the finding comes next to the governance findings of the same transaction;
- if the delegatecall frame is internal (the alert fired, but the input is not an `execTransaction` with a delegatecall, because the Safe was called from a module or another contract), it reports **high**, "Safe delegatecall alert fired, inspect the trace". Only deliveries of the alert ids you listed are treated this way, so other deliveries stay quiet.

An auto-pause rule can name the Safe (`watch`) and the kind `safe-delegatecall` (step 5); only the critical, decoded finding can pause.

## 4. Where the ERC20 Token Transfer alert fits

The ERC20 Token Transfer alert ([alert types](https://docs.tenderly.co/monitoring/alerts/types#erc20-token-transfer)) supports direction, netting per transaction and min and max amount. Among the token scopes of its Dashboard card, two matter here: **Specific token** (one token, needed for a min or max amount) and **Any ERC20 token** (every ERC-20 token, including tokens that are not added to the project). Three optional alerts in `alerts/optional/` belong to this step; the tripwire and the holder alert use the ERC20 Token Transfer type. They are meant for a native Slack or Email destination: a notification lists the matched transfers, while a Web3 Action receives the transaction and its raw logs (the `AlertEvent` payload) and would have to decode the transfers itself. The mint alert goes to Slack or Email too, because the guard only decodes governance events.

- **Admin wallet tripwire** (`admin-wallet-tripwire.json`). Add the admin EOAs and Safes found in step 3 to the project and give them the tag `mf-admin-wallets` (`admin_tag` of `index.json`, or `ADMIN_TAG=`), then one alert watches every address with that tag: `match_any` with `address_tag`, direction `sent`, `net: true`, any ERC20 token that has a USD price. A compromised admin key usually drains its own wallet or treasury too, so this is a cheap second signal. Netting keeps flash-loan round trips from firing it. Three limits. It covers ERC20 tokens only: native MON leaving a wallet is not an ERC20 `Transfer` and is not caught. It has no gating expression, so run it in a project that holds only the admin wallets and quiet contracts: the busier the project's accounts are, the more transactions the alert has to consider, whether or not a token moves. Like the other tag based alerts it carries no network filter, so it covers every chain on which a tagged wallet is in the project. As above, send it to Slack or Email.
  - **Dashboard or API.** The tripwire can be created in the Dashboard or with the API. In the Dashboard, watch the addresses with the tag, set the token scope to **Any ERC20 token**, trigger on tokens sent and turn on netting. With that scope **Notify me only about tokens with a USD price** appears under Trigger, checked by default. In the API, "any token" is `match_non_project_contracts: true` and the checkbox is `require_dollar_value: true`. `require_dollar_value` is accepted only together with `match_non_project_contracts`: `create-alerts.js` refuses a body that has it without, and `REQUIRE_DOLLAR_VALUE=0` creates the tripwire without it (every token counts again).
  - **What the USD price filter skips.** Tokens without a known USD price: spam and airdropped tokens, and the look-alike tokens of address poisoning. In that attack a token contract emits a fake `Transfer` log with `from` set to the admin wallet, so the wallet looks like it sent something. Netting already skips fakes of value zero; with the filter on, a fake of an unpriced look-alike token no longer fires the tripwire at all. The price of that: a real token with no known USD price is skipped too, so a drain of it is not reported. If an admin wallet holds such a token, add a **Specific token** alert for it (`token_addresses`), or create the tripwire with `REQUIRE_DOLLAR_VALUE=0` and accept the spam. A token you deployed yourself has no known USD price either, so to test the tripwire with one, use `REQUIRE_DOLLAR_VALUE=0` (or uncheck the box in the Dashboard).
- **The minter case** (`token-mint-from-zero.json`). Do not rely on the ERC20 Token Transfer alert for the mint itself: its docs do not describe watching 0x0 as an address. Keep a regular Event alert on the token's `Transfer` with `from == 0x0` instead. That is a parameter condition, so the token has to be a contract of the project (the body has `match_non_project_contracts: false`) with a verified ABI on Tenderly, and the parameter must carry the ABI's own name (`from` for OpenZeppelin tokens). One alert per token; add a `value >=` condition to ignore small mints.
- **Outflow of one token from the address that holds it** (`pool-outflow-of-token.json`). The ERC20 Token Transfer alert can watch where the funds sit: the holder as the watched address, that one token (the **Specific token** scope in the Dashboard, `token_addresses` in the API), direction `sent`, net, and `min_amount` in raw token units. For a lending market that is not the Pool. In an Aave V3 fork the Pool holds almost nothing: every reserve's asset sits in that reserve's aToken, and a borrow is a `Transfer` of the asset from the aToken to the borrower (checked on a real borrow of an Aave V3 fork on Monad and of Aave V3 on Ethereum: the asset leaves the aToken, the Pool sends nothing). An alert on the Pool never fires on a borrow. So create one alert per borrowable reserve: list the reserves with `Pool.getReservesList()`, read each aToken with `Pool.getReserveData(asset).aTokenAddress`, and set the watched address to that aToken, the token to the reserve's asset, and `min_amount` to the size you want to hear about. One alert per reserve because `min_amount` needs exactly one token, and every aToken has to be a contract of the project (mind the project's contract limit for a market with many reserves; the alert evaluates every supply, borrow, repay and withdraw that touches the aToken). The other leg of a minted collateral attack is the collateral arriving: the same body with `DIRECTION=received`, the watched address the aToken of the minted token, that token, and `min_amount` above any normal single deposit, reports an unusual inflow before the other assets are borrowed out. In a pool or vault that custodies the funds itself (not an Aave V3 fork) the pool or vault address is the holder.

The bodies carry placeholders. `create-alerts.js` fills them from the environment and refuses to create a body that still has one. `HOLDER_ADDRESS` is the address that holds the token (the aToken of one reserve), `LABEL` is appended to the alert name so that a second run creates a second alert (an alert is created once per name), and `DIRECTION=received` makes the outflow body the inflow alert. Run the tripwire once on its own, and the mint and holder alerts once per token or reserve, each run with its own `TOKEN_ADDRESS`, `HOLDER_ADDRESS` and `LABEL` (a `LABEL` on the tripwire would only create a duplicate). The tripwire keeps its USD price filter unless you set `REQUIRE_DOLLAR_VALUE=0`; the dry run prints `require_dollar_value true` or `false` next to it:

```
# once (add REQUIRE_DOLLAR_VALUE=0 to watch every token, spam included)
OPTIONAL=admin-wallet-tripwire NOTIFY_CHANNEL_IDS=<Slack or Email destination id> ACCOUNT=... PROJECT=... DRY_RUN=0 node alerts/create-alerts.js
# per token, or per reserve (HOLDER_ADDRESS is the aToken of that reserve)
OPTIONAL=token-mint-from-zero,pool-outflow-of-token \
TOKEN_ADDRESS=0x... HOLDER_ADDRESS=0x... NETWORK_ID=143 MIN_AMOUNT=<raw units> LABEL=<aUSDC> \
NOTIFY_CHANNEL_IDS=<Slack or Email destination id> ACCOUNT=... PROJECT=... DRY_RUN=0 node alerts/create-alerts.js
```

## 5. Auto pause

An action can sign and send `pause()` with a key kept in Secrets. Two notes: give that key only the pause or guardian role, because it is a hot key; and in most real takeovers the gap between the role change and the loss was a few minutes or less, sometimes the same transaction, so auto pause helps most on slower cascades and less on atomic ones.

### Without prior notice

The simplest check for "without prior notice" is whether the transaction that made the change also carries the timelock's `CallExecuted` (OpenZeppelin) or `ExecuteTransaction` (Compound style). If it does not, it skipped the notice period, so the guard pages or pauses. Two refinements keep this honest:

- the execution counts only for a timelock listed in `CONFIG.trustedTimelocks` with a delay of at least `minNoticeSeconds`, and only for the change it executes: the governance log must lie inside that execution, whoever made the call must be the timelock or the call's target, and the executed calldata must name the new holder or value. Otherwise an attacker could wrap a change in a zero-delay timelock of their own, or bundle an unrelated execution into the transaction. A change executed through a trusted timelock counts as notice whoever proposed it: the delay is the notice (when the timelock itself becomes the holder of a power, step 2 says who can propose on it);
- a signed announcement is an optional extra beyond a timelock (below).

Announcing a change (optional). A planned privileged change can be announced before it is executed. A matching announcement turns a `high` change to a strong holder into `info`, and it does not trigger the auto-pause for a strong holder. What an announcement can never do: excuse a single-key holder. An EOA, an EIP-7702 delegated EOA or a 1-of-N Safe stays `critical` and still triggers the pause. For a key you really accept, list it in `knownHolders` (your own explicit config).

The credential is a signature. Nothing secret is sent: the announcer signs a short text with an EIP-191 `personal_sign` and `changeRegistry.js` accepts it only when the signer is in `CONFIG.announcers`. The guard verifies the signature again when a change arrives, so a forged storage row, or another action in the same project, cannot fake notice. Deploy `changeRegistry.js` with a webhook trigger and `authenticated: false`: the signature is the credential, so the request carries no Tenderly access key. Use signing-only keys, ideally a hardware wallet; the same addresses go into `CONFIG.announcers` of both files.

```
npm install ethers@5.7.2
node announce.js announce --network 143 --contract 0x... --kind role --role MINTER_ROLE \
     --holder 0x... --days 7 --note "new bridge minter"            # prints the message to sign
ANNOUNCER_PRIVATE_KEY=0x... node announce.js announce ...           # or sign with a key from the environment
node announce.js announce ... --nonce <n> --from <t> --signature 0x...   # or use a hardware wallet signature
curl -X POST https://api.tenderly.co/api/v1/actions/<actionId>/webhook \
     -H 'content-type: application/json' -d '<the printed body>'
```

Rules: an announcement is valid for at most 30 days; it matches on network, contract, kind, role, holder or value; it is used once (the next matching change is unannounced again); a cancelled or used announcement cannot be replayed; at most 100 are stored. An AccessControl, ACLManager or AccessManager role is `kind: role`; a Circle style minter is `kind: minter`; fixed Circle roles are written `@PAUSER`, `@BLACKLISTER`, `@RESCUER` (with `kind: any`). Addresses are lowercase. Results appear in the action's execution history, and in Slack when the secret is set. Webhook actions run in parallel: send announcements one at a time (two sent within the same second can lose one, which is the safe direction). In our tests the webhook answered HTTP 200 when it accepted a request, before the action ran, so do not treat a 200 as confirmation that the announcement was stored; check the execution history. After deploying, wait a few minutes before the first request, then send `{"op":"list"}` and confirm every announcement in the execution history. The webhook is unauthenticated by design: anyone who knows its URL can create executions, though an invalid request fails.

For AccessManager, whose `OperationExecuted` log comes before the call and carries no target, only changes made by the manager itself (or on contracts it owns, or that name it as authority) are linked to a trusted timelock execution.

### The pause rule

Optional, off the critical path of detection. `autoPause.rules` names a contract to watch, the chain it lives on (`network`, default 143), the kinds and roles that matter, and the transaction that pauses (`pause()` is `0x8456cb59`; an Aave V3 fork pool is paused with `PoolConfigurator.setPoolPause(true)`, `0x7641f3d9` plus the `true` argument). A rule fires on a grant, pending or parameter change of the watched contract that was not announced (or whose holder is a single key and not in `knownHolders`). A rule acts on its own chain only, with the RPC of that chain; a chain without an RPC in `CONFIG.networks` is never paused.

`mode` is `dry-run` by default and should stay that way until you trust it. A dry run simulates the pause from the guardian address with `eth_call` and reports the result, the gas estimate and the guardian's balance. `live` signs a type 2 transaction with `GUARDIAN_PRIVATE_KEY`: it simulates first, refuses above `maxFeeGwei`, checks that the guardian can pay `gasLimit x maxFee` (Monad charges the gas limit), records the signed transaction before broadcasting, so it is never signed twice (same nonce, so it can never pause twice). If the run that sent it did not complete (for example the Slack post failed), the next delivery of the same transaction broadcasts the stored transaction again; a plain redelivery of a completed run is skipped as a duplicate. The key is validated before any library sees it and is redacted from every log and message.

### Auto-pause: limits

- **It never front-runs.** It acts seconds after the block that contains the change. An attacker who grants a role and exploits it in the same transaction, or within a few blocks (Monad blocks are about 0.3 s), is not stopped.
- **The key is readable by every action in the project.** Secrets and Storage are shared by all actions of a Tenderly project. A stolen key can pause your contract (grief) and, if it is over-privileged, do worse. Give the key only the right to pause: ideally a guardian contract or a Safe module that can call only `pause()` or `setPoolPause(true)`, never unpause and never an admin role. Run the live auto-pause in a dedicated Tenderly project.
- **A hot `EMERGENCY_ADMIN` is itself a finding.** Granting the pause power to an EOA is a privileged role on an EOA, which this guard flags.
- **It sends or it does not.** On Monad a node may accept an underfunded transaction or a nonce gap without rejecting it, so "sent, receipt not seen yet" can mean the transaction was never mined. The guard checks the balance first. It broadcasts the stored transaction again only when the run that sent it did not complete, and it does not retry on its own.
- **It does not unpause** and does not undo anything.
- **DRY RUN stays the default.**

## Limits

- Events and transaction input only. A change that emits no event and is not a Safe delegatecall in the input is not seen here; the posture audit reads such state.
- Treat alert delivery as at least once (a redelivery is possible), so the guard skips logs it already handled (transaction hash and log index). A new alert configuration takes a short while to start delivering: in our tests the first alert arrived 3 min 46 s after creation on Monad testnet, so wait about 5 minutes before you test. Executions over 400 per 5 minutes per action are dropped, not queued ([usage rate limits](https://docs.tenderly.co/monitoring/web3-actions/usage-rate-limits)).
- In our tests a run that had to verify an announcement signature took 9 to 12 s when it started cold (loading `ethers`), inside the 30 s limit, and memory reached 87 to 112 MB of 128 MB, so keep `CONFIG` small.
- Classification is one hop deep: a Safe is judged by threshold, signers and the contract it controls, a timelock by its delay and its proposers (each proposer judged like any holder, without following it further).
- Timelock proposers of an OpenZeppelin timelock need the posture audit's stored role set; without it they are not readable. The stored set is as fresh as the audit's last run, and a proposer added since is not in it (the guard does see the `RoleGranted` of that very change when the timelock is tagged). The admin role of a timelock (an optional admin that can grant `PROPOSER_ROLE` without the delay, when an EOA still holds it) is not read here.
- The Safe delegatecall alert needs the call decoded with the Safe ABI. Reading `tx.input` covers a direct `execTransaction`; a delegatecall that the Safe makes from inside another transaction is reported only as "inspect the trace".
- The public RPCs rate limit. A failed or missing read is reported as "could not classify", never as an EOA; set your own `MONAD_RPC_URL` and `ETHEREUM_RPC_URL` with a provider you trust for production.
- With `onlyListedContracts: false`, governance logs of contracts that are not listed in `contracts` but share a transaction with a delivered log are reported too; when `contracts` is not empty they are capped at `high` and labelled.
- For Solmate `Auth` the "previous owner" topic is the caller; the message says "previous owner or caller".
- The registry and the guard share project storage; the registry keeps at most 100 announcements and 90,000 bytes.

## Testing

The tests are not included in this repository. To test a deployment, emit governance events on a Monad testnet contract you control (`test-contract/GovProbe.sol` emits the events of the common families), wait about 5 minutes after creating the alerts, and read the guard's execution history. In a live run on Monad testnet, 25 probe transactions produced 23 guard executions, one for every transaction that had an alert, and the findings (decoded event, holder class, severity, notice, dry-run pause) matched what was sent. Live auto-pause was exercised from a local harness; inside Tenderly only the dry run was.

What was checked read only against real contracts: holders on Monad and Ethereum (EOA, EIP-7702 delegated EOA, Safes of several sizes, OpenZeppelin and Compound style timelocks); the proposers of nine real Monad timelocks, read from the posture audit's stored set and confirmed with `hasRole`; the 16 canonical Safe libraries, the Safe migration helpers and the Safe singletons, which all have code on Monad and Ethereum (the singletons answer `VERSION()` with their version); and a real Safe migration on Monad, which the guard reports as a delegatecall to a non-library target next to the `ChangedMasterCopy` to the canonical 1.5.0 L2 singleton, while Safe batches through MultiSendCallOnly are not reported. The two optional alerts that use the ERC20 Token Transfer type were checked against the alert API's validation rules, not created in a live project; the tripwire's `require_dollar_value` filter follows the Alerts API documentation.
