# Monad governance monitoring

Governance and access monitoring for Monad and other EVM chains, built on Tenderly Alerts and Web3 Actions.

Two templates answer one question about the contracts you watch: who can change owners, roles, admins and Safe settings, and is that power held by a single key or by a multisig or a timelock.

- **Privileged change guard.** Event alerts, one per governance event, deliver each matching transaction to a Web3 Action. The action decodes the change, classifies the new holder (EOA, EIP-7702 delegated EOA, Safe with its threshold, timelock with its delay), checks for prior notice, scores the severity and posts the result to Slack. Optional extras: ERC20 Token Transfer alerts for admin wallets and pools, a Safe delegatecall alert, and an auto pause that is a dry run by default.
- **Privileged posture audit.** A block-triggered Web3 Action that snapshots and diffs who holds power: owners, proxy admins, AccessControl and Aave ACL roles, DSAuth, wards, Circle FiatToken roles and Safe settings. It also sees changes that emit no event, and keeps a standing list of every privileged role that still relies on one key.

Neither template needs an ABI, so unverified contracts work. They cover OpenZeppelin `Ownable` and `AccessControl`, Safe, Solmate and Solady auth, dapptools `DSAuth`, Maker style wards, Circle FiatToken, Aave V3 forks and EIP-1967 proxies.

## Supported chains

| chain | id | change guard | posture audit |
|---|---|---|---|
| Monad mainnet | 143 | configured | configured (default) |
| Monad testnet | 10143 | configured | set in `CONFIG` |
| Ethereum | 1 | configured | set in `CONFIG` |

The guard reads the chain from each alert payload, so one set of alerts covers every chain on which a tagged contract lives. Add other chains to `CONFIG.networks` in `privChangeGuard.js`. The optional announcement registry (`changeRegistry.js`) has its own `CONFIG.networks`: check that it lists every chain you announce changes for. The posture audit watches one chain per deployed copy: set `chainId`, `chainName`, `explorerAddressUrl` and `rpcUrls` in its `CONFIG`, and the network and `blocks` interval of its block trigger.

## Repo layout

| path | what it is |
|---|---|
| `privileged-change-guard/` | `privChangeGuard.js` (the Web3 Action), `alerts/` (alert bodies, packs and `create-alerts.js`), `changeRegistry.js` and `announce.js` (optional signed announcements of planned changes), `tenderly.yaml.example`, `test-contract/` (a testnet contract that emits governance events) |
| `privileged-posture-audit/` | `privPostureAudit.js` (the Web3 Action), `probe/` (a testnet contract for changes that emit no event) |

Each folder has its own README with the full setup, severity rules and limits.

## Prerequisites

- A Tenderly account and a project where Alerts and Web3 Actions are available.
- The contracts you want to watch, added to that project. Tag them (for example in the Dashboard with **Add Tag**) so one alert per event covers all of them. The alerts are scoped to one tag: the default is the `tag` value in `privileged-change-guard/alerts/index.json`, and `TAG=<your tag>` overrides it when you create the alerts.
- The Tenderly CLI to deploy the actions (install commands and command reference: [CLI cheatsheet](https://docs.tenderly.co/monitoring/web3-actions/references/cli-cheatsheet)), and an [access token](https://docs.tenderly.co/platform/account/projects/api-tokens) to create alerts through the API.
- An alert destination (email or Slack) created in the Dashboard. See [alert destinations](https://docs.tenderly.co/monitoring/alerts/destinations/overview).
- Node.js 18 or newer, with npm, for the CLI project and the helper scripts.
- Optional: a Slack incoming webhook, and your own RPC URL per chain (the public RPCs rate limit).

Tag quiet admin contracts only: address registries, ACL managers, proxy admins, timelocks, Safes and master minters. An alert looks at every transaction that touches a tagged contract, and a sequential Web3 Action runs at most 400 times per 5 minutes ([usage rate limits](https://docs.tenderly.co/monitoring/web3-actions/usage-rate-limits)).

## Quick start

The steps follow the documented CLI flow ([Deploy a Web3 Action with the CLI](https://docs.tenderly.co/monitoring/web3-actions/tutorials/deploy-via-cli)). If your CLI version differs from what is shown here, the docs are the reference.

**1. Create an actions project and deploy the guard.** Work in a folder of your own, outside the clone. Log in, then let the CLI create the project:

```bash
git clone https://github.com/Tenderly/monad-governance-monitoring.git
export GUARD="$PWD/monad-governance-monitoring/privileged-change-guard"
mkdir governance-actions && cd governance-actions
tenderly login
tenderly actions init --language javascript
```

`tenderly actions init` asks which Tenderly project to use, then writes `tenderly.yaml` and an `actions/` folder with a `package.json` and a sample action. Check that `account_id`, `project_slug` and the `actions:` key (`<account>/<project>`) in `tenderly.yaml` name your project.

Copy the guard into `actions/` and edit `CONFIG` at the top of the copy (the contracts you watch, known holders, trusted timelocks, Slack settings):

```bash
cp "$GUARD/privChangeGuard.js" actions/
```

Delete the sample action file from `actions/` and its spec from `tenderly.yaml`, so that only your specs are deployed. Then copy the `privChangeGuard` spec from `$GUARD/tenderly.yaml.example` under `specs:` in your `tenderly.yaml`. Keep your own `account_id`, `project_slug` and `actions:` key, and make sure the specs sit under `runtime: v2` and `sources: actions`, as in the example. Deploy from the folder that holds `tenderly.yaml`:

```bash
tenderly actions validate    # optional, local check of tenderly.yaml
tenderly actions deploy
```

Announcements are optional. To use them, also copy `changeRegistry.js` into `actions/` and add its `changeRegistry` spec from `tenderly.yaml.example`; its helper `announce.js` runs on your machine and needs `npm install ethers@5.7.2`. The registry, custom role names and a live auto pause need ethers v5 inside the action. In our tests it was available in the runtime; if it is not, run `npm install ethers@5.7.2` in `actions/` and deploy again.

Prefer the Dashboard? You can create the action there instead: **Web3 Actions**, **Add Action**, trigger type **Alert**, and paste the file ([deploy via the Dashboard](https://docs.tenderly.co/monitoring/web3-actions/tutorials/deploy-via-dashboard)). After deploying, check the action's Execution History for its first run.

**2. Preview the alerts.** This is a dry run, nothing is created:

```bash
PACKS=base,safe node "$GUARD/alerts/create-alerts.js"
```

| preset | `PACKS` | alerts |
|---|---|---|
| Universal minimum | `base` | 10 |
| Aave V3 fork | `base,timelock,aave-fork,safe` | 26 |
| Stablecoin issuer | `base,minter,safe` | 21 |
| dapptools or Maker style | `base,dapptools-maker,safe` | 23 |
| All core packs | `base,safe,timelock,dapptools-maker,solmate-solady,oz-accessmanager,minter,aave-fork` | 42 |
| Everything | `all` | 100 |

**3. Create the alerts**, with the guard and your destination as delivery channels. Check your alert quota in the Dashboard first: your plan may limit how many alerts an account can have. Keep the access token in your environment, never in a file you commit:

```bash
export TENDERLY_ACCESS_KEY=<your access token>
ACCOUNT=<account slug> PROJECT=<project slug> \
PACKS=base,safe GUARD_ACTION_ID=<guard action id> \
NOTIFY_CHANNEL_IDS=<destination id> DRY_RUN=0 node "$GUARD/alerts/create-alerts.js"
```

`GUARD_ACTION_ID` is the id of the deployed guard action. In our tests an alert-triggered action showed up as a project delivery channel whose id is the action id, so the same id works as the alert's destination. The [delivery channels of your project](https://docs.tenderly.co/api-reference/delivery-channels/list-delivery-channels-for-project) (`GET /account/<account>/project/<project>/delivery-channels`) list it, and also the ids of your email and Slack destinations for `NOTIFY_CHANNEL_IDS`. To connect an alert to the action in the Dashboard instead, add the deployed Web3 Action as the alert's destination ([docs](https://docs.tenderly.co/monitoring/alerts/destinations/web3-action)). `TAG=<your tag>` overrides the tag the alerts are scoped to. The script writes the ids of the alerts it created to `created-alerts.json` in the current folder.

**4. Add secrets and test.** In the Dashboard, open **Web3 Actions**, then **Secrets**, click **Add Secret** and add `SLACK_WEBHOOK_URL` (without it the guard only writes to the execution log). In our tests a new alert took a few minutes to start delivering, so wait about 5 minutes. Then emit a test change on a testnet contract you control (`privileged-change-guard/test-contract/GovProbe.sol` emits the common governance events) and read the execution in the action's Execution History.

**5. Deploy the posture audit.** In the clone, edit `CONFIG` in `privileged-posture-audit/privPostureAudit.js` (`deploymentName`, `targets`), then deploy it the same way, as a second spec with a block trigger. The setup, with the YAML, is in [`privileged-posture-audit/README.md`](privileged-posture-audit/README.md).

## Security notes

- **Dry run is the default.** `create-alerts.js` creates nothing unless `DRY_RUN=0`. The guard's auto pause ships with `mode: 'dry-run'`: it simulates the pause with `eth_call` and reports the result, and signs nothing.
- **The auto pause key is hot and pause-only.** Live auto pause signs with `GUARDIAN_PRIVATE_KEY`, read from Web3 Actions Secrets. Give that key only the right to pause (ideally a guardian contract or Safe module that can call only `pause()`), never ownership or upgrade rights. Storage and Secrets are shared between all Actions in a project ([docs](https://docs.tenderly.co/monitoring/web3-actions/references/context)), so use a dedicated project if you enable live pause. The guard never unpauses.
- **Review `CONFIG` before deploying.** The watched contracts, `knownHolders`, `trustedTimelocks`, `announcers` and the auto pause rules decide what is reported, what is excused and what can pause a contract. A pause rule is only as good as the contract list you give it.
- **Announcements are signed.** A planned change can be announced in advance with an EIP-191 signature from an address in `CONFIG.announcers`. Use signing-only keys, ideally a hardware wallet. An announcement never excuses a change to a single-key holder.
- **The announcement webhook needs no access key.** `changeRegistry.js` is deployed with `authenticated: false` because the signature of an announcer is its credential ([webhook triggers](https://docs.tenderly.co/monitoring/web3-actions/references/functions-events-triggers)). Nobody can forge an announcement without an announcer's key, but anyone who learns the action id can start executions of it and use up its execution budget. Keep the id private and watch its execution history. If you do not use announcements, do not deploy it.
- **Keep credentials out of git.** Access tokens, webhook URLs and private keys belong in your environment or in Web3 Actions Secrets. The included `.gitignore` excludes `.env` files.
- **The test contracts are for testnets.** `GovProbe.sol` and `SilentProbe.sol` hold nothing and exist only to emit events and make silent changes on a chain you control.

## Documentation

- [Alerts API](https://docs.tenderly.co/monitoring/alerts/api)
- [Alert types, targets and parameters](https://docs.tenderly.co/monitoring/alerts/types), including the ERC20 Token Transfer alert
- [Alert destinations](https://docs.tenderly.co/monitoring/alerts/destinations/overview)
- [Web3 Action as an alert destination](https://docs.tenderly.co/monitoring/alerts/destinations/web3-action)
- [Delivery channels of a project (API)](https://docs.tenderly.co/api-reference/delivery-channels/list-delivery-channels-for-project)
- [Web3 Actions](https://docs.tenderly.co/monitoring/web3-actions/introduction)
- [Functions, events and triggers](https://docs.tenderly.co/monitoring/web3-actions/references/functions-events-triggers)
- [Storage and Secrets](https://docs.tenderly.co/monitoring/web3-actions/references/context)
- [Usage rate limits](https://docs.tenderly.co/monitoring/web3-actions/usage-rate-limits)
- [Deploy a Web3 Action with the CLI](https://docs.tenderly.co/monitoring/web3-actions/tutorials/deploy-via-cli)
- [Deploy a Web3 Action from the Dashboard](https://docs.tenderly.co/monitoring/web3-actions/tutorials/deploy-via-dashboard)
- [CLI cheatsheet](https://docs.tenderly.co/monitoring/web3-actions/references/cli-cheatsheet)

## Disclaimer

These templates are provided as is. They are examples, not a security audit, and they do not guarantee that every change is detected or prevented: an attacker can act in the same transaction or block as a privileged change, and a public RPC can rate limit or lag. Review the code and the configuration before you rely on them in production, and test on a testnet first.

## License

[MIT](LICENSE)
