// privChangeGuard.js: privileged change guard (Tenderly Web3 Action, one file). Monad and Ethereum out of the box.
//
// WHAT IT DOES
//   Alerts on ownership, role, proxy-admin, authority, ward, minter, Safe and timelock
//   changes of the contracts you watch, and says how dangerous each change is.
//   For every delivered transaction it
//     1. finds the governance logs (OpenZeppelin, Safe, timelocks, dapptools DSAuth, Maker
//        wards incl. the anonymous LogNote, Solmate, Solady, AccessManager, Circle, Aave V3
//        forks, a few Monad protocols) and decodes them by layout: who gains or loses
//        power, the previous holder, the role;
//     2. classifies the holder on chain: zero address, EOA, EIP-7702 delegated EOA, Safe
//        (version, threshold, signers), timelock (delay and who may propose) or other contract;
//     3. looks for prior notice: a signed announcement in the change registry
//        (changeRegistry.js) or the execution of a trusted timelock that is linked to
//        that very change;
//     4. scores it, optionally pauses (DRY RUN by default) and posts one Slack message.
//   It also reads the transaction input: a Safe execTransaction that delegatecalls a target
//   which is not a canonical Safe library is reported (the Safe singleton-swap takeover route).
//
// SEVERITY (see score())
//   critical  a privileged power goes to a weak holder (EOA, EIP-7702 EOA, 1-of-N Safe, a
//             contract owned by one key, a short timelock), or a structural risk: Safe
//             threshold set to 1, timelock delay lowered, a function opened to everyone,
//             an implementation without code, a Safe guard removed, a Safe singleton swapped
//             for an address that is not a canonical Safe singleton, a Safe delegatecall to a
//             non-library target, a proxy upgraded without notice by a single-key admin, the
//             last multi-signature holder of a role removed
//   high      a privileged change without prior notice to a strong holder (Safe above threshold 1,
//             timelock) or to a plain contract that no single key owns, a timelock whose proposers
//             include a single key (the delay is only notice), a
//             pause or unpause, a holder that could not be classified (including a chain
//             without an RPC in CONFIG.networks), a Safe or timelock losing a power when no
//             other strong holder could be confirmed
//   info      announced or timelock-executed changes to strong holders, routine roles,
//             renounces, scheduling, a revoke while another strong holder remains
//   "Unannounced" is also the condition of the auto-pause rule (see CONFIG.autoPause); a
//   change to a single-key holder pauses even when it was announced.
//
// TRIGGER
//   The governance alerts in alerts/ (one Event Emitted alert per topic0, scoped to the tag
//   mf-privileged, no network filter: the same alert covers every chain the tagged contracts
//   live on) with this action as a destination. The network is read from the payload and
//   looked up in CONFIG.networks. A transaction trigger payload also works
//   (alerts/alt-tx-trigger.tenderly.yaml).
//
// RUN IT SEQUENTIALLY. The docs state that alert-triggered actions run sequentially (Web3 Actions, triggers).
// CLI: tenderly.yaml.example sets execution_type sequential. REST publishFile: invocationType is SYNC or
// ASYNC (see the API reference); in our tests an action published without it defaulted to SYNC, and we
// recommend leaving it at SYNC. The dedupe list and the pause store are single storage keys, so the guard
// is written for sequential runs. Treat alert delivery as at least once (a redelivery is possible): logs
// already handled are skipped (tx hash + log index).
//
// SECRETS (Web3 Actions > Secrets, all optional)
//   SLACK_WEBHOOK_URL     Slack incoming webhook; without it the message is only logged
//   MONAD_RPC_URL         preferred RPC for Monad, tried before the public RPCs
//   ETHEREUM_RPC_URL      preferred RPC for Ethereum (the public ones rate limit)
//   GUARDIAN_PRIVATE_KEY  LIVE auto-pause only. Readable by every action of the project:
//                         give it a pause-only right, in a dedicated project (see README)

const CONFIG = {
  // ---------------------------------------------------------------- networks
  // The network id is read from the alert payload ("1" = Ethereum, "143" = Monad mainnet).
  // One alert (tag scoped, no network filter) delivers every chain, and this table says how to read
  // each one: RPCs (the optional secret is tried first), the explorer for links, and the Tenderly
  // dashboard slug (https://dashboard.tenderly.co/tx/<tenderlySlug>/<hash>) and the native coin symbol
  // (symbol, for the guardian balance in auto-pause messages). A chain that is NOT
  // listed here does not make the run fail: its events are decoded and reported with the holder
  // marked "not classified: no RPC configured for chain N" (severity high), and auto-pause is skipped.
  networks: {
    1: {
      name: 'Ethereum',
      rpcSecret: 'ETHEREUM_RPC_URL',
      // mevblocker first: it serves historical reads (eth_getCode at an old block) that publicnode answers with "Archive requests require a personal token"
      rpc: ['https://rpc.mevblocker.io', 'https://ethereum-rpc.publicnode.com', 'https://eth-pokt.nodies.app'],
      symbol: 'ETH',
      tenderlySlug: 'mainnet',
      explorer: 'https://etherscan.io',
    },
    143: {
      name: 'Monad',
      rpcSecret: 'MONAD_RPC_URL',
      rpc: ['https://rpc.monad.xyz', 'https://rpc1.monad.xyz', 'https://rpc2.monad.xyz', 'https://rpc3.monad.xyz', 'https://rpc-mainnet.monadinfra.com'],
      symbol: 'MON',
      tenderlySlug: 'monad',
      explorer: 'https://monadscan.com',
    },
    10143: {
      name: 'Monad testnet',
      rpcSecret: 'MONAD_TESTNET_RPC_URL',
      rpc: ['https://testnet-rpc.monad.xyz', 'https://rpc-testnet.monadinfra.com'],
      symbol: 'MON',
      tenderlySlug: 'monad-testnet',
      explorer: 'https://testnet.monadscan.com',
    },
  },

  // ---------------------------------------------------------------- what you watch
  // Contracts by address (any case). All fields are optional.
  //   label              name used in messages
  //   roles              per role policy, by role name or 32-byte id:
  //                      'critical' any unannounced change is critical, 'high' the default
  //                      for privileged roles, 'info' routine role, 'ignore' not reported
  //   strictUnannounced  true: every unannounced privileged change here is critical
  //                      (for protocols that announce their changes in the registry)
  contracts: {
    // '0x1111111111111111111111111111111111111111': {
    //   label: 'Example PoolAddressesProvider',
    //   roles: { MINTER_ROLE: 'critical', KEEPER_ROLE: 'ignore' },
    //   strictUnannounced: false,
    // },
  },
  // true: ignore governance logs of contracts that are not listed above. When the list is
  // not empty, logs of unlisted contracts in the same transaction are capped at 'high'.
  onlyListedContracts: false,
  extendedEvents: true, // false: decode only the core table (the EXTENDED_EVENTS block at the end of the file is skipped)
  roleNames: [], // extra role names to recognise (hashed with ethers when available), e.g. ['LIQUIDATOR_ROLE']

  // ---------------------------------------------------------------- who you accept
  // Holders you know and accept (an issuer's operational key, your own Safe). A change TO
  // one of them is not "weak" and counts as prior notice. It also suppresses the auto-pause.
  knownHolders: {
    // '0x...': 'our 3/5 operations Safe',
  },
  labels: {}, // extra address labels for messages

  // Timelocks whose executions count as prior notice. The execution must be linked to the
  // change: the governance log lies inside that execution and the executed call (target and
  // calldata) concerns the changed contract and the new holder.
  trustedTimelocks: [
    // '0x2222222222222222222222222222222222222222',
  ],
  minNoticeSeconds: 3600, // a trusted timelock needs at least this delay; a shorter one is a weak holder

  // Addresses whose EIP-191 signature makes an announcement valid (use signing-only keys,
  // for example a hardware wallet). Must match changeRegistry.js. Empty: announcements are ignored.
  announcers: [],

  // ---------------------------------------------------------------- severity
  // Role names that make a role grant "privileged". A named role that is not listed here
  // is not privileged; a role the table cannot name follows unknownRolesArePrivileged.
  privilegedRoles: [
    'DEFAULT_ADMIN_ROLE', 'ADMIN_ROLE', 'MINTER_ROLE', 'PAUSER_ROLE', 'UPGRADER_ROLE', 'BURNER_ROLE',
    'GUARDIAN_ROLE', 'TIMELOCK_ADMIN_ROLE', 'PROPOSER_ROLE', 'CANCELLER_ROLE', 'POOL_ADMIN',
    'EMERGENCY_ADMIN', 'RISK_ADMIN', 'ASSET_LISTING_ADMIN', 'BRIDGE', 'AccessManager ADMIN_ROLE',
    'PAUSER', 'DAO Permissions', 'Emergency Council', 'Timelock',
  ],
  routineRoles: [], // role names or ids that are always 'info' (keepers, operators, ...)
  unknownRolesArePrivileged: true,
  renounceSeverity: 'info', // owner or admin set to 0x0
  revokeSeverity: 'info', // raised when the last Safe or timelock holder is removed
  notifyScheduled: true, // post CallScheduled / QueueTransaction / OperationScheduled as info

  // ---------------------------------------------------------------- timelock proposers
  // When a holder is a timelock the guard also says who may PROPOSE on it. OpenZeppelin
  // TimelockController: the PROPOSER_ROLE members, read from the timelock itself when it is enumerable
  // (getRoleMemberCount / getRoleMember), else from the role set the posture audit keeps in project
  // Storage, each member re-confirmed with hasRole(); if neither exists the message says
  // "proposers not readable, add the timelock to the posture audit". Compound style timelock: admin().
  // Storage key read: <storagePrefix or privPosture:v1:<chainId>:<deploymentName>>:t:<timelock>
  // (a JSON string; roles["role:<PROPOSER_ROLE id>"].a is the member list). The audit must list the
  // timelock with patterns ["access-control"] and roles ["PROPOSER_ROLE"].
  postureAudit: {
    deploymentName: 'example', // the deploymentName of the posture audit action; '' turns the storage read off
    storagePrefix: '', // optional: the audit's own CONFIG.storagePrefix, used as is for every chain
  },

  // ---------------------------------------------------------------- Safe
  // libraries: canonical Safe libraries (CREATE2: the same address on every chain). A delegatecall to
  //            one of them is normal (MultiSend); a delegatecall to anything else is not.
  //            All 16 have code on Monad (143) and Ethereum (1), checked with eth_getCode.
  // singletons: canonical Safe implementations; ChangedMasterCopy to anything else is critical.
  //            Safe 1.0.0 and 1.2.0 exist on Ethereum only.
  // delegatecallAlertIds: ids of the optional alert alerts/optional/safe-delegatecall-non-library.json.
  //            A delivery of such an alert whose delegatecall cannot be read from the transaction input
  //            (the Safe was called from another contract) is reported as high: inspect the trace.
  // migrationHelpers: Safe's own migration contracts (also delegatecalled, by a planned upgrade). They are not libraries, so
  //            such a call is still reported as critical, with a note naming the helper.
  // inspectMultiSend: also look inside a delegatecall to a MultiSend (it can carry nested delegatecalls).
  safe: {
    libraries: {
      '0xa238cbeb142c10ef7ad8442c6d1f9e89e07e7761': 'MultiSend 1.3.0', '0x40a2accbd92bca938b02010e17a5b8929b49130d': 'MultiSendCallOnly 1.3.0',
      '0x7cbb62eaa69f79e6873cd1ecb2392971036cfaa4': 'CreateCall 1.3.0', '0xa65387f16b013cf2af4605ad8aa5ec25a2cba3a2': 'SignMessageLib 1.3.0',
      '0x998739bfdaadde7c933b942a68053933098f9eda': 'MultiSend 1.3.0 eip155', '0xa1dabef33b3b82c7814b6d82a79e50f4ac44102b': 'MultiSendCallOnly 1.3.0 eip155',
      '0xb19d6ffc2182150f8eb585b79d4abcd7c5640a9d': 'CreateCall 1.3.0 eip155', '0x98ffbbf51bb33a056b08ddf711f289936aaff717': 'SignMessageLib 1.3.0 eip155',
      '0x38869bf66a61cf6bdb996a6ae40d5853fd43b526': 'MultiSend 1.4.1', '0x9641d764fc13c8b624c04430c7356c1c7c8102e2': 'MultiSendCallOnly 1.4.1',
      '0x9b35af71d77eaf8d7e40252370304687390a1a52': 'CreateCall 1.4.1', '0xd53cd0ab83d845ac265be939c57f53ad838012c9': 'SignMessageLib 1.4.1',
      '0x218543288004cd07832472d464648173c77d7eb7': 'MultiSend 1.5.0', '0xa83c336b20401af773b6219ba5027174338d1836': 'MultiSendCallOnly 1.5.0',
      '0x2ef5ecfbea521449e4de05edb1ce63b75eda90b4': 'CreateCall 1.5.0', '0x4ffef8222648872b3de295ba1e49110e61f5b5aa': 'SignMessageLib 1.5.0',
    },
    singletons: {
      '0xb6029ea3b2c51d09a50b53ca8012feeb05bda35a': 'Safe 1.0.0', '0x34cfac646f301356faa8b21e94227e3583fe3f5f': 'Safe 1.1.1', '0x6851d6fdfafd08c0295c392436245e5bc78b0185': 'Safe 1.2.0',
      '0xd9db270c1b5e3bd161e8c8503c55ceabee709552': 'Safe 1.3.0', '0x3e5c63644e683549055b9be8653de26e0b4cd36e': 'SafeL2 1.3.0',
      '0x69f4d1788e39c87893c980c06edf4b7f686e2938': 'Safe 1.3.0 eip155', '0xfb1bffc9d739b8d520daf37df666da4c687191ea': 'SafeL2 1.3.0 eip155',
      '0x41675c099f32341bf84bfc5382af534df5c7461a': 'Safe 1.4.1', '0x29fcb43b46531bca003ddc8fcb67ffe91900c762': 'SafeL2 1.4.1',
      '0xff51a5898e281db6dfc7855790607438df2ca44b': 'Safe 1.5.0', '0xedd160febbd92e350d4d398fb636302fccd67c7e': 'SafeL2 1.5.0',
    },
    migrationHelpers: {
      '0x526643f69b81b008f46d95cd5ced5ec0edffdac6': 'SafeMigration 1.4.1', '0xff83f6335d8930cbad1c0d439a841f01888d9f69': 'SafeToL2Migration 1.4.1', '0xbd89a1ce4dde368ffab0ec35506eece0b1ffdc54': 'SafeToL2Setup 1.4.1',
      '0x6439e7abd8bb915a5263094784c5cf561c4172ac': 'SafeMigration 1.5.0', '0x900c7589200010d6c6ecaae5b06ebe653bc2d82a': 'SafeToL2Setup 1.5.0',
    },
    delegatecallAlertIds: [],
    inspectMultiSend: true,
  },

  // ---------------------------------------------------------------- output and runtime
  slack: { secret: 'SLACK_WEBHOOK_URL', minSeverity: 'info', maxChars: 3800 },
  storage: {
    seenKey: 'privGuard:seen:v1',
    seenMax: 600,
    registryKey: 'privGuard:announcements:v2', // written by changeRegistry.js
    consumedKey: 'privGuard:consumed:v1', // announcements already used (single use)
    pauseKey: 'privGuard:pauses:v1',
  },
  rpcTimeoutMs: 4000,
  budgetMs: 22000, // stop optional enrichment after this (the runtime limit is 30 s)

  // ---------------------------------------------------------------- optional auto-pause
  // Default DRY RUN: simulates the pause call from the guardian address (eth_call) and
  // reports what it would do. LIVE signs with GUARDIAN_PRIVATE_KEY. Give that key ONLY the
  // right to pause. The pause happens seconds after the block: it never front-runs.
  // A rule acts on one chain only (rule.network, default 143), with the RPC and chain id of that
  // network; a chain without an RPC in CONFIG.networks is never paused.
  autoPause: {
    mode: 'dry-run', // 'off' | 'dry-run' | 'live'
    guardian: '', // address of the pause key (dry run simulates from it)
    keySecret: 'GUARDIAN_PRIVATE_KEY',
    maxFeeGwei: 1000, // refuse to sign above this max fee per gas
    rules: [
      // {
      //   watch: '0x...',                 // contract whose change triggers the pause
      //   network: 143,                   // chain of the contract and of the pause call (default 143)
      //   kinds: ['minter', 'role', 'owner', 'proxy-admin', 'proxy', 'ward'], // 'safe-delegatecall' (watch = the Safe) also works
      //   roles: ['MINTER_ROLE', 'DEFAULT_ADMIN_ROLE'], // role events only; omit = any role
      //   unannouncedOnly: true,         // skip announced changes, except those to a single-key holder
      //   pause: { to: '0x...', data: '0x8456cb59', gasLimit: 100000, label: 'pause()' },
      //   pausedCheck: { to: '0x...', data: '0x5c975abb' }, // skip if paused() is already true
      // },
      // Aave V3 fork example: pause the whole pool from the EMERGENCY_ADMIN.
      // pause: { to: '<PoolConfigurator>', gasLimit: 400000, label: 'setPoolPause(true)',
      //          data: '0x7641f3d90000000000000000000000000000000000000000000000000000000000000001' }
    ],
  },
};

// ---------------------------------------------------------------------------- EVENTS
// [topic0, signature, kind, class, fields, family]. Every topic0 = keccak256(signature)
// (anonymous LogNote: the function selector, left-aligned). This is the core table: the
// events of the alert packs plus the timelock executions. EXTENDED_EVENTS at the end of
// the file holds the rarely used families.
// kind:   owner, pending-owner, role, role-admin, authority, ward, proxy, proxy-admin,
//         safe, timelock, minter, pause
// class:  grant (gains power), revoke (loses it), toggle (a flag says which), pending
//         (2-step, not effective yet), param (a setting), state (pause/unpause),
//         notice (a change scheduled in advance), trace (context only, never posted)
// fields: name=source:type. tN = topics[N], dN = Nth 32-byte data word, tN|dM = topics[N]
//         when the log has it, else data word M (Safe v1.3.0 and Circle do not index).
//         types: a address, aL left-aligned address (DSGuard), u uint, w bytes32 role,
//         b bool, s bytes4, dynsel first 4 bytes of a dynamic bytes arg, am AccessManager
//         uint64 role, u8 Solmate role, bits Solady role bitmap, sh keccak of a string
//         role, @NAME fixed role label.
const EVENTS = [
  ['0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0', 'OwnershipTransferred(address,address)', 'owner', 'grant', 'prev=t1|d0:a who=t2|d1:a', 'OZ Ownable, Solmate, Solady, Circle FiatToken (non-indexed), most EIP-173'],
  ['0x38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e22700', 'OwnershipTransferStarted(address,address)', 'pending-owner', 'pending', 'prev=t1|d0:a who=t2|d1:a', 'OZ Ownable2Step'],
  ['0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d', 'RoleGranted(bytes32,address,address)', 'role', 'grant', 'role=t1:w who=t2:a by=t3:a', 'OZ AccessControl, Aave ACLManager, OZ TimelockController'],
  ['0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b', 'RoleRevoked(bytes32,address,address)', 'role', 'revoke', 'role=t1:w who=t2:a by=t3:a', 'OZ AccessControl'],
  ['0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff', 'RoleAdminChanged(bytes32,bytes32,bytes32)', 'role-admin', 'param', 'role=t1:w prevRole=t2:w newRole=t3:w', 'OZ AccessControl'],
  ['0xf98448b987f1428e0e230e1f3c6e2ce15b5693eaf31827fbd0b1ec4b424ae7cf', 'RoleGranted(uint64,address,uint32,uint48,bool)', 'role', 'grant', 'role=t1:am who=t2:a delay=d0:u at=d1:u', 'OZ AccessManager'],
  ['0x9ea6790c7dadfd01c9f8b9762b3682607af2c7e79e05a9f9fdf5580dde949151', 'TargetFunctionRoleUpdated(address,bytes4,uint64)', 'authority', 'param', 'target=t1:a sel=d0:s role=t2:am', 'OZ AccessManager'],
  ['0x76a2a46953689d4861a5d3f6ed883ad7e6af674a21f8e162707159fc9dde614d', 'OperationExecuted(bytes32,uint32)', 'timelock', 'trace', 'id=t1:w', 'OZ AccessManager'],
  ['0x2f658b440c35314f52658ea8a740e05b284cdc84dc9ae01e891f21b8933e7cad', 'AuthorityUpdated(address)', 'authority', 'grant', 'who=t1|d0:a', 'OZ AccessManaged'],
  ['0xa3396fd7f6e0a21b50e5089d2da70d5ac0a3bbbd1f617a93f134b76389980198', 'AuthorityUpdated(address,address)', 'authority', 'grant', 'by=t1:a who=t2:a', 'Solmate Auth'],
  ['0x4c9bdd0c8e073eb5eda2250b18d8e5121ff27b62064fbeeeed4869bb99bc5bf2', 'UserRoleUpdated(address,uint8,bool)', 'role', 'toggle', 'who=t1:a role=t2:u8 flag=d0:b', 'Solmate RolesAuthority'],
  ['0x715ad5ce61fc9595c7b415289d59cf203f23a94fa06f04af7e489a0a76e1fe26', 'RolesUpdated(address,uint256)', 'role', 'toggle', 'who=t1:a role=t2:bits', 'Solady OwnableRoles'],
  ['0xce241d7ca1f669fee44b6fc00b8eba2df3bb514eed0f6f668f8f89096e81ed94', 'LogSetOwner(address)', 'owner', 'grant', 'who=t1|d0:a', 'dapptools DSAuth'],
  ['0x1abebea81bfa2637f28358c371278fb15ede7ea8dd28d2e03b112ff6d936ada4', 'LogSetAuthority(address)', 'authority', 'grant', 'who=t1|d0:a', 'dapptools DSAuth'],
  ['0xdd0e34038ac38b2a1ce960229778ac48a8719bc900b6c4f8d0475c6e8b385a60', 'Rely(address)', 'ward', 'grant', 'who=t1|d0:a', 'Maker wards (dss style)'],
  ['0x184450df2e323acec0ed3b5c7531b81f9b4cdef7914dfd4c0a4317416bb5251b', 'Deny(address)', 'ward', 'revoke', 'who=t1|d0:a', 'Maker wards (dss style)'],
  ['0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b', 'Upgraded(address)', 'proxy', 'grant', 'who=t1|d0:a', 'EIP-1967 / UUPS / Transparent / zos proxies'],
  ['0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f', 'AdminChanged(address,address)', 'proxy-admin', 'grant', 'prev=t1|d0:a who=t2|d1:a', 'EIP-1967 proxies'],
  ['0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e', 'BeaconUpgraded(address)', 'proxy', 'grant', 'who=t1|d0:a', 'EIP-1967 beacon proxies'],
  ['0x9465fa0c962cc76958e6373a993326400c1c94f8be2fe3a952adfa7f60b2ea26', 'AddedOwner(address)', 'safe', 'grant', 'who=t1|d0:a', 'Safe (v1.3.0 data, v1.4.1+ indexed)'],
  ['0xf8d49fc529812e9a7c5c50e69c20f0dccc0db8fa95c98bc58cc9a4f1c1299eaf', 'RemovedOwner(address)', 'safe', 'revoke', 'who=t1|d0:a', 'Safe'],
  ['0x610f7ff2b304ae8903c3de74c60c6ab1f7d6226b3f52c5161905bb5ad4039c93', 'ChangedThreshold(uint256)', 'safe', 'param', 'val=d0:u', 'Safe'],
  ['0xecdf3a3effea5783a3c4c2140e677577666428d44ed9d474a0b3a4c9943f8440', 'EnabledModule(address)', 'safe', 'grant', 'who=t1|d0:a', 'Safe'],
  ['0x1151116914515bc0891ff9047a6cb32cf902546f83066499bcf8ba33d2353fa2', 'ChangedGuard(address)', 'safe', 'grant', 'who=t1|d0:a', 'Safe'],
  ['0x5ac6c46c93c8d0e53714ba3b53db3e7c046da994313d7ed0d192028bc7c228b0', 'ChangedFallbackHandler(address)', 'safe', 'grant', 'who=t1|d0:a', 'Safe'],
  ['0x75e41bc35ff1bf14d81d1d2f649c0084a0f974f9289c803ec9898eeec4c8d0b8', 'ChangedMasterCopy(address)', 'proxy', 'grant', 'who=t1|d0:a', 'Safe (1.1.1 and 1.2.0 changeMasterCopy, Safe migration helpers)'],
  ['0x11c24f4ead16507c69ac467fbd5e4eed5fb5c699626d2cc6d66421df253886d5', 'MinDelayChange(uint256,uint256)', 'timelock', 'param', 'prevVal=d0:u val=d1:u', 'OZ TimelockController'],
  ['0xc2617efa69bab66782fa219543714338489c4e9e178271560a91b82c3f612b58', 'CallExecuted(bytes32,uint256,address,uint256,bytes)', 'timelock', 'trace', 'id=t1:w target=d0:a sel=d2:dynsel', 'OZ TimelockController'],
  ['0x71614071b88dee5e0b2ae578a9dd7b2ebbe9ae832ba419dc0242cd065a290b6c', 'NewAdmin(address)', 'timelock', 'grant', 'who=t1|d0:a', 'Compound Timelock'],
  ['0x69d78e38a01985fbb1462961809b4b2d65531bc93b2b94037f3334b82ca4a756', 'NewPendingAdmin(address)', 'pending-owner', 'pending', 'who=t1|d0:a', 'Compound Timelock'],
  ['0x948b1f6a42ee138b7e34058ba85a37f716d55ff25ff05a763f15bed6a04c8d2c', 'NewDelay(uint256)', 'timelock', 'param', 'val=t1|d0:u', 'Compound Timelock'],
  ['0xa560e3198060a2f10670c1ec5b403077ea6ae93ca8de1c32b451dc1a943cd6e7', 'ExecuteTransaction(bytes32,address,uint256,string,bytes,uint256)', 'timelock', 'trace', 'id=t1:w target=t2:a', 'Compound Timelock'],
  ['0x46980fca912ef9bcdbd36877427b6b90e860769f604e89c0e67720cece530d20', 'MinterConfigured(address,uint256)', 'minter', 'grant', 'who=t1:a val=d0:u', 'Circle FiatToken'],
  ['0xe94479a9f7e1952cc78f2d6baab678adc1b772d936c6583def489e524cb66692', 'MinterRemoved(address)', 'minter', 'revoke', 'who=t1:a', 'Circle FiatToken'],
  ['0xdb66dfa9c6b8f5226fe9aac7e51897ae8ee94ac31dc70bb6c9900b2574b707e6', 'MasterMinterChanged(address)', 'minter', 'grant', 'who=t1:a', 'Circle FiatToken'],
  ['0xb80482a293ca2e013eda8683c9bd7fc8347cfdaeea5ede58cba46df502c2a604', 'PauserChanged(address)', 'pause', 'grant', 'who=t1:a role=@PAUSER', 'Circle FiatToken'],
  ['0xe9cf53972264dc95304fd424458745019ddfca0e37ae8f703d74772c41ad115b', 'ACLAdminUpdated(address,address)', 'role-admin', 'grant', 'prev=t1:a who=t2:a', 'Aave V3 PoolAddressesProvider (and forks)'],
  ['0xb30efa04327bb8a537d61cc1e5c48095345ad18ef7cc04e6bacf7dfb6caaf507', 'ACLManagerUpdated(address,address)', 'authority', 'grant', 'prev=t1:a who=t2:a', 'Aave V3 PoolAddressesProvider'],
  ['0x8932892569eba59c8382a089d9b732d1f49272878775235761a2a6b0309cd465', 'PoolConfiguratorUpdated(address,address)', 'proxy', 'grant', 'prev=t1:a who=t2:a', 'Aave V3 PoolAddressesProvider'],
  ['0x90affc163f1a2dfedcd36aa02ed992eeeba8100a4014f0b4cdc20ea265a66627', 'PoolUpdated(address,address)', 'proxy', 'grant', 'prev=t1:a who=t2:a', 'Aave V3 PoolAddressesProvider'],
  ['0x56b5f80d8cac1479698aa7d01605fd6111e90b15fc4d2b377417f46034876cbd', 'PriceOracleUpdated(address,address)', 'authority', 'grant', 'prev=t1:a who=t2:a', 'Aave V3 PoolAddressesProvider'],
  ['0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258', 'Paused(address)', 'pause', 'state', 'by=d0:a', 'OZ Pausable'],
  ['0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa', 'Unpaused(address)', 'pause', 'state', 'by=d0:a', 'OZ Pausable'],
  ['0x65fae35e00000000000000000000000000000000000000000000000000000000', 'LogNote rely(address) (anonymous)', 'ward', 'grant', 'by=t1:a who=t2:a', 'Maker MCD LibNote (anonymous)'],
  ['0x9c52a7f100000000000000000000000000000000000000000000000000000000', 'LogNote deny(address) (anonymous)', 'ward', 'revoke', 'by=t1:a who=t2:a', 'Maker MCD LibNote (anonymous)'],
];

const ROLE_NAMES = {
  '0x0000000000000000000000000000000000000000000000000000000000000000': 'DEFAULT_ADMIN_ROLE',
  '0x12ad05bde78c5ab75238ce885307f96ecd482bb402ef831f99e7018a0f169b7b': 'POOL_ADMIN',
  '0x5c91514091af31f62f596a314af7d5be40146b2f2355969392f055e12e0982fb': 'EMERGENCY_ADMIN',
  '0x8aa855a911518ecfbe5bc3088c8f3dda7badf130faaf8ace33fdc33828e18167': 'RISK_ADMIN',
  '0x939b8dfb57ecef2aea54a93a15e86768b9d4089f1ba61c245e6ec980695f4ca4': 'FLASH_BORROWER',
  '0x08fb31c3e81624356c3314088aa971b73bcc82d22bc3e3b184b4593077ae3278': 'BRIDGE',
  '0x19c860a63258efbd0ecb7d55c626237bf5c2044c26c073390b74f0c13c857433': 'ASSET_LISTING_ADMIN',
  '0x5f58e3a2316349923ce3780f8d587db2d72378aed66a8261c916544fa6846ca5': 'TIMELOCK_ADMIN_ROLE',
  '0xb09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1': 'PROPOSER_ROLE',
  '0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63': 'EXECUTOR_ROLE',
  '0xfd643c72710c63c0180259aba6b2d05451e3591a24e58b62239378085726f783': 'CANCELLER_ROLE',
  '0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6': 'MINTER_ROLE',
  '0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a': 'PAUSER_ROLE',
  '0x3c11d16cbaffd01df69ce1c404f6340ee057498f5f00246190ea54220576a848': 'BURNER_ROLE',
  '0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3': 'UPGRADER_ROLE',
  '0xa49807205ce4d355092ef5a8a18f56e8913cf4a201fbe287825b095693c21775': 'ADMIN_ROLE',
  '0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365284bb7f0a5041': 'GUARDIAN_ROLE',
  '0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929': 'OPERATOR_ROLE',
  '0x241ecf16d79d0f8dbfb92cbc07fe17840425976cf0667f022fe9877caa831b08': 'MANAGER_ROLE',
  '0xfc8737ab85eb45125971625a9ebdb75cc78e01d5c1fa80c4c6e5203f47bc4fab': 'KEEPER_ROLE',
};

// Function selectors and slots (cast sig / cast keccak).
const SEL = {
  getThreshold: '0xe75235b8', getOwners: '0xa0e67e2b', VERSION: '0xffa1ad74', getMinDelay: '0xf27a0c92',
  delay: '0x6a42b8f8', owner: '0x8da5cb5b', authority: '0xbf7e214f', NAME: '0xa3f4df7e', name: '0x06fdde03',
  PROPOSER_ROLE: '0x8f61f4f5', GRACE_PERIOD: '0xc1a287e2', admin: '0xf851a440',
  getRoleMemberCount: '0xca15c873', getRoleMember: '0x9010d07c', hasRole: '0x91d14854',
};
const SEL_EXEC_TRANSACTION = '0x6a761202'; // Safe execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)
const SEL_MULTISEND = '0x8d80ff0a'; // MultiSend multiSend(bytes)
const SLOT_ADMIN = '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103'; // EIP-1967 admin
const SLOT_ZOS_ADMIN = '0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b'; // zos / Circle proxies
const PROPOSER_ROLE_ID = '0xb09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1';
const SAFE_VERSION = /^1\.\d+\.\d+/;
const ZERO = '0x0000000000000000000000000000000000000000';
const SEV = { info: 0, high: 1, critical: 2 };
const PRIV_KINDS = new Set(['owner', 'pending-owner', 'proxy', 'proxy-admin', 'role-admin', 'authority', 'ward', 'minter', 'timelock', 'pause', 'safe']);
const RENOUNCE_KINDS = new Set(['owner', 'pending-owner', 'proxy-admin', 'role-admin', 'authority', 'ward', 'minter', 'timelock', 'pause', 'role']);

// ---------------------------------------------------------------------------- helpers
const lc = (a) => String(a || '').toLowerCase();
const strip = (h) => String(h || '').replace(/^0x/i, '').toLowerCase();
const isAddr = (a) => /^0x[0-9a-f]{40}$/.test(lc(a));
const short = (a) => (a && a.length > 14 ? `${a.slice(0, 6)}...${a.slice(-4)}` : String(a));
function words(hex) {
  const s = strip(hex);
  const out = [];
  for (let i = 0; i + 64 <= s.length; i += 64) out.push(s.slice(i, i + 64));
  return out;
}
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
// Error text for logs and Slack. 64-hex runs (private keys, hashes) and URLs are redacted: an
// error message from a library must never be able to carry key material out, and a URL taken from a
// secret (an RPC URL can contain an API key) must never reach a log or Slack.
const errMsg = (e) =>
  String((e && e.message) || e)
    .replace(/(?:0x)?[0-9a-fA-F]{64}/g, '[hex value redacted]')
    .replace(/https?:\/\/\S+/g, '[url redacted]')
    .slice(0, 200);
// Network table lookups. A chain that is not in CONFIG.networks is not an error (see CONFIG.networks).
const netCfg = (net) => (Object.prototype.hasOwnProperty.call(CONFIG.networks, net) ? CONFIG.networks[net] : null);
const netName = (net) => (netCfg(net) ? netCfg(net).name : `chain ${net}`);
// The payload carries the numeric network id ("143"); a slug ("monad") is mapped back to the id.
function normNet(v) {
  const s = String(v === undefined || v === null || v === '' ? '143' : v).toLowerCase();
  if (netCfg(s)) return s;
  const hit = Object.entries(CONFIG.networks).find(([, n]) => lc(n.tenderlySlug) === s);
  return hit ? hit[0] : s;
}
const explorerAddr = (net, a) => (netCfg(net) && netCfg(net).explorer ? `${netCfg(net).explorer}/address/${a}` : null);
const tenderlyTx = (net, hash) => `https://dashboard.tenderly.co/tx/${netCfg(net) ? netCfg(net).tenderlySlug : net}/${hash}`;
function fmtDur(sec) {
  const s = Number(sec);
  if (!Number.isFinite(s)) return String(sec);
  if (s === 0) return '0 s (no delay)';
  for (const [u, n] of [['d', 86400], ['h', 3600], ['m', 60]]) if (s >= n && s % n === 0) return `${s} s (${s / n}${u})`;
  return `${s} s`;
}
const fmtMon = (wei) => (Number(BigInt(wei) / 10n ** 14n) / 1e4).toFixed(4);
const nativeSym = (net) => (netCfg(net) && netCfg(net).symbol) || 'native coin';
const fmtNative = (wei, net) => `${fmtMon(wei)} ${nativeSym(net)}`;
// Config lookups by address, whatever the case of the configured keys.
const byAddr = (obj, a) => {
  if (!obj) return undefined;
  if (obj[a] !== undefined) return obj[a];
  const k = Object.keys(obj).find((x) => lc(x) === a);
  return k === undefined ? undefined : obj[k];
};
const contractCfg = (a) => byAddr(CONFIG.contracts, lc(a)) || null;
function labelOf(a) {
  const x = lc(a);
  const c = contractCfg(x);
  return (c && c.label) || byAddr(CONFIG.knownHolders, x) || byAddr(CONFIG.labels, x) || '';
}
let ETHERS; // ethers v5 (5.7.2 in our tests) is available in the Tenderly runtime; only custom role names, announcements and LIVE auto-pause need it
function getEthers() {
  if (ETHERS === undefined) {
    try {
      ETHERS = require('ethers');
    } catch (e) {
      ETHERS = null;
    }
  }
  return ETHERS;
}

// ---------------------------------------------------------------------------- event table
// Parsed once per setting of CONFIG.extendedEvents.
const TABLES = {};
function tableFor(ext) {
  const key = ext ? 'ext' : 'core';
  if (TABLES[key]) return TABLES[key];
  const EV = new Map();
  for (const [t0, sig, kind, cls, fields, family] of [...EVENTS, ...(ext ? EXTENDED_EVENTS() : [])]) {
    const f = {};
    for (const tok of fields.split(' ').filter(Boolean)) {
      const [name, spec] = tok.split('=');
      if (spec.startsWith('@')) {
        f[name] = { fixed: spec.slice(1) };
        continue;
      }
      const [src, type] = spec.split(':');
      f[name] = { type, src: src.split('|').map((s) => ({ t: s[0], i: Number(s.slice(1)) })) };
    }
    const name = sig.startsWith('LogNote') ? sig.replace(' (anonymous)', '') : sig.split('(')[0];
    EV.set(t0, { t0, sig, name, kind, cls, fields: f, family });
  }
  // Timelock executions (OZ TimelockController, Compound Timelock, OZ AccessManager).
  const T_EXEC = Object.fromEntries([...EV.values()].filter((e) => ['CallExecuted', 'ExecuteTransaction', 'OperationExecuted'].includes(e.name)).map((e) => [e.t0, e.name]));
  TABLES[key] = { EV, T_EXEC };
  return TABLES[key];
}

function decodeLog(log, spec) {
  const topics = (log.topics || []).map(strip);
  const data = words(log.data);
  const out = {};
  for (const [name, f] of Object.entries(spec.fields)) {
    if (f.fixed) {
      out[name] = f.fixed;
      out[name + 'Type'] = 'fixed';
      continue;
    }
    let w = null;
    for (const s of f.src) {
      if (s.t === 't' && topics[s.i] !== undefined) {
        w = topics[s.i].padStart(64, '0');
        break;
      }
      if (s.t === 'd' && data[s.i] !== undefined) {
        w = data[s.i];
        break;
      }
    }
    out[name + 'Type'] = f.type;
    if (w === null) {
      out[name] = null;
      continue;
    }
    if (f.type === 'a') out[name] = '0x' + w.slice(24);
    else if (f.type === 'aL') out[name] = '0x' + w.slice(0, 40);
    else if (f.type === 'u') out[name] = BigInt('0x' + w);
    else if (f.type === 'b') out[name] = BigInt('0x' + w) !== 0n;
    else if (f.type === 's') out[name] = '0x' + w.slice(0, 8);
    else if (f.type === 'dynsel') {
      const off = Number(BigInt('0x' + w) / 32n);
      const len = data[off] ? Number(BigInt('0x' + data[off])) : 0;
      out[name] = len >= 4 && data[off + 1] ? '0x' + data[off + 1].slice(0, 8) : null;
    } else out[name] = '0x' + w; // w, am, u8, bits, sh: kept as a 32-byte word
  }
  return out;
}

// ABI dynamic bytes whose offset sits in data word `wordIdx`, as lowercase hex without 0x.
function dynBytes(log, wordIdx) {
  try {
    const w = words(log.data);
    const off = Number(BigInt('0x' + w[wordIdx]) / 32n);
    const len = Number(BigInt('0x' + w[off]));
    return strip(log.data).slice((off + 1) * 64, (off + 1) * 64 + len * 2);
  } catch (e) {
    return null;
  }
}

let EXTRA_ROLES; // CONFIG.roleNames hashed with ethers
function extraRoleName(id) {
  if (EXTRA_ROLES === undefined || EXTRA_ROLES.src !== CONFIG.roleNames) {
    EXTRA_ROLES = { src: CONFIG.roleNames, map: {} };
    const eth = getEthers();
    if (eth && Array.isArray(CONFIG.roleNames)) for (const n of CONFIG.roleNames) EXTRA_ROLES.map[eth.utils.id(n)] = n;
  }
  return EXTRA_ROLES.map[id] || null;
}

function roleInfo(id, type) {
  if (id === null || id === undefined) return null;
  const isPriv = (n) => (n ? CONFIG.privilegedRoles.includes(n) : CONFIG.unknownRolesArePrivileged);
  if (type === 'fixed') return { id: null, name: id, label: id, privileged: isPriv(id) };
  const n = BigInt(id);
  if (type === 'am') {
    if (n === 0n) return { id, name: 'AccessManager ADMIN_ROLE', label: 'AccessManager ADMIN_ROLE (0)', privileged: isPriv('AccessManager ADMIN_ROLE') };
    if (n === 2n ** 64n - 1n) return { id, name: 'PUBLIC_ROLE', label: 'AccessManager PUBLIC_ROLE (anyone)', privileged: true };
    return { id, name: null, label: `AccessManager role ${n}`, privileged: isPriv(null) };
  }
  if (type === 'u8') return { id, name: null, label: `role #${n}`, privileged: isPriv(null) };
  if (type === 'bits') {
    const bits = [];
    for (let i = 0; i < 256 && bits.length < 12; i++) if ((n >> BigInt(i)) & 1n) bits.push(i);
    return { id, name: null, label: n === 0n ? 'no roles (bitmap 0)' : `role bitmap, bits ${bits.join(',')}`, privileged: isPriv(null) };
  }
  if (type === 'sh') {
    const nm = STRING_ROLES[id];
    return { id, name: nm || null, label: nm ? `"${nm}"` : `string role (keccak ${short(id)})`, privileged: isPriv(nm) };
  }
  const nm = ROLE_NAMES[id] || extraRoleName(id);
  if (nm) return { id, name: nm, label: nm, privileged: isPriv(nm) };
  const h = strip(id);
  if (/^f{64}$/.test(h)) return { id, name: null, label: 'wildcard role (0xff..ff)', privileged: true };
  if (/^[0-9a-f]{8}0{56}$/.test(h) && !/^0{8}/.test(h)) return { id, name: null, label: `function-selector role 0x${h.slice(0, 8)}`, privileged: isPriv(null) };
  return { id, name: null, label: `role ${short(id)}`, privileged: isPriv(null) };
}

// ---------------------------------------------------------------------------- RPC
class RpcError extends Error {
  constructor(e) {
    super(String((e && e.message) || 'rpc error'));
    this.data = e && e.data;
    // Not an answer, ask the next URL: rate limits, timeouts, and history a node does not serve (publicnode answers
    // an old-block eth_getCode with -32602 "Archive requests require a personal token").
    this.transport = /rate|limit|too many|capacity|unavailable|timeout|exceeded|archive|personal token|pruned|missing trie/i.test(this.message) && !/revert/i.test(this.message);
  }
}

const CACHED = new Set(['eth_getCode', 'eth_call']);
// JSON-RPC batch with fallback: items that fail with a transport error (rate limit,
// timeout, missing answer) are retried on the next URL; a revert is a real answer.
async function rpcBatch(ctx, calls) {
  const out = new Array(calls.length);
  let pending = [];
  calls.forEach((c, i) => {
    const k = c.method + JSON.stringify(c.params);
    if (CACHED.has(c.method) && ctx.cache.has(k)) out[i] = ctx.cache.get(k);
    else pending.push(i);
  });
  let last = new Error('no RPC URL configured');
  for (const url of ctx.urls) {
    if (!pending.length) break;
    try {
      const body = pending.map((i, j) => ({ jsonrpc: '2.0', id: j + 1, method: calls[i].method, params: calls[i].params }));
      const r = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body.length === 1 ? body[0] : body),
        signal: AbortSignal.timeout(CONFIG.rpcTimeoutMs),
      });
      if (!r.ok) throw new Error(`HTTP ${r.status} from an RPC URL`); // the URL can carry a key: never print it
      let j = await r.json();
      if (!Array.isArray(j)) j = [j];
      const byId = new Map(j.map((x) => [x.id, x]));
      const retry = [];
      pending.forEach((i, n) => {
        const x = byId.get(n + 1);
        const res = !x ? new RpcError({ message: 'missing response (rate limited?)' }) : x.error ? new RpcError(x.error) : x.result;
        out[i] = res;
        if (res instanceof RpcError && res.transport) {
          retry.push(i);
          last = res;
        } else if (CACHED.has(calls[i].method) && res !== null && !(res instanceof Error)) {
          // cache only state reads; never a null (pending receipt) or a nonce/fee/send call
          ctx.cache.set(calls[i].method + JSON.stringify(calls[i].params), res);
        }
      });
      pending = retry;
    } catch (e) {
      last = new Error(errMsg(e));
    }
  }
  if (pending.length && pending.length === calls.length) throw last;
  return out;
}

async function rpc(ctx, method, params) {
  const [r] = await rpcBatch(ctx, [{ method, params }]);
  if (r instanceof Error) throw r;
  return r;
}

// eth_call many (to, data) pairs; a revert or empty answer comes back as null.
// .transportFail is set when an answer is missing because every RPC failed (not a revert).
async function callMany(ctx, pairs) {
  const res = await rpcBatch(ctx, pairs.map(([to, data, from]) => ({ method: 'eth_call', params: [{ to, data, ...(from ? { from } : {}) }, 'latest'] })));
  const out = res.map((r) => (r instanceof Error || !r || strip(r).length < 64 ? null : r));
  out.transportFail = res.some((r) => r instanceof RpcError && r.transport);
  return out;
}

const asUint = (hex) => (hex ? BigInt('0x' + words(hex)[0]) : null);
function asAddr(hex) {
  if (!hex) return null;
  const w = words(hex)[0];
  return w && /^0{24}/.test(w) ? '0x' + w.slice(24) : null;
}
function asAddrArray(hex) {
  if (!hex) return null;
  const w = words(hex);
  try {
    const off = Number(BigInt('0x' + w[0]) / 32n);
    const n = Number(BigInt('0x' + w[off]));
    if (!(n >= 0 && n <= 300) || off + n >= w.length + 1) return null;
    const out = [];
    for (let i = 0; i < n; i++) {
      if (!/^0{24}/.test(w[off + 1 + i] || 'x')) return null;
      out.push('0x' + w[off + 1 + i].slice(24));
    }
    return out;
  } catch (e) {
    return null;
  }
}
function asString(hex) {
  if (!hex) return null;
  const w = words(hex);
  try {
    let bytes;
    if (w.length >= 2 && BigInt('0x' + w[0]) === 32n) {
      const len = Number(BigInt('0x' + w[1]));
      bytes = Buffer.from(w.slice(2).join(''), 'hex').subarray(0, Math.min(len, 64));
    } else bytes = Buffer.from(w[0], 'hex');
    const s = bytes.toString('utf8').replace(/\u0000+$/, '');
    return /^[\x20-\x7e]{1,64}$/.test(s) ? s : null;
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------------------- classify
// cls: zero | eoa | eip7702 | safe | timelock | contract | unknown
// singleKey: one private key alone controls it (EOA, 7702 EOA, Safe with threshold 1,
// or a contract whose owner() is one of those). weak: single key or a timelock whose
// delay is below CONFIG.minNoticeSeconds. unknown (RPC failed) is treated as weak by score().
// deep: follow one hop (the owner of a contract, the signers of a Safe, the proposers of a timelock).
// proposers: read the proposers of a timelock (defaults to deep; the proposers themselves are classified
// without it, so a timelock behind a timelock never recurses).
async function classify(ctx, addr, deep = true, proposers = deep) {
  const a = lc(addr);
  const key = `${a}:${deep}:${proposers}`;
  if (ctx.holders.has(key)) return ctx.holders.get(key);
  const p = classifyUncached(ctx, a, deep, proposers).catch((e) => ({ addr: a, cls: 'unknown', desc: `could not classify (${errMsg(e)})` }));
  ctx.holders.set(key, p);
  return p;
}

// A Safe answers VERSION() with 1.x.y, getThreshold() >= 1 and a non-empty getOwners()
// that is at least as long as the threshold. A singleton or a look-alike fails one of them.
function parseSafe([thr, owners, version]) {
  const t = asUint(thr);
  const os = asAddrArray(owners);
  const v = asString(version);
  if (t === null || !os || !os.length || t < 1n || t > BigInt(os.length) || !v || !SAFE_VERSION.test(v)) return null;
  return { t, os, v };
}
// OZ TimelockController: getMinDelay() and the PROPOSER_ROLE() constant. Compound Timelock:
// admin(), delay() and GRACE_PERIOD(). A bare delay() getter is not a timelock.
function parseTimelock([minDelay, proposerRole, delay, admin, grace]) {
  const md = asUint(minDelay);
  if (md !== null && md < 10n ** 10n && proposerRole && strip(proposerRole).slice(0, 64) === strip(PROPOSER_ROLE_ID)) return { delay: md, flavor: 'OZ TimelockController' };
  const dl = asUint(delay);
  const gp = asUint(grace);
  if (dl !== null && dl <= 31536000n && asAddr(admin) && gp !== null && gp > 0n) return { delay: dl, flavor: 'Compound Timelock', admin: asAddr(admin) };
  return null;
}

// Public RPCs rate limit now and then: retry a failed read a couple of times before giving up.
async function retried(ctx, fn) {
  let out;
  for (let k = 0; k < 3; k++) {
    try {
      out = await fn();
      if (!(out && out.transportFail)) return out;
    } catch (e) {
      if (k === 2) throw e;
    }
    if (Date.now() > ctx.deadline) break;
    await new Promise((res) => setTimeout(res, 400 * (k + 1)));
  }
  return out;
}

async function classifyUncached(ctx, a, deep, proposers) {
  if (!isAddr(a)) return { addr: a, cls: 'unknown', desc: 'not an address' };
  if (a === ZERO) return { addr: a, cls: 'zero', desc: 'zero address' };
  if (ctx.noRpc) return { addr: a, cls: 'unknown', noRpc: true, desc: `holder not classified: no RPC configured for chain ${ctx.net}` };
  if (Date.now() > ctx.deadline) return { addr: a, cls: 'unknown', desc: 'not classified (time budget)' };
  const raw = await retried(ctx, () => rpc(ctx, 'eth_getCode', [a, 'latest']));
  if (typeof raw !== 'string' || !/^0x[0-9a-f]*$/i.test(raw)) return { addr: a, cls: 'unknown', desc: 'could not read the code (the RPC returned no result)' };
  const code = strip(raw);
  if (!code) return { addr: a, cls: 'eoa', singleKey: true, weak: true, desc: 'EOA (no code)' };
  if (code.startsWith('ef0100') && code.length === 46) {
    const delegate = '0x' + code.slice(6);
    let dn = null;
    if (deep) {
      const [n1, n2] = await callMany(ctx, [[delegate, SEL.NAME], [delegate, SEL.name]]);
      dn = asString(n1) || asString(n2);
    }
    return { addr: a, cls: 'eip7702', singleKey: true, weak: true, delegate, desc: `EOA with EIP-7702 delegation to ${dn ? dn + ' ' : ''}${delegate} (the private key still controls it)` };
  }
  const probes = await retried(ctx, () => callMany(ctx, [
    [a, SEL.getThreshold], [a, SEL.getOwners], [a, SEL.VERSION],
    [a, SEL.getMinDelay], [a, SEL.PROPOSER_ROLE], [a, SEL.delay], [a, SEL.admin], [a, SEL.GRACE_PERIOD], [a, SEL.owner],
  ]));
  if (probes.transportFail) return { addr: a, cls: 'unknown', desc: 'contract, not classified (RPC rate limited)' };
  const safe = parseSafe(probes.slice(0, 3));
  if (safe) {
    const info = { addr: a, cls: 'safe', threshold: Number(safe.t), owners: safe.os, version: safe.v, singleKey: safe.t === 1n, weak: safe.t === 1n };
    const signers = deep ? await signerSummary(ctx, safe.os) : null;
    info.signerKinds = signers;
    info.desc = `Safe ${safe.t}/${safe.os.length} (v${safe.v})${signers ? `, signers: ${signers}` : ''}${safe.t === 1n ? ', ONE signature moves it' : ''}`;
    return info;
  }
  const tl = parseTimelock(probes.slice(3, 8));
  if (tl) {
    const weak = tl.delay < BigInt(CONFIG.minNoticeSeconds);
    const info = { addr: a, cls: 'timelock', flavor: tl.flavor, delay: Number(tl.delay), singleKey: false, weak };
    const pr = proposers ? await readProposers(ctx, a, tl).catch((e) => ({ risk: 'unreadable', text: `proposers not readable (${errMsg(e)})`, list: [] })) : null;
    if (pr) {
      info.proposers = pr;
      info.proposerRisk = pr.risk;
    }
    info.desc = `timelock (${tl.flavor}, delay ${fmtDur(tl.delay)})${weak ? ', delay below the notice minimum' : ''}${pr ? `, ${pr.text}` : ''}`;
    return info;
  }
  const ow = deep ? asAddr(probes[8]) : null;
  if (ow && ow !== ZERO && ow !== a) {
    const oc = await classify(ctx, ow, false);
    return { addr: a, cls: 'contract', owner: ow, ownerCls: oc.cls, singleKey: oc.singleKey === true, weak: oc.weak === true, desc: `contract owned by ${ow} (${oc.desc})` };
  }
  return { addr: a, cls: 'contract', singleKey: false, desc: `contract (${code.length / 2} bytes, not a Safe or timelock)` };
}

// Short label of a classified holder, used in the proposer list: "Safe 3/5", "EOA", ...
function kindLabel(c) {
  if (c.cls === 'safe') return `Safe ${c.threshold}/${c.owners.length}`;
  if (c.cls === 'contract') return c.singleKey ? 'contract owned by one key' : 'contract';
  return { eoa: 'EOA', eip7702: 'EIP-7702 EOA', timelock: 'timelock', zero: 'zero address' }[c.cls] || 'not classified';
}

// Who may propose on a timelock. OZ TimelockController: the PROPOSER_ROLE members. The standard
// contract is not enumerable, so: (1) getRoleMemberCount/getRoleMember when the timelock answers them,
// (2) the role set the posture audit stored in project Storage (see CONFIG.postureAudit), each member
// re-confirmed with hasRole(), (3) otherwise the answer is "not readable". Compound style: admin().
// Returns { source, list: [{ addr, c }], risk, text }. risk: multisig | mixed | single-key | none | unreadable.
// One compromised proposer is enough to queue a call (every OZ proposer can schedule alone), so a single
// key among the proposers is what counts; the delay then only gives notice, not a second signature.
async function readProposers(ctx, a, tl) {
  const NOT_READABLE = 'proposers not readable, add the timelock to the posture audit';
  const finish = async (source, addrs, extra = {}) => {
    const list = await Promise.all(addrs.map(async (m) => ({ addr: m, c: await classify(ctx, m, true, false) })));
    const single = list.filter((x) => x.c.singleKey === true).length;
    const known = list.filter((x) => x.c.cls !== 'unknown').length;
    const risk = !list.length ? (extra.empty ? 'none' : 'unreadable') : single === list.length ? 'single-key' : single > 0 ? 'mixed' : known < list.length ? 'unreadable' : 'multisig';
    const label = (x) => `${kindLabel(x.c)} ${short(x.addr)}`;
    let text;
    if (!list.length) text = extra.none || NOT_READABLE;
    else {
      const names = list.length <= 4 ? list.map(label).join(', ') : Object.entries(list.reduce((o, x) => ((o[kindLabel(x.c)] = (o[kindLabel(x.c)] || 0) + 1), o), {})).map(([k, v]) => `${v} ${k}`).join(', ');
      text = `proposers${extra.count > list.length ? ` (${list.length} of ${extra.count} shown)` : ''}: ${names}`;
      if (risk === 'single-key') text += '; every proposer is a single key, so the delay is only notice';
      else if (risk === 'mixed') text += `; ${single} of ${list.length} proposers ${single === 1 ? 'is a single key' : 'are single keys'}, any one of them can queue a call`;
    }
    return { source, list, risk, text, note: extra.note || null, count: extra.count ?? list.length };
  };
  if (tl.flavor === 'Compound Timelock') {
    if (!tl.admin || tl.admin === ZERO) return { source: 'admin()', list: [], risk: 'unreadable', text: 'no admin set: nobody can queue a call', count: 0 };
    const r = await finish('admin()', [tl.admin]);
    r.text = r.text.replace(/^proposers/, 'proposer (admin)');
    return r;
  }
  const role = strip(PROPOSER_ROLE_ID);
  // (1) the timelock itself
  const [cnt] = await callMany(ctx, [[a, SEL.getRoleMemberCount + role]]);
  const n = asUint(cnt);
  if (n !== null && n <= 1000n) {
    const take = Math.min(Number(n), 12);
    const members = (await callMany(ctx, [...Array(take).keys()].map((k) => [a, SEL.getRoleMember + role + k.toString(16).padStart(64, '0')]))).map(asAddr).filter(Boolean);
    return finish('getRoleMember', members, { count: Number(n), empty: n === 0n, none: n === 0n ? 'no proposers: nobody can queue a call' : null });
  }
  // (2) the posture audit's stored role set
  const st = await storedProposers(ctx, a);
  if (st && st.members) {
    const calls = st.members.map((m) => [a, SEL.hasRole + role + strip(m).padStart(64, '0')]);
    const res = calls.length ? await callMany(ctx, calls) : [];
    const keep = st.members.filter((m, i) => res[i] === null || asUint(res[i]) !== 0n); // true, or not answered
    const confirmed = res.filter((x) => x !== null && asUint(x) !== 0n).length;
    const gone = res.filter((x) => x !== null && asUint(x) === 0n).length;
    const unanswered = st.members.length - confirmed - gone;
    // `at` is when the audit last WROTE this state: a state that did not change is rewritten only about every 10 minutes (the audit's stateHeartbeatS), so this is an upper bound on the age of the read, not the time of the last run.
    const age = st.at ? `${Math.max(0, Math.round((Date.now() / 1000 - st.at) / 60))} min ago` : 'at an unknown time';
    const note = `proposers from the posture audit (stored state written ${age}; an unchanged state is rewritten about every 10 min while the audit runs); hasRole confirms ${confirmed} of ${st.members.length} stored members${gone ? `, ${gone} no longer ${gone === 1 ? 'holds' : 'hold'} the role` : ''}${unanswered ? `, ${unanswered} could not be checked` : ''}; a proposer added since is not in the list`;
    return finish('posture audit', keep, { note, empty: true, none: 'no proposers found by the posture audit: nobody can queue a call' });
  }
  return { source: 'none', list: [], risk: 'unreadable', text: NOT_READABLE, note: st && st.why ? st.why : null, count: 0 };
}

// The posture audit's stored state of a timelock: { members, at } or { why } or null (no key).
function postureKey(net, a) {
  const pa = CONFIG.postureAudit || {};
  const prefix = pa.storagePrefix || `privPosture:v1:${net}:${pa.deploymentName}`;
  return `${prefix}:t:${a}`;
}
async function storedProposers(ctx, a) {
  const pa = CONFIG.postureAudit || {};
  if (!ctx.context || !(pa.storagePrefix || pa.deploymentName)) return null;
  let raw;
  try {
    raw = await ctx.context.storage.getStr(postureKey(ctx.net, a));
  } catch (e) {
    return { why: `posture audit state could not be read (${errMsg(e)})` };
  }
  if (!raw) return null;
  let st;
  try {
    st = JSON.parse(raw);
  } catch (e) {
    return { why: 'posture audit state is not valid JSON' };
  }
  const role = st && st.roles && st.roles[`role:${PROPOSER_ROLE_ID}`];
  if (!st.baselined) return { why: 'the posture audit has not finished its baseline of this timelock yet' };
  if (!role || !Array.isArray(role.a)) return { why: 'the posture audit tracks this timelock but not PROPOSER_ROLE (add roles: ["PROPOSER_ROLE"] to its target)' };
  return { members: role.a.filter(isAddr).map(lc).slice(0, 12), at: Number(st.at) || null };
}

async function signerSummary(ctx, owners) {
  const list = owners.slice(0, 12);
  const codes = await rpcBatch(ctx, list.map((o) => ({ method: 'eth_getCode', params: [o, 'latest'] }))).catch(() => null);
  if (!codes) return null;
  const n = { EOA: 0, 'EIP-7702': 0, Safe: 0, contract: 0, unknown: 0 };
  const contracts = [];
  codes.forEach((c, i) => {
    if (typeof c !== 'string') n.unknown++;
    else if (!strip(c)) n.EOA++;
    else if (strip(c).startsWith('ef0100') && strip(c).length === 46) n['EIP-7702']++;
    else contracts.push(list[i]);
  });
  const cls = await Promise.all(contracts.map((c) => classify(ctx, c, false)));
  for (const c of cls) n[c.cls === 'safe' ? 'Safe' : 'contract']++;
  const s = Object.entries(n).filter(([, v]) => v).map(([k, v]) => `${v} ${k}`).join(', ');
  return owners.length > list.length ? `${s}, ${owners.length - list.length} not checked` : s;
}

// ---------------------------------------------------------------------------- notice
// 1. Announcements. changeRegistry.js stores a change announced IN ADVANCE together with
// the announcer's EIP-191 signature. The guard re-verifies the signature of every match
// (a forged storage row does not count), accepts only CONFIG.announcers, and uses each
// announcement once. The message format is shared with changeRegistry.js.
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

async function loadRegistry(context) {
  const out = { items: [], consumed: new Set() };
  try {
    const v = await context.storage.getJson(CONFIG.storage.registryKey);
    if (v && v.v === 2 && Array.isArray(v.items)) out.items = v.items;
  } catch (e) {
    console.error(`registry read failed: ${errMsg(e)}`);
  }
  try {
    const c = await context.storage.getJson(CONFIG.storage.consumedKey);
    if (c && Array.isArray(c.items)) out.consumed = new Set(c.items.map((x) => x.id));
  } catch (e) {
    console.error(`consumed read failed: ${errMsg(e)}`);
  }
  return out;
}

const kindMatches = (ak, fk) => ak === 'any' || ak === fk || (ak === 'owner' && fk === 'pending-owner') || (ak === 'proxy' && fk === 'proxy-admin');

function announcementValid(a) {
  const eth = getEthers();
  const allowed = (CONFIG.announcers || []).map(lc);
  if (!eth || !allowed.length || !a.sig) return false;
  try {
    return allowed.includes(lc(eth.utils.verifyMessage(announcementMessage(a), a.sig)));
  } catch (e) {
    return false;
  }
}

function registryMatch(reg, f, net) {
  const now = Math.floor(Date.now() / 1000);
  return reg.items.find(
    (a) =>
      !reg.consumed.has(a.id) &&
      String(a.network || net) === net &&
      lc(a.contract) === f.contract &&
      kindMatches(a.kind, f.kind) &&
      (!a.role || (f.role && (f.role.id ? lc(a.role) === lc(f.role.id) : a.role === `@${f.role.name}`))) &&
      (!a.holder || lc(a.holder) === lc(f.who)) &&
      (a.value === undefined || a.value === null || (f.val !== null && f.val !== undefined && String(a.value) === String(f.val))) &&
      (a.holder || (a.value !== undefined && a.value !== null)) &&
      now >= Number(a.validFrom || 0) &&
      now <= Number(a.validUntil || 0) &&
      announcementValid(a)
  );
}

// 2. Trusted timelock executions. A timelock execution in the same transaction is not
// notice for everything else in it. A governance log is covered only when
//   - it lies inside that execution (OZ TimelockController and Compound emit their exec
//     log AFTER the call, AccessManager BEFORE it: between two exec logs of the same timelock),
//   - whoever made the call is the timelock or the call's target (the sender in the log),
//     or the executed target is the changed contract or its owner, authority or proxy admin,
//   - the executed calldata names the new holder or value (OZ and Compound only).
// Nothing links: no notice.
function execInfo(logs, table) {
  const out = [];
  logs.forEach((l, i) => {
    const t0 = lc((l.topics || [])[0]);
    const name = table.T_EXEC[t0];
    if (!name) return;
    const d = decodeLog(l, table.EV.get(t0));
    out.push({ i, tl: lc(l.address), name, target: d.target || null, calldata: name === 'OperationExecuted' ? null : dynBytes(l, 2) });
  });
  return out;
}

// owner(), authority() and the proxy admin of a contract: who may call its admin functions
// ({ set: all of them, admin: the EIP-1967 or zos admin }).
async function controllersOf(ctx, c) {
  if (ctx.ctl.has(c)) return ctx.ctl.get(c);
  const p = (async () => {
    const res = await rpcBatch(ctx, [
      { method: 'eth_call', params: [{ to: c, data: SEL.owner }, 'latest'] },
      { method: 'eth_call', params: [{ to: c, data: SEL.authority }, 'latest'] },
      { method: 'eth_getStorageAt', params: [c, SLOT_ADMIN, 'latest'] },
      { method: 'eth_getStorageAt', params: [c, SLOT_ZOS_ADMIN, 'latest'] },
    ]).catch(() => []);
    const set = new Set();
    let admin = null;
    for (const r of res.slice(0, 2)) {
      const a = r instanceof Error || !r ? null : asAddr(r);
      if (a && a !== ZERO) set.add(a);
    }
    for (const r of res.slice(2)) {
      if (typeof r === 'string' && /^0x0{24}[0-9a-f]{40}$/i.test(r) && !/^0x0+$/.test(r)) {
        admin = admin || '0x' + r.slice(26).toLowerCase();
        set.add('0x' + r.slice(26).toLowerCase());
      }
    }
    return { set, admin };
  })();
  ctx.ctl.set(c, p);
  return p;
}

async function timelockDelay(ctx, t) {
  if (ctx.delays.has(t)) return ctx.delays.get(t);
  const p = callMany(ctx, [[t, SEL.getMinDelay], [t, SEL.delay]]).then(([md, dl]) => asUint(md) ?? asUint(dl)).catch(() => null);
  ctx.delays.set(t, p);
  return p;
}

// Does the executed calldata name the new holder (or the new value)?
function mentionsChange(calldata, f, tl) {
  if (calldata === null || calldata === undefined) return true;
  if (f.who === tl) return true; // the timelock itself became the holder (for example acceptOwnership)
  const want = [];
  if (f.who && f.who !== ZERO && isAddr(f.who)) want.push(strip(f.who).padStart(64, '0'));
  else if (typeof f.val === 'bigint') want.push(f.val.toString(16).padStart(64, '0'));
  return !want.length || want.some((w) => calldata.includes(w));
}

async function timelockNotice(ctx, f, execs) {
  if (!execs.length) return null;
  const trusted = new Set(CONFIG.trustedTimelocks.map(lc));
  const why = [];
  let linkedElsewhere = false;
  for (const e of execs) {
    const label = labelOf(e.tl);
    if (!trusted.has(e.tl)) {
      why.push(`executed by ${label ? label + ' ' : ''}${e.tl}, which is not in trustedTimelocks`);
      continue;
    }
    const same = execs.filter((x) => x.tl === e.tl);
    const after = e.name !== 'OperationExecuted';
    const prevI = Math.max(-1, ...same.filter((x) => x.i < e.i).map((x) => x.i));
    const nextI = Math.min(Infinity, ...same.filter((x) => x.i > e.i).map((x) => x.i));
    if (!(after ? f.i > prevI && f.i < e.i : f.i > e.i && f.i < nextI)) continue; // not inside this execution
    const actors = after ? [e.tl, e.target].filter(Boolean) : [e.tl];
    const ctl = (await controllersOf(ctx, f.contract)).set;
    const linked = f.by
      ? actors.includes(f.by)
      : actors.includes(f.contract) || actors.some((x) => ctl.has(x)) || (f.prev && actors.includes(f.prev)) || f.who === e.tl;
    if (!linked || (after && !mentionsChange(e.calldata, f, e.tl))) {
      linkedElsewhere = true;
      continue;
    }
    if (after) {
      const d = await timelockDelay(ctx, e.tl);
      if (d === null) {
        why.push(`executed by trusted timelock ${e.tl} but its delay could not be read`);
        continue;
      }
      if (d < BigInt(CONFIG.minNoticeSeconds)) {
        why.push(`executed by trusted timelock ${e.tl} with delay ${fmtDur(d)}, below the ${fmtDur(CONFIG.minNoticeSeconds)} minimum`);
        continue;
      }
      return { ok: true, text: `executed by trusted timelock ${label ? label + ' ' : ''}${e.tl} (delay ${fmtDur(d)})` };
    }
    return { ok: true, text: `scheduled operation executed by trusted AccessManager ${label ? label + ' ' : ''}${e.tl}` };
  }
  if (!why.length && linkedElsewhere) why.push('a trusted timelock executed a call in this transaction, but it is not linked to this change');
  return { ok: false, text: why.join('; ') };
}

// ---------------------------------------------------------------------------- severity
function effectiveClass(f) {
  if (f.cls !== 'toggle') return f.cls;
  if (f.flag !== undefined && f.flag !== null) return f.flag ? 'grant' : 'revoke';
  if (f.roleType === 'bits') return f.role && BigInt(f.role.id) !== 0n ? 'grant' : 'revoke';
  return 'grant';
}

// Per-role policy: the contract's own map first, then routineRoles. null = the default rules.
function policyFor(f) {
  if (f.kind !== 'role' || !f.role) return null;
  const keys = [f.role.name, f.role.id && lc(f.role.id)].filter(Boolean);
  const c = contractCfg(f.contract);
  const pol = c && c.roles ? keys.map((k) => byAddr(c.roles, lc(k))).find(Boolean) : null;
  if (['critical', 'high', 'info', 'ignore'].includes(pol)) return pol;
  if (keys.some((k) => (CONFIG.routineRoles || []).map(lc).includes(lc(k)))) return 'info';
  return null;
}

function isPrivileged(f) {
  if (f.policy === 'critical' || f.policy === 'high') return true;
  if (f.policy === 'info') return false;
  if (f.kind === 'role') return f.role ? f.role.privileged : CONFIG.unknownRolesArePrivileged;
  return PRIV_KINDS.has(f.kind);
}

// Why an unannounced change that does not go to a single key is still high. The text names what the change or
// the holder is, so it never calls a plain contract (or an event with no holder) a multi-signature or timelock.
function unannouncedReason(f, H) {
  if (f.kind === 'proxy') return 'implementation change without prior notice';
  if (f.kind === 'safe') return 'Safe configuration changed without prior notice';
  if (!H) return f.kind === 'role-admin' ? 'role admin changed without prior notice' : 'privileged setting changed without prior notice';
  if (H.cls === 'safe' || H.cls === 'timelock') return 'privileged change without prior notice to a multi-signature or timelock holder';
  if (H.cls === 'contract') {
    if (H.owner && (H.ownerCls === 'safe' || H.ownerCls === 'timelock')) return 'privileged change without prior notice to a contract owned by a multi-signature or timelock holder';
    if (H.owner) return 'privileged change without prior notice to a contract that is not a Safe or timelock (owned by another contract, not followed further)';
    return 'privileged change without prior notice to a contract that is not a Safe or timelock (no owner() to follow, so who controls it is not known)';
  }
  return 'privileged change without prior notice';
}

function score(f) {
  const r = [];
  const cls = f.ecls;
  const H = f.holder;
  const safe = f.safeState;
  if (f.initial) return { sev: 'info', reasons: ['initial assignment (contract deployment or initialize)'] };
  if (cls === 'notice') return { sev: 'info', reasons: ['change scheduled in advance (this is the notice)'] };
  if (cls === 'state') return { sev: 'high', reasons: [f.name.toLowerCase().includes('unpause') || f.flag === false ? 'contract unpaused' : 'contract paused or closed'] };
  if (cls === 'revoke') {
    if (f.kind === 'safe' && f.name === 'RemovedOwner' && safe && safe.threshold === 1) return { sev: 'critical', reasons: ['Safe owner removed and the Safe is now 1-of-N: one key moves it'] };
    if (H && (H.cls === 'safe' || H.cls === 'timelock')) {
      if (f.remaining && f.remaining.checked) {
        if (!f.remaining.strong) return { sev: 'critical', reasons: ['the last multi-signature Safe or timelock holder lost this power; only single keys (or nobody) hold it now'] };
        return { sev: CONFIG.revokeSeverity, reasons: ['a Safe or timelock lost this power; another multi-signature Safe or timelock still holds it'] };
      }
      return { sev: 'high', reasons: ['a Safe or timelock lost this power and no other Safe or timelock holder could be confirmed'] };
    }
    return { sev: CONFIG.revokeSeverity, reasons: ['power removed'] };
  }
  // grant, pending, param
  if (cls !== 'param' && f.who === ZERO && RENOUNCE_KINDS.has(f.kind)) {
    const p = f.prevHolder;
    if (p && (p.cls === 'safe' || p.cls === 'timelock')) return { sev: 'high', reasons: ['power renounced (set to 0x0) by a Safe or timelock holder: these functions are now disabled'] };
    return { sev: CONFIG.renounceSeverity, reasons: [f.kind === 'pending-owner' ? 'pending transfer cleared' : 'power renounced (set to 0x0): these functions are now disabled'] };
  }
  const strict = f.policy === 'critical' || (contractCfg(f.contract) || {}).strictUnannounced === true;
  let sev = null;
  // Structural risks: critical whatever the notice.
  if (f.kind === 'proxy') {
    if (f.who === ZERO || (H && (H.cls === 'eoa' || H.cls === 'eip7702'))) {
      sev = 'critical';
      r.push('new implementation has no contract code');
    } else if (f.name === 'ChangedMasterCopy') {
      // Publicly reported Safe takeovers (2024 and 2025) swapped the Safe singleton for an attacker contract.
      // A move to a canonical Safe implementation (a planned upgrade) is judged like any other change.
      const canon = byAddr(CONFIG.safe.singletons, lc(f.who));
      if (!canon) {
        sev = 'critical';
        r.push('the Safe singleton was changed to an address that is not a canonical Safe singleton (CONFIG.safe.singletons): the publicly reported singleton-swap takeover route');
      } else r.push(`the Safe singleton was changed to the canonical ${canon}`);
    }
  } else if (f.kind === 'safe') {
    if (f.name === 'ChangedThreshold' && f.val === 1n) {
      sev = 'critical';
      r.push('Safe threshold set to 1: one key moves it');
    } else if (f.name === 'AddedOwner' && safe && safe.threshold === 1) {
      sev = 'critical';
      r.push('owner added while the Safe stays 1-of-N');
    } else if ((f.name === 'EnabledModule' || f.name === 'ChangedModuleGuard') && H && H.singleKey) {
      sev = 'critical';
      r.push('module is controlled by a single key and can move funds without the other signers');
    } else if ((f.name === 'ChangedGuard' || f.name === 'ChangedModuleGuard') && f.who === ZERO) {
      sev = 'critical';
      r.push('Safe guard removed');
    }
  } else if (cls === 'param') {
    const min = BigInt(CONFIG.minNoticeSeconds);
    if (f.kind === 'timelock' && f.val !== null && f.val !== undefined && typeof f.val === 'bigint') {
      if (f.prevVal !== null && f.prevVal !== undefined && f.val < f.prevVal) {
        sev = 'critical';
        r.push('timelock delay lowered');
      } else if (f.val < min) {
        sev = 'critical';
        r.push(`delay below ${fmtDur(CONFIG.minNoticeSeconds)}`);
      }
    }
    if (f.kind === 'authority' && f.flag === true && /Public/.test(f.name)) {
      sev = 'critical';
      r.push('function opened to everyone');
    }
  }
  // An upgrade is exercised by the proxy admin: a single-key admin is critical unannounced, high announced.
  if (f.kind === 'proxy' && f.authority && f.authority.weak && !f.known && isPrivileged(f)) {
    const up = f.notice ? 'high' : 'critical';
    if (!sev || SEV[up] > SEV[sev]) sev = up;
    r.push(`the proxy is upgradeable by a single key: ${f.authority.desc}`);
  }
  // Everything else: how dangerous is the holder, and was the change announced?
  if (!sev) {
    if (!isPrivileged(f)) return { sev: 'info', reasons: [f.policy === 'info' ? 'routine role (configured), not a privileged change' : 'role is not marked privileged (CONFIG.privilegedRoles)'] };
    if (f.kind !== 'safe' && f.kind !== 'proxy' && H && H.weak && !f.known) {
      sev = 'critical';
      const who = { eoa: 'an EOA', eip7702: 'an EIP-7702 delegated EOA', safe: 'a Safe with threshold 1', contract: 'a contract owned by a single key' }[H.cls] || H.cls;
      r.push(H.singleKey ? `privileged power (${f.role ? f.role.label : f.kind}) given to a single key: ${who}` : 'privileged power given to a timelock with a short delay');
    } else if (H && H.cls === 'unknown' && !f.known) {
      sev = 'high'; // not proven weak, so not critical, but never quieter than high
      r.push(H.noRpc ? H.desc : 'the holder could not be classified (RPC unavailable): check it by hand');
    } else if (f.kind !== 'safe' && f.kind !== 'proxy' && H && H.cls === 'timelock' && (H.proposerRisk === 'single-key' || H.proposerRisk === 'mixed') && !f.known) {
      // A timelock keeps its delay as notice, but if a single key can propose on it the delay is the only
      // protection: never quieter than high, even when the change was announced. Not critical (the delay
      // still gives people time to react; a bare EOA owner would be critical). A critical-role policy
      // still makes an unannounced change critical.
      sev = strict && !f.notice ? 'critical' : 'high';
      const all = H.proposerRisk === 'single-key';
      r.push(`privileged power given to a timelock (delay ${fmtDur(H.delay)}) ${all ? 'whose proposers are all single keys' : 'with a single-key proposer among its proposers'}: the delay is notice, not a second signature${f.notice ? ' (the change was announced, but the proposer side is still one key)' : ''}`);
    } else if (f.notice) {
      sev = 'info';
      r.push({ registry: 'announced change (signed announcement), holder is not a single key', timelock: 'executed by a linked trusted timelock, holder is not a single key', known: 'change to a known holder (CONFIG.knownHolders)' }[f.noticeKind] || 'change with prior notice');
    } else {
      sev = strict ? 'critical' : 'high';
      r.push(strict ? 'unannounced change on a contract marked strictUnannounced or a critical role' : unannouncedReason(f, H));
    }
  }
  if (f.noRpc && !r.some((x) => x.includes('no RPC configured'))) r.push(`holder not classified: no RPC configured for chain ${f.net}`);
  if (!f.notice && SEV[sev] >= SEV.high) r.push('no prior notice (no matching signed announcement, not executed by a linked trusted timelock)');
  if (f.other && SEV[sev] > SEV.high) {
    sev = 'high';
    r.push('capped at high: emitted by a contract that is not listed in CONFIG.contracts');
  }
  return { sev, reasons: r };
}

// ---------------------------------------------------------------------------- auto-pause
// A pause rule fires on a grant, pending or param change of the watched contract. With
// unannouncedOnly (the default) an announced change does not pause, with two exceptions
// that announcements can never switch off: a single-key holder (EOA, 7702, 1-of-N, ...)
// still pauses, unless it is one of CONFIG.knownHolders.
function ruleMatches(rule, f, net) {
  if (!rule || !rule.pause || lc(rule.watch) !== f.contract) return false;
  if (String(rule.network === undefined || rule.network === null ? '143' : rule.network) !== String(net)) return false; // a rule acts on its own chain only
  // A critical Safe delegatecall (rule.watch = the Safe) pauses only when the rule asks for that kind.
  if (f.kind === 'safe-delegatecall') return !!(rule.kinds && rule.kinds.includes('safe-delegatecall')) && f.sev === 'critical';
  if (!['grant', 'pending', 'param'].includes(f.ecls) || f.initial) return false;
  if (rule.kinds && !rule.kinds.includes(f.kind)) return false;
  if (f.kind === 'role' && rule.roles && rule.roles.length && !(f.role && (rule.roles.includes(f.role.name) || rule.roles.map(lc).includes(lc(f.role.id))))) return false;
  if (rule.unannouncedOnly !== false && f.notice && (f.noticeKind === 'known' || !(f.holder && f.holder.singleKey))) return false;
  return true;
}

async function simulate(ctx, from, p) {
  const tx = { from, to: p.to, data: p.data, gas: '0x' + Number(p.gasLimit || 300000).toString(16) };
  try {
    await rpc(ctx, 'eth_call', [tx, 'latest']);
  } catch (e) {
    return { ok: false, reason: errMsg(e) + (e.data ? ` ${String(e.data).slice(0, 74)}` : '') };
  }
  const [gas, bal] = await rpcBatch(ctx, [{ method: 'eth_estimateGas', params: [tx] }, { method: 'eth_getBalance', params: [from, 'latest'] }]).catch(() => []);
  return { ok: true, gas: typeof gas === 'string' ? Number(BigInt(gas)) : null, balance: typeof bal === 'string' ? BigInt(bal) : null };
}

// The guardian key from Secrets, checked before it goes anywhere near a library: a
// malformed value must never reach ethers, whose error text would echo it.
async function loadGuardianKey(context, name) {
  let raw;
  try {
    raw = await context.secrets.get(name);
  } catch (e) {
    return { err: `secret ${name} missing` };
  }
  const k = String(raw || '').trim();
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(k)) return { err: `secret ${name} is not a 32-byte hex private key (check for quotes or extra characters)` };
  return { key: k.startsWith('0x') ? k : '0x' + k };
}

// Broadcast the stored raw transaction again (same nonce: it can never pause twice) and look for a receipt.
async function resendPause(ctx, item) {
  let sendErr = null;
  try {
    await rpc(ctx, 'eth_sendRawTransaction', [item.raw]);
  } catch (e) {
    sendErr = e;
  }
  const rc = await rpc(ctx, 'eth_getTransactionReceipt', [item.hash]).catch(() => null);
  if (rc) {
    item.status = rc.status === '0x1' ? 'confirmed' : 'reverted';
    item.raw = null;
    return `LIVE: pause tx ${item.hash} ${item.status === 'confirmed' ? `confirmed in block ${Number(BigInt(rc.blockNumber))}` : 'REVERTED on chain'}`;
  }
  return `LIVE: pause tx ${item.hash} broadcast again, no receipt yet${sendErr ? ` (${errMsg(sendErr)})` : ''}`;
}

async function runAutoPause(context, ctx, findings) {
  const ap = CONFIG.autoPause;
  if (!ap || ap.mode === 'off' || !Array.isArray(ap.rules) || !ap.rules.length) return;
  const groups = new Map();
  for (const f of findings) {
    for (const rule of ap.rules) {
      if (!ruleMatches(rule, f, ctx.net)) continue;
      const k = `${lc(rule.pause.to)}:${strip(rule.pause.data).slice(0, 8)}`;
      if (!groups.has(k)) groups.set(k, { rule, fs: [] });
      groups.get(k).fs.push(f);
    }
  }
  if (!groups.size) return;
  if (ctx.noRpc) {
    // No RPC for this chain: nothing can be simulated, signed or sent. Say so, never guess.
    for (const { fs } of groups.values()) {
      fs[0].autoPause = `skipped: no RPC configured for chain ${ctx.net}, nothing sent`;
      for (const f of fs.slice(1)) f.autoPause = 'see above';
    }
    console.log(`autopause skipped: no RPC configured for chain ${ctx.net}`);
    return;
  }
  let store = { v: 1, items: [] };
  try {
    const v = await context.storage.getJson(CONFIG.storage.pauseKey);
    if (v && Array.isArray(v.items)) store = v;
  } catch (e) {}
  const save = () => context.storage.putJson(CONFIG.storage.pauseKey, { v: 1, items: store.items.slice(-50) });
  for (const [k, { rule, fs }] of groups) {
    const p = rule.pause;
    const label = p.label || `${short(p.to)} ${strip(p.data).slice(0, 8)}`;
    const id = `${ctx.net}:${ctx.hash}:${k}`;
    const say = (t) => {
      fs[0].autoPause = t;
      for (const f of fs.slice(1)) f.autoPause = 'see above';
      console.log(`autopause mode=${ap.mode} target=${p.to} result="${t}"`);
    };
    try {
      const done = store.items.find((x) => x.id === id);
      if (done) {
        if (ap.mode === 'live' && done.raw && done.status !== 'confirmed') {
          say(await resendPause(ctx, done));
          await save();
        } else say('already handled for this transaction (duplicate delivery), nothing sent');
        continue;
      }
      if (rule.pausedCheck) {
        const [pc] = await callMany(ctx, [[rule.pausedCheck.to, rule.pausedCheck.data]]);
        if (pc && asUint(pc) !== 0n) {
          say(`${label}: target already paused, nothing sent`);
          continue;
        }
      }
      const guardian = lc(ap.guardian);
      if (ap.mode === 'dry-run') {
        if (!isAddr(guardian)) {
          say(`DRY RUN: would call ${label} on ${p.to}; set autoPause.guardian to simulate it`);
          continue;
        }
        const sim = await simulate(ctx, guardian, p);
        say(
          sim.ok
            ? `DRY RUN: would call ${label} on ${p.to}; simulation from guardian ${guardian} succeeded${sim.gas ? `, estimateGas ${sim.gas}` : ''}${sim.balance !== null ? `, guardian balance ${fmtNative(sim.balance, ctx.net)}` : ''}`
            : `DRY RUN: ${label} simulation from guardian ${guardian} REVERTED (${sim.reason}); the guardian could not pause`
        );
        continue;
      }
      if (ap.mode !== 'live') continue;
      const loaded = await loadGuardianKey(context, ap.keySecret);
      if (loaded.err) {
        say(`LIVE: ${loaded.err}, nothing sent`);
        continue;
      }
      const ethers = getEthers(); // ethers v5, see getEthers()
      if (!ethers) {
        say('LIVE: ethers is not available, nothing sent');
        continue;
      }
      let wallet;
      try {
        wallet = new ethers.Wallet(loaded.key);
      } catch (e) {
        say('LIVE: ethers rejected the guardian key, nothing sent'); // never print e.message here
        continue;
      }
      loaded.key = null;
      if (isAddr(guardian) && lc(wallet.address) !== guardian) {
        say(`LIVE: key address ${wallet.address} is not the configured guardian, nothing sent`);
        continue;
      }
      const sim = await simulate(ctx, lc(wallet.address), p);
      if (!sim.ok) {
        say(`LIVE: ${label} not sent, simulation reverted (${sim.reason})`);
        continue;
      }
      const [nonce, block, tip, bal] = await rpcBatch(ctx, [
        { method: 'eth_getTransactionCount', params: [wallet.address, 'latest'] }, // 'pending' behaves as 'latest' on Monad
        { method: 'eth_getBlockByNumber', params: ['latest', false] },
        { method: 'eth_maxPriorityFeePerGas', params: [] },
        { method: 'eth_getBalance', params: [wallet.address, 'latest'] },
      ]);
      if (nonce instanceof Error || block instanceof Error) throw nonce instanceof Error ? nonce : block;
      const base = BigInt(block.baseFeePerGas || '0x0');
      const prio = tip instanceof Error || !tip ? 2n * 10n ** 9n : BigInt(tip);
      const maxFee = base * 2n + prio;
      if (maxFee > BigInt(ap.maxFeeGwei) * 10n ** 9n) {
        say(`LIVE: max fee ${maxFee / 10n ** 9n} gwei above autoPause.maxFeeGwei, nothing sent`);
        continue;
      }
      const gasLimit = BigInt(p.gasLimit || 300000);
      if (typeof bal === 'string' && BigInt(bal) < gasLimit * maxFee) {
        // Monad charges the gas limit, and may accept an underfunded transaction without rejecting it.
        say(`LIVE: guardian balance ${fmtNative(bal, ctx.net)} is below the maximum cost ${fmtNative(gasLimit * maxFee, ctx.net)}, nothing sent`);
        continue;
      }
      let n = Number(BigInt(nonce));
      if (ctx.lastNonce !== undefined && n <= ctx.lastNonce) n = ctx.lastNonce + 1; // two pauses in one run
      ctx.lastNonce = n;
      const raw = await wallet.signTransaction({
        type: 2, chainId: Number(ctx.net), nonce: n, to: p.to, data: p.data, value: 0,
        gasLimit: Number(gasLimit), maxFeePerGas: maxFee, maxPriorityFeePerGas: prio,
      });
      // Record the signed transaction BEFORE broadcasting: a redelivered alert broadcasts the same raw
      // transaction again (same nonce) and can never send a second pause.
      const item = { id, at: Math.floor(Date.now() / 1000), mode: 'live', raw, hash: ethers.utils.keccak256(raw), status: 'signed' };
      store.items.push(item);
      await save();
      try {
        await rpc(ctx, 'eth_sendRawTransaction', [raw]);
      } catch (e) {
        if (!/already known|known transaction|nonce too low/i.test(errMsg(e))) throw e;
      }
      item.status = 'sent';
      let status = 'sent, receipt not seen yet';
      for (let i = 0; i < 12 && Date.now() < ctx.deadline + 4000; i++) {
        const rc = await rpc(ctx, 'eth_getTransactionReceipt', [item.hash]).catch(() => null);
        if (rc) {
          item.status = rc.status === '0x1' ? 'confirmed' : 'reverted';
          item.raw = null;
          status = rc.status === '0x1' ? `confirmed in block ${Number(BigInt(rc.blockNumber))}` : 'REVERTED on chain';
          break;
        }
        await new Promise((res) => setTimeout(res, 500));
      }
      await save();
      say(`LIVE: ${label} sent by guardian ${wallet.address}, tx ${item.hash}, ${status}`);
    } catch (e) {
      say(`${ap.mode.toUpperCase()}: ${label} failed (${errMsg(e)})`);
    }
  }
}

// ---------------------------------------------------------------------------- render
const TITLES = {
  owner: 'Owner changed', 'pending-owner': 'Ownership transfer started (pending acceptance)', role: 'Role granted',
  'role-admin': 'Role admin changed', authority: 'Authority changed', ward: 'Ward added (rely)', proxy: 'Implementation changed',
  'proxy-admin': 'Proxy admin changed', safe: 'Safe configuration changed', timelock: 'Timelock changed', minter: 'Minter changed',
  pause: 'Pauser changed',
};
// Clearer titles for events whose kind alone is vague.
const TITLE_BY_EVENT = {
  AssetSourceUpdated: 'Oracle price source changed', PriceOracleUpdated: 'Price oracle changed', PriceOracleSentinelUpdated: 'Oracle sentinel changed',
  PoolUpdated: 'Pool implementation changed', PoolConfiguratorUpdated: 'Pool configurator implementation changed', ACLManagerUpdated: 'ACL manager changed',
  ACLAdminUpdated: 'ACL admin changed', AddressSet: 'Address registry entry changed', AddressSetAsProxy: 'Address registry proxy implementation changed',
  PoolDataProviderUpdated: 'Pool data provider changed', ChangedMasterCopy: 'Safe singleton (implementation) changed', GovSetGovernorAdmin: 'Vault governor changed',
  GovernorSet: 'Governor changed', PeerSet: 'Bridge peer changed', LogPermit: 'Permission granted (DSGuard)', LogForbid: 'Permission removed (DSGuard)',
  DiamondCut: 'Diamond facets changed', EnabledModule: 'Safe module enabled', DisabledModule: 'Safe module disabled', ChangedGuard: 'Safe guard changed',
  ChangedFallbackHandler: 'Safe fallback handler changed', ChangedModuleGuard: 'Safe module guard changed', AddedOwner: 'Safe signer added',
  RemovedOwner: 'Safe signer removed', MasterMinterChanged: 'Master minter changed', TargetFunctionRoleUpdated: 'Function role changed',
  TargetCustomAuthorityUpdated: 'Custom authority changed',
};
function title(f) {
  if (f.title) return f.title;
  if (TITLE_BY_EVENT[f.name]) return TITLE_BY_EVENT[f.name];
  if (f.ecls === 'revoke') return f.kind === 'ward' ? 'Ward removed (deny)' : f.kind === 'safe' ? 'Safe configuration changed' : f.kind === 'minter' ? 'Minter removed' : 'Role revoked';
  if (f.ecls === 'state') return 'Pause state changed';
  if (f.ecls === 'notice') return 'Change scheduled';
  if (f.ecls === 'param') return f.kind === 'safe' ? 'Safe threshold changed' : f.kind === 'timelock' ? 'Delay changed' : 'Permission setting changed';
  if (f.ecls === 'pending') return 'Transfer started (pending acceptance)';
  return TITLES[f.kind] || 'Privileged change';
}

function renderFinding(f, net) {
  // Links when the chain has an explorer in CONFIG.networks, the full address otherwise.
  const al = (a) => {
    if (!isAddr(a)) return esc(a);
    const u = explorerAddr(net, a);
    return `${u ? `<${u}|${short(a)}>` : a}${labelOf(a) ? ` ${esc(labelOf(a))}` : ''}`;
  };
  const icon = f.sev === 'critical' ? ':rotating_light:' : f.sev === 'high' ? ':warning:' : ':information_source:';
  if (f.kind === 'safe-delegatecall') return renderDelegatecall(f, al, icon);
  const head = `${icon} *${f.sev.toUpperCase()}* ${esc(title(f))}${f.role ? `: ${esc(f.role.label)}` : ''} (${esc(f.name)}) on ${al(f.contract)}`;
  const L = [head];
  const verbs = { revoke: 'removed', pending: 'pending', grant: 'new', param: 'new' };
  if (f.who !== undefined && f.who !== null) L.push(`> ${verbs[f.ecls] || 'account'}: ${al(f.who)} ${f.holder ? esc(f.holder.desc) : ''}`);
  if (f.prev) L.push(`> previous owner or caller: ${al(f.prev)}${f.prevHolder ? ` ${esc(f.prevHolder.desc)}` : ''}`);
  if (f.val !== undefined && f.val !== null) L.push(`> value: ${f.kind === 'timelock' ? fmtDur(f.val) : String(f.val)}${f.prevVal !== undefined && f.prevVal !== null ? ` (was ${f.kind === 'timelock' ? fmtDur(f.prevVal) : String(f.prevVal)})` : ''}`);
  if (f.delay !== undefined && f.delay !== null) L.push(`> delay: ${fmtDur(f.delay)}`);
  if (f.at) L.push(`> effective at: ${new Date(Number(f.at) * 1000).toISOString()}`);
  if (f.target) L.push(`> target: ${al(f.target)}${f.sel ? ` selector ${f.sel}` : ''}`);
  else if (f.sel) L.push(`> selector: ${f.sel}`);
  if (f.by) L.push(`> by: ${al(f.by)}`);
  if (f.safeState && !f.safeState.noRpc) L.push(`> Safe now: ${esc(f.safeState.desc)}`);
  if (f.remaining && f.remaining.text) L.push(`> remaining holders: ${esc(f.remaining.text)}`);
  if (['grant', 'pending', 'param'].includes(f.ecls) && !f.initial) L.push(`> prior notice: ${f.notice ? esc(f.notice) : 'NONE'}`);
  for (const n of f.notes) L.push(`> note: ${esc(n)}`);
  L.push(`> why ${f.sev}: ${esc(f.reasons.join('; '))}`);
  if (f.autoPause) L.push(`> auto-pause: ${esc(f.autoPause)}`);
  return L.join('\n');
}

// One line for the Slack message of a Safe delegatecall finding (see safeDelegatecall()).
function renderDelegatecall(f, al, icon) {
  const L = [`${icon} *${f.sev.toUpperCase()}* ${esc(f.title)} on ${al(f.contract)}`];
  if (f.target) L.push(`> delegatecall target: ${al(f.target)}${f.targetDesc ? ` ${esc(f.targetDesc)}` : ''}`);
  if (f.inner) L.push(`> inside a MultiSend call: transaction ${f.inner.index + 1} of ${f.inner.total}`);
  if (f.safeState && !f.safeState.noRpc) L.push(`> Safe: ${esc(f.safeState.desc)}`);
  L.push(`> seen through: ${esc(f.via)}`);
  for (const n of f.notes) L.push(`> note: ${esc(n)}`);
  L.push(`> why ${f.sev}: ${esc(f.reasons.join('; '))}`);
  if (f.autoPause) L.push(`> auto-pause: ${esc(f.autoPause)}`);
  return L.join('\n');
}

function renderMessage(findings, ctx) {
  const count = (s) => findings.filter((f) => f.sev === s).length;
  const head = `*${netName(ctx.net)} privileged change* (${findings.length} finding${findings.length > 1 ? 's' : ''}: ${count('critical')} critical, ${count('high')} high, ${count('info')} info) <${tenderlyTx(ctx.net, ctx.hash)}|tx ${short(ctx.hash)}>${ctx.block ? ` block ${ctx.block}` : ''}`;
  const parts = [head];
  let used = head.length;
  let cut = 0;
  for (const f of findings) {
    const t = renderFinding(f, ctx.net);
    if (used + t.length + 2 > CONFIG.slack.maxChars) {
      cut++;
      continue;
    }
    parts.push(t);
    used += t.length + 2;
  }
  if (cut) parts.push(`_${cut} more finding(s) not shown, see the action execution log_`);
  return { text: parts.join('\n\n') };
}

async function postSlack(context, text) {
  let url;
  try {
    url = await context.secrets.get(CONFIG.slack.secret);
  } catch (e) {
    return 'no-secret';
  }
  const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text }), signal: AbortSignal.timeout(8000) });
  const body = await r.text();
  if (r.status !== 200) throw new Error(`slack HTTP ${r.status} ${body.slice(0, 80)}`);
  return 'sent';
}

// ---------------------------------------------------------------------------- Safe delegatecall
// Publicly reported Safe takeovers (2024 and 2025) were a Safe execTransaction with operation 1
// (DELEGATECALL) to an attacker contract that overwrote the singleton pointer in storage slot 0: no
// owner, threshold or module event.
// Normal Safes delegatecall the canonical libraries (MultiSend) all the time, so those are excluded
// (CONFIG.safe.libraries). The optional alert (alerts/optional/safe-delegatecall-non-library.json, a
// Function Call alert with parameter conditions) needs the call decoded with the Safe ABI; this code
// reads the transaction input itself as a second path.
//
// execTransaction(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures)
function decodeExec(input) {
  const h = strip(input);
  if (!h.startsWith(strip(SEL_EXEC_TRANSACTION))) return null;
  const args = h.slice(8);
  const w = words('0x' + args);
  if (w.length < 10 || !/^0{24}/.test(w[0])) return null;
  const op = BigInt('0x' + w[3]);
  if (op > 1n) return null; // operation is 0 (CALL) or 1 (DELEGATECALL)
  let data = '';
  try {
    const off = Number(BigInt('0x' + w[2])) * 2;
    const len = Number(BigInt('0x' + args.slice(off, off + 64)));
    if (off >= 0 && len >= 0 && off + 64 + len * 2 <= args.length) data = args.slice(off + 64, off + 64 + len * 2);
  } catch (e) {
    data = '';
  }
  return { to: '0x' + w[0].slice(24), value: BigInt('0x' + w[1]), operation: Number(op), data };
}

// multiSend(bytes transactions): packed operation (1) | to (20) | value (32) | data length (32) | data.
function decodeMultiSend(data) {
  const h = strip(data);
  if (!h.startsWith(strip(SEL_MULTISEND))) return null;
  const args = h.slice(8);
  if (args.length < 128) return null;
  try {
    const off = Number(BigInt('0x' + args.slice(0, 64))) * 2;
    if (off !== 64) return null; // the one bytes argument sits right after its offset word
    const len = Number(BigInt('0x' + args.slice(off, off + 64)));
    const packed = args.slice(off + 64, off + 64 + len * 2);
    if (packed.length !== len * 2) return null;
    const out = [];
    for (let i = 0; i < packed.length && out.length < 200; ) {
      if (i + 2 * 85 > packed.length) return null;
      const dlen = Number(BigInt('0x' + packed.slice(i + 2 + 40 + 64, i + 2 + 40 + 128)));
      out.push({ op: Number(BigInt('0x' + packed.slice(i, i + 2))), to: '0x' + packed.slice(i + 2, i + 42) });
      i += 2 + 40 + 64 + 64 + dlen * 2;
    }
    return out;
  } catch (e) {
    return null;
  }
}

// Findings for a Safe delegatecall. Two ways to see one:
//   1. the transaction input is execTransaction on a Safe with operation 1: decode `to` and `operation`;
//      a target outside CONFIG.safe.libraries is critical, and a MultiSend is opened to look for a nested one;
//   2. the delivery came from the delegatecall alert (CONFIG.safe.delegatecallAlertIds) but nothing could be
//      read from the input (the Safe is called from another contract): high, inspect the trace.
async function safeDelegatecall(ctx, event, txTo) {
  const cfg = CONFIG.safe || {};
  const alertHit = (cfg.delegatecallAlertIds || []).map(String).includes(String((event && event.alertId) || ''));
  const input = event && typeof event.input === 'string' ? event.input : '';
  let ex = isAddr(txTo) && lc(input).startsWith(SEL_EXEC_TRANSACTION) ? decodeExec(input) : null;
  if (!ex && !alertHit) return [];
  let safeState = null;
  if (ex && ex.operation === 1) {
    // Only a delegatecall needs the check that the called contract is a Safe (a plain call costs no RPC here).
    safeState = await classify(ctx, txTo, true);
    if (safeState.cls !== 'safe' && safeState.cls !== 'unknown') ex = null; // an execTransaction look-alike on another kind of contract
  }
  const mk = (sev, titleText, reasons, extra = {}) => ({
    id: `${ctx.net}:${ctx.hash.slice(2, 18)}:dc${extra.inner ? extra.inner.index : ''}`, i: -1, contract: lc(txTo || ''), name: 'SafeDelegatecall', family: 'Safe',
    kind: 'safe-delegatecall', cls: 'alert', ecls: 'alert', notes: [], noRpc: ctx.noRpc, net: ctx.net, sev, title: titleText, reasons, safeState, ...extra,
  });
  const NON_LIBRARY = 'Safe delegatecall to a non-library target (the singleton-swap route)';
  const describe = async (target) => {
    if (ctx.noRpc) return '(no RPC configured, code not read)';
    const code = await rpc(ctx, 'eth_getCode', [target, 'latest']).catch(() => null);
    if (typeof code !== 'string') return '(code could not be read)';
    return strip(code) ? `contract (${strip(code).length / 2} bytes)` : 'no code (an address without a contract)';
  };
  const out = [];
  if (ex && ex.operation === 1) {
    const target = lc(ex.to);
    const lib = byAddr(cfg.libraries, target);
    const unverified = safeState.cls === 'unknown' ? 'could not verify that the called contract is a Safe, it has the execTransaction layout' : null;
    if (!lib) {
      const f = mk('critical', NON_LIBRARY, ['execTransaction with operation 1 (DELEGATECALL) to a contract that is not one of the canonical Safe libraries (CONFIG.safe.libraries); it runs with the Safe\'s own storage and can overwrite the singleton pointer, owners or modules without emitting an event'], {
        target, targetDesc: await describe(target), via: 'the transaction input (execTransaction decoded)',
      });
      if (unverified) f.notes.push(unverified);
      const helper = byAddr(cfg.migrationHelpers, target);
      if (helper) f.notes.push(`the target is Safe's own helper ${helper}: if this upgrade was planned the singleton now points at a canonical implementation (see ChangedMasterCopy), if not treat it as a takeover`);
      out.push(f);
    } else if (cfg.inspectMultiSend !== false && /^MultiSend \d/.test(lib)) {
      const inner = decodeMultiSend(ex.data);
      if (inner) {
        for (let k = 0; k < inner.length; k++) {
          if (inner[k].op !== 1 || byAddr(cfg.libraries, inner[k].to)) continue;
          const f = mk('critical', `${NON_LIBRARY}, nested in a MultiSend`, [`the MultiSend (${lib}) contains a DELEGATECALL (operation 1) to a contract that is not a canonical Safe library (CONFIG.safe.libraries)`], {
            target: inner[k].to, targetDesc: await describe(inner[k].to), via: 'the transaction input (execTransaction, MultiSend payload decoded)', inner: { index: k, total: inner.length },
          });
          if (unverified) f.notes.push(unverified);
          out.push(f);
        }
      }
    }
  }
  if (alertHit && !out.length) {
    out.push(mk('high', 'Safe delegatecall alert fired, inspect the trace', ['the Safe delegatecall alert matched this transaction, but the delegatecall is not in the transaction input (the Safe was called from another contract, a module or a nested call), so its target could not be read here: open the trace and look for the DELEGATECALL frame'], {
      via: `alert ${String(event.alertId).slice(0, 8)} (the delegatecall frame is internal)`,
    }));
  }
  return out;
}

// ---------------------------------------------------------------------------- main
async function rpcUrls(context, net) {
  const N = netCfg(net);
  if (!N) return []; // a chain that is not in CONFIG.networks: no RPC, no classification (never a failed run)
  const urls = [];
  if (N.rpcSecret) {
    try {
      const u = await context.secrets.get(N.rpcSecret);
      if (/^https?:\/\//.test(u)) urls.push(u);
    } catch (e) {}
  }
  return [...urls, ...(N.rpc || [])];
}

// Did the contract exist before this block? true | false | null (could not be checked).
async function existedBefore(ctx, contract) {
  if (!ctx.block || ctx.block < 1 || ctx.noRpc || Date.now() > ctx.deadline) return null;
  try {
    const code = await rpc(ctx, 'eth_getCode', [contract, '0x' + (ctx.block - 1).toString(16)]);
    if (typeof code !== 'string' || !/^0x[0-9a-f]*$/i.test(code)) return null;
    return strip(code).length > 0;
  } catch (e) {
    return null;
  }
}

// "Initial assignment" (owner or admin set from 0x0, a first implementation, the first role grants) is harmless
// in a deployment and exactly the shape of a takeover on a live contract. It counts as initial only in
// a creation transaction, or when the contract had no code in the previous block.
async function markInitial(ctx, findings, creation) {
  const fromZero = (f) => f.prev === ZERO && ['owner', 'proxy-admin'].includes(f.kind);
  const newProxy = (f) => f.kind === 'proxy' && (f.name === 'Upgraded' || f.name === 'BeaconUpgraded'); // a proxy deployed in this block reports its first implementation
  const newGrant = (f) => f.ecls === 'grant' && ['role', 'ward', 'minter'].includes(f.kind); // a deployment hands out its initial roles
  for (const f of findings) {
    if (creation) {
      f.initial = true;
      continue;
    }
    if (!fromZero(f) && !newProxy(f) && !newGrant(f)) continue;
    const existed = await existedBefore(ctx, f.contract);
    if (existed === false) f.initial = true;
    else if (existed === true && fromZero(f)) f.notes.push('owner set from 0x0 on an existing contract: possible re-initialisation');
    else if (existed === null && fromZero(f)) f.notes.push('could not check whether this contract existed before this block');
  }
  for (const f of findings) {
    if (f.initial || f.kind !== 'proxy' || f.name !== 'Upgraded') continue;
    if (findings.some((g) => g.contract === f.contract && g.name === 'AdminChanged' && g.prev === ZERO && g.initial)) f.initial = true;
  }
}

const actionFn = async (context, event) => {
  const started = Date.now();
  const net = normNet(event && (event.network || event.networkId));
  const hash = lc(event && (event.hash || event.transactionHash));
  const urls = await rpcUrls(context, net);
  const ctx = { net, hash, context, cache: new Map(), holders: new Map(), ctl: new Map(), delays: new Map(), deadline: started + CONFIG.budgetMs, urls, noRpc: urls.length === 0 };
  if (ctx.noRpc) console.log(`chain ${net} has no RPC in CONFIG.networks: events are decoded, holders are not classified, auto-pause is skipped`);
  const table = tableFor(CONFIG.extendedEvents !== false);
  let logs = Array.isArray(event && event.logs) ? event.logs : null;
  ctx.block = event && event.blockNumber ? Number(event.blockNumber) : null;
  let txTo = event ? event.to : undefined;
  if (!logs || !logs.length) {
    if (!hash) throw new Error('event carries no logs and no transaction hash');
    if (ctx.noRpc) logs = []; // nothing to read the receipt with
    else {
      const rc = await rpc(ctx, 'eth_getTransactionReceipt', [hash]);
      logs = (rc && rc.logs) || [];
      ctx.block = ctx.block || (rc && rc.blockNumber ? Number(BigInt(rc.blockNumber)) : null);
      if (txTo === undefined && rc) txTo = rc.to;
      console.log(`event carried no logs, read ${logs.length} from the receipt`);
    }
  }
  const creation = txTo === null || txTo === '' || txTo === '0x';

  // 1. decode, skipping logs already handled
  let seen = { v: 1, ids: [] };
  try {
    const v = await context.storage.getJson(CONFIG.storage.seenKey);
    if (v && Array.isArray(v.ids)) seen = v;
  } catch (e) {
    console.error(`dedupe read failed: ${errMsg(e)}`);
  }
  const seenSet = new Set(seen.ids);
  const listed = Object.keys(CONFIG.contracts || {}).length > 0;
  const findings = [];
  let dupes = 0;
  logs.forEach((log, i) => {
    const spec = table.EV.get(lc((log.topics || [])[0]));
    if (!spec) return;
    const contract = lc(log.address);
    if (CONFIG.onlyListedContracts && !contractCfg(contract)) return;
    const id = `${net}:${hash.slice(2, 18)}:${i}`;
    if (seenSet.has(id)) {
      dupes++;
      return;
    }
    const d = decodeLog(log, spec);
    const f = { id, i, contract, t0: spec.t0, name: spec.name, family: spec.family, kind: spec.kind, cls: spec.cls, notes: [], net, noRpc: ctx.noRpc, ...d };
    if (ctx.noRpc) f.notes.push(`holder not classified: no RPC configured for chain ${net} (add it to CONFIG.networks); no auto-pause on this chain`);
    f.roleType = d.roleType;
    f.role = d.role !== undefined ? roleInfo(d.role, d.roleType) : null;
    if (f.newRole) f.notes.push(`new admin role ${roleInfo(f.newRole, d.newRoleType).label}${f.prevRole ? `, was ${roleInfo(f.prevRole, d.prevRoleType).label}` : ''}`);
    f.ecls = effectiveClass(f);
    f.known = f.who && byAddr(CONFIG.knownHolders, lc(f.who)) ? byAddr(CONFIG.knownHolders, lc(f.who)) : null;
    f.other = listed && !contractCfg(contract);
    if (f.other) f.notes.push('emitted by a contract that is not listed in CONFIG.contracts (another contract in the same transaction)');
    findings.push(f);
  });
  if (dupes) console.log(`duplicate delivery: ${dupes} governance log(s) of tx ${hash} already handled`);
  const reportable = findings.filter((f) => f.ecls !== 'trace' && !(f.ecls === 'notice' && !CONFIG.notifyScheduled));
  for (const f of reportable) f.policy = policyFor(f);
  const posted = reportable.filter((f) => f.policy !== 'ignore');
  if (reportable.length > posted.length) console.log(`${reportable.length - posted.length} finding(s) ignored by the role policy of CONFIG.contracts`);
  // Safe delegatecall (alerts/optional/safe-delegatecall-non-library.json): read from the transaction input.
  let dc = [];
  try {
    dc = (await safeDelegatecall(ctx, event || {}, txTo)).filter((f) => !seenSet.has(f.id));
  } catch (e) {
    console.error(`safe delegatecall check failed: ${errMsg(e)}`);
  }
  if (!posted.length && !dc.length) {
    console.log(`no new governance findings in tx ${hash} (${logs.length} logs)`);
    return;
  }

  // 2. context inside the tx: deployments and re-initialisation, transient grants, temporary ownership
  await markInitial(ctx, findings, creation);
  for (const f of findings) {
    if (f.ecls === 'grant' && f.role) {
      const undo = findings.find((g) => g.i > f.i && g.ecls === 'revoke' && g.contract === f.contract && g.role && g.role.id === f.role.id && g.who === f.who);
      if (undo) f.notes.push('granted and revoked again in this same transaction (temporary role)');
    }
    if (f.kind === 'owner' && f.ecls === 'grant' && f.prev) {
      const back = findings.find((g) => g.i > f.i && g.contract === f.contract && g.kind === 'owner' && g.prev === f.who && g.who === f.prev);
      if (back) f.notes.push('ownership returned to the previous owner later in this transaction (temporary transfer)');
    }
  }

  // 3. prior notice: signed announcement, then a LINKED trusted timelock execution, then known holder
  const registry = await loadRegistry(context);
  const execs = execInfo(logs, table);
  for (const f of posted) {
    if (!['grant', 'pending', 'param'].includes(f.ecls)) continue;
    const a = registryMatch(registry, f, net);
    if (a) {
      f.notice = `announced in the change registry (id ${a.id}, signed by ${short(a.announcer || '')}${a.note ? `: ${String(a.note).slice(0, 120)}` : ''}, valid until ${new Date(a.validUntil * 1000).toISOString()}, single use)`;
      f.noticeKind = 'registry';
      f.usedAnnouncement = { id: a.id, u: a.validUntil };
      continue;
    }
    const tl = await timelockNotice(ctx, f, execs).catch((e) => ({ ok: false, text: `timelock check failed (${errMsg(e)})` }));
    if (tl && tl.ok) {
      f.notice = tl.text;
      f.noticeKind = 'timelock';
    } else if (f.known) {
      f.notice = `known holder: ${f.known}`;
      f.noticeKind = 'known';
    } else if (tl && tl.text) f.notes.push(tl.text);
  }

  // 4. classify holders (parallel; the cache dedupes repeated addresses)
  await Promise.all(
    posted.map(async (f) => {
      if (f.who && f.ecls !== 'notice' && f.ecls !== 'state') f.holder = await classify(ctx, f.who, f.kind !== 'proxy');
      if (f.prev && f.prev !== ZERO) f.prevHolder = await classify(ctx, f.prev, false);
      if (f.kind === 'safe') f.safeState = await classify(ctx, f.contract, true);
      if (f.kind === 'proxy' && f.name === 'Upgraded' && !f.initial) {
        // who can upgrade this proxy: its admin (a ProxyAdmin owned by one key is a single key)
        const { admin } = await controllersOf(ctx, f.contract);
        if (admin) f.authority = await classify(ctx, admin, true);
      }
    })
  );
  // revokes from a Safe or timelock: does another Safe or timelock still hold the role?
  for (const f of posted) {
    if (f.ecls !== 'revoke' || !f.holder || !['safe', 'timelock'].includes(f.holder.cls)) continue;
    if (!f.role || f.roleType !== 'w' || Date.now() > ctx.deadline) continue;
    const [cnt] = await callMany(ctx, [[f.contract, SEL.getRoleMemberCount + strip(f.role.id)]]);
    const n = asUint(cnt);
    if (n === null || n > 20n) continue;
    const members = (await callMany(ctx, [...Array(Number(n)).keys()].map((k) => [f.contract, SEL.getRoleMember + strip(f.role.id) + k.toString(16).padStart(64, '0')]))).map(asAddr).filter(Boolean);
    const cls = await Promise.all(members.map((m) => classify(ctx, m, false)));
    const strong = cls.filter((c) => (c.cls === 'safe' && !c.singleKey) || (c.cls === 'timelock' && !c.weak));
    f.remaining = { checked: true, strong: strong.length > 0, text: members.length ? cls.map((c) => `${short(c.addr)} ${c.desc}`).join(', ') : 'nobody holds this role now' };
  }

  // 5. severity (the Safe delegatecall findings carry their own)
  for (const f of posted) Object.assign(f, (({ sev, reasons }) => ({ sev, reasons }))(score(f)));
  for (const f of posted) if (f.holder && f.holder.proposers && f.holder.proposers.note) f.notes.push(f.holder.proposers.note);
  posted.push(...dc);
  posted.sort((a, b) => SEV[b.sev] - SEV[a.sev] || a.i - b.i);

  // 6. auto-pause (before notifying: the pause is the time-critical part)
  await runAutoPause(context, ctx, posted).catch((e) => console.error(`auto-pause error: ${errMsg(e)}`));

  // 7. notify
  for (const f of posted) console.log(`finding sev=${f.sev} event=${f.name} contract=${f.contract} who=${f.who || '-'} holder="${f.holder ? f.holder.desc : '-'}" notice="${f.notice || 'none'}" why="${f.reasons.join('; ')}"`);
  const toSend = posted.filter((f) => SEV[f.sev] >= SEV[CONFIG.slack.minSeverity]);
  let delivered = true;
  if (toSend.length) {
    const msg = renderMessage(toSend, ctx);
    console.log(msg.text);
    try {
      const st = await postSlack(context, msg.text);
      if (st === 'no-secret') console.log(`secret ${CONFIG.slack.secret} not set: message logged only`);
    } catch (e) {
      delivered = false;
      console.error(`slack delivery failed: ${errMsg(e)}`);
    }
  }
  if (delivered) {
    seen.ids = [...seen.ids, ...findings.map((f) => f.id), ...dc.map((f) => f.id)].slice(-CONFIG.storage.seenMax);
    try {
      await context.storage.putJson(CONFIG.storage.seenKey, seen);
    } catch (e) {
      console.error(`dedupe write failed: ${errMsg(e)}`);
    }
    // Announcements are single use: mark the ones this run relied on, now that the run is committed.
    const used = posted.filter((f) => f.usedAnnouncement).map((f) => f.usedAnnouncement);
    if (used.length) {
      try {
        const now = Math.floor(Date.now() / 1000);
        const c = await context.storage.getJson(CONFIG.storage.consumedKey);
        const items = [...(Array.isArray(c && c.items) ? c.items : []), ...used].filter((x) => x.u > now);
        await context.storage.putJson(CONFIG.storage.consumedKey, { v: 1, items: items.slice(-300) });
      } catch (e) {
        console.error(`consumed write failed: ${errMsg(e)}`);
      }
    }
  }
  console.log(`done in ${Date.now() - started} ms: ${posted.length} finding(s), top ${posted[0].sev}`);
  if (!delivered) throw new Error('Slack delivery failed; the run is marked failed so it can be re-run');
  return { findings: posted.map((f) => ({ sev: f.sev, name: f.name, network: net, contract: f.contract, who: f.who || f.target || null, holder: f.holder ? f.holder.cls : null, proposers: f.holder && f.holder.proposerRisk ? f.holder.proposerRisk : null, notice: f.notice || null, autoPause: f.autoPause || null })) };
};

// ---------------------------------------------------------------------------- EXTENDED_EVENTS
// Rarely used families (same row format as EVENTS), decoded when CONFIG.extendedEvents is
// true: the remaining AccessManager, DefaultAdminRules, Solmate and Solady events, Safe
// extras, Compound and Circle MintController, Aave extras, Diamond, Chainlink, and the
// Monad protocols (Euler, Morpho, Uniswap V3, LayerZero, Curvance, Agora).
function EXTENDED_EVENTS() {
  return [
    ['0x3377dc44241e779dd06afab5b788a35ca5f3b778836e2990bdb26a2a4b2e5ed6', 'DefaultAdminTransferScheduled(address,uint48)', 'pending-owner', 'pending', 'who=t1:a at=d0:u', 'OZ AccessControlDefaultAdminRules'],
    ['0x8886ebfc4259abdbc16601dd8fb5678e54878f47b3c34836cfc51154a9605109', 'DefaultAdminTransferCanceled()', 'pending-owner', 'notice', '', 'OZ AccessControlDefaultAdminRules'],
    ['0xf1038c18cf84a56e432fdbfaf746924b7ea511dfe03a6506a0ceba4888788d9b', 'DefaultAdminDelayChangeScheduled(uint48,uint48)', 'timelock', 'param', 'val=d0:u at=d1:u', 'OZ AccessControlDefaultAdminRules'],
    ['0x2b1fa2edafe6f7b9e97c1a9e0c3660e645beb2dcaa2d45bdbf9beaf5472e1ec5', 'DefaultAdminDelayChangeCanceled()', 'timelock', 'notice', '', 'OZ AccessControlDefaultAdminRules'],
    ['0xf229baa593af28c41b1d16b748cd7688f0c83aaf92d4be41c44005defe84c166', 'RoleRevoked(uint64,address)', 'role', 'revoke', 'role=t1:am who=t2:a', 'OZ AccessManager'],
    ['0x1fd6dd7631312dfac2205b52913f99de03b4d7e381d5d27d3dbfe0713e6e6340', 'RoleAdminChanged(uint64,uint64)', 'role-admin', 'param', 'role=t1:am newRole=t2:am', 'OZ AccessManager'],
    ['0x7a8059630b897b5de4c08ade69f8b90c3ead1f8596d62d10b6c4d14a0afb4ae2', 'RoleGuardianChanged(uint64,uint64)', 'role-admin', 'param', 'role=t1:am newRole=t2:am', 'OZ AccessManager'],
    ['0xfeb69018ee8b8fd50ea86348f1267d07673379f72cffdeccec63853ee8ce8b48', 'RoleGrantDelayChanged(uint64,uint32,uint48)', 'timelock', 'param', 'role=t1:am val=d0:u at=d1:u', 'OZ AccessManager'],
    ['0x90d4e7bb7e5d933792b3562e1741306f8be94837e1348dacef9b6f1df56eb138', 'TargetClosed(address,bool)', 'pause', 'state', 'target=t1:a flag=d0:b', 'OZ AccessManager'],
    ['0xa56b76017453f399ec2327ba00375dbfb1fd070ff854341ad6191e6a2e2de19c', 'TargetAdminDelayUpdated(address,uint32,uint48)', 'timelock', 'param', 'target=t1:a val=d0:u at=d1:u', 'OZ AccessManager'],
    ['0x82a2da5dee54ea8021c6545b4444620291e07ee83be6dd57edb175062715f3b4', 'OperationScheduled(bytes32,uint32,uint48,address,address,bytes)', 'timelock', 'notice', 'id=t1:w at=d0:u by=d1:a target=d2:a', 'OZ AccessManager'],
    ['0xbd9ac67a6e2f6463b80927326310338bcbb4bdb7936ce1365ea3e01067e7b9f7', 'OperationCanceled(bytes32,uint32)', 'timelock', 'notice', 'id=t1:w', 'OZ AccessManager'],
    ['0x1256f5b5ecb89caec12db449738f2fbcd1ba5806cf38f35413f4e5c15bf6a450', 'RoleLabel(uint64,string)', 'role', 'trace', 'role=t1:am', 'OZ AccessManager'],
    ['0x950a343f5d10445e82a71036d3f4fb3016180a25805141932543b83e2078a93e', 'PublicCapabilityUpdated(address,bytes4,bool)', 'authority', 'param', 'target=t1:a sel=t2:s flag=d0:b', 'Solmate RolesAuthority'],
    ['0xa52ea92e6e955aa8ac66420b86350f7139959adfcc7e6a14eee1bd116d09860e', 'RoleCapabilityUpdated(uint8,address,bytes4,bool)', 'authority', 'param', 'role=t1:u8 target=t2:a sel=t3:s flag=d0:b', 'Solmate RolesAuthority'],
    ['0x36d28126bef21a4f3765d7fcb7c45cead463ae4c41094ef3b771ede598544103', 'PublicCapabilityUpdated(bytes4,bool)', 'authority', 'param', 'sel=t1:s flag=d0:b', 'Solmate MultiRolesAuthority'],
    ['0xbfe16b2c35ce23dfd1ab0e7b5d086a10060c9b52d1574e1680c881b3b3a2b151', 'RoleCapabilityUpdated(uint8,bytes4,bool)', 'authority', 'param', 'role=t1:u8 sel=t2:s flag=d0:b', 'Solmate MultiRolesAuthority'],
    ['0xa4908e11a5f895b13d51526c331ac93cdd30e59772361c5d07874eb36bff2065', 'TargetCustomAuthorityUpdated(address,address)', 'authority', 'grant', 'target=t1:a who=t2:a', 'Solmate MultiRolesAuthority'],
    ['0xdbf36a107da19e49527a7176a1babf963b4b0ff8cde35ee35d6cd8f1f9ac7e1d', 'OwnershipHandoverRequested(address)', 'pending-owner', 'notice', 'who=t1:a', 'Solady Ownable'],
    ['0xfa7b8eab7da67f412cc9575ed43464468f9bfbae89d1675917346ca6d8fe3c92', 'OwnershipHandoverCanceled(address)', 'pending-owner', 'trace', 'who=t1:a', 'Solady Ownable'],
    ['0xaddc47d7e02c95c00ec667676636d772a589ffbf0663cfd7cd4dd3d4758201b8', 'RoleSet(address,uint256,bool)', 'role', 'toggle', 'who=t1:a role=t2:w flag=t3:b', 'Solady EnumerableRoles'],
    ['0x6f50375045128971c5469d343039ba7b8e30a5b190453737b28bda6f7a306771', 'LogPermit(bytes32,bytes32,bytes32)', 'authority', 'grant', 'who=t1:aL target=t2:aL sel=t3:s', 'dapptools DSGuard'],
    ['0x95ba64c95d85e67ac83a0476c4a62ac2cf8ab2d0407545b8c9d79c3eefa62829', 'LogForbid(bytes32,bytes32,bytes32)', 'authority', 'revoke', 'who=t1:aL target=t2:aL sel=t3:s', 'dapptools DSGuard'],
    ['0xaab4fa2b463f581b2b32cb3b7e3b704b9ce37cc209b5fb4d77e593ace4054276', 'DisabledModule(address)', 'safe', 'revoke', 'who=t1|d0:a', 'Safe'],
    ['0xcd1966d6be16bc0c030cc741a06c6e0efaf8d00de2c8b6a9e11827e125de8bb8', 'ChangedModuleGuard(address)', 'safe', 'grant', 'who=t1|d0:a', 'Safe v1.5.0'],
    ['0x6895c13664aa4f67288b25d7a21d7aaa34916e355fb9b6fae0a139a9085becb8', 'ExecutionFromModuleSuccess(address)', 'safe', 'trace', 'by=t1|d0:a', 'Safe'],
    ['0x141df868a6331af528e38c83b7aa03edc19be66e37ae67f9285bf4f8e3c6a1a8', 'SafeSetup(address,address[],uint256,address,address)', 'safe', 'trace', 'by=t1:a', 'Safe'],
    ['0x4cf4410cc57040e44862ef0f45f3dd5a5e02db8eb8add648d4b0e236f1d07dca', 'CallScheduled(bytes32,uint256,address,uint256,bytes,bytes32,uint256)', 'timelock', 'notice', 'id=t1:w target=d0:a sel=d2:dynsel delay=d4:u', 'OZ TimelockController'],
    ['0xbaa1eb22f2a492ba1a5fea61b8df4d27c6c8b5f3971e63bb58fa14ff72eedb70', 'Cancelled(bytes32)', 'timelock', 'notice', 'id=t1:w', 'OZ TimelockController'],
    ['0x76e2796dc3a81d57b0e8504b647febcbeeb5f4af818e164f11eef8131a6a763f', 'QueueTransaction(bytes32,address,uint256,string,bytes,uint256)', 'timelock', 'notice', 'id=t1:w target=t2:a at=d3:u', 'Compound Timelock'],
    ['0x2fffc091a501fd91bfbff27141450d3acb40fb8e6d8382b243ec7a812a3aaf87', 'CancelTransaction(bytes32,address,uint256,string,bytes,uint256)', 'timelock', 'notice', 'id=t1:w target=t2:a', 'Compound Timelock'],
    ['0xf9ffabca9c8276e99321725bcb43fb076a6c66a54b7f21c4e8146d8519b417dc', 'NewAdmin(address,address)', 'owner', 'grant', 'prev=d0:a who=d1:a', 'Compound Comptroller / CToken'],
    ['0xca4f2f25d0898edd99413412fb94012f9e54ec8142f9b093e7720646a95b16a9', 'NewPendingAdmin(address,address)', 'pending-owner', 'pending', 'prev=d0:a who=d1:a', 'Compound Comptroller / CToken'],
    ['0xd604de94d45953f9138079ec1b82d533cb2160c906d1076d1f7ed54befbca97a', 'NewImplementation(address,address)', 'proxy', 'grant', 'prev=d0:a who=d1:a', 'Compound Unitroller / CErc20Delegator'],
    ['0xe945ccee5d701fc83f9b8aa8ca94ea4219ec1fcbd4f4cab4f0ea57c5c3e1d815', 'NewPendingImplementation(address,address)', 'proxy', 'pending', 'prev=d0:a who=d1:a', 'Compound Unitroller'],
    ['0xc67398012c111ce95ecb7429b933096c977380ee6c421175a71a4a4c6c88c06e', 'BlacklisterChanged(address)', 'role', 'grant', 'who=t1:a role=@BLACKLISTER', 'Circle FiatToken'],
    ['0xe475e580d85111348e40d8ca33cfdd74c30fe1655c2d8537a13abc10065ffa5a', 'RescuerChanged(address)', 'role', 'grant', 'who=t1:a role=@RESCUER', 'Circle FiatToken'],
    ['0x6985a02210a168e66602d3235cb6db0e70f92b3ba4d376a33c0f3d9434bff625', 'Pause()', 'pause', 'state', '', 'Circle FiatToken, Tether'],
    ['0x7805862f689e2f13df9f062ff482ad3ad112aca9e0847911ed832e158c525b33', 'Unpause()', 'pause', 'state', '', 'Circle FiatToken, Tether'],
    ['0x9992ea32e96992be98be5c833cd5b9fd77314819d2146b6f06ab9cfef957af12', 'MinterManagerSet(address,address)', 'minter', 'grant', 'prev=t1:a who=t2:a', 'Circle MintController'],
    ['0x5b0b60a4f757b33d9dcb8bd021b6aa371bb2e6f134086797aefcd8c0afab538c', 'MinterConfigured(address,address,uint256)', 'minter', 'grant', 'by=t1:a who=t2:a val=d0:u', 'Circle MintController'],
    ['0x4b5ef9a786cf64a7d82ebcf2d5132667edc9faef4ac36260d9a9e52c526b6232', 'MinterRemoved(address,address)', 'minter', 'revoke', 'by=t1:a who=t2:a', 'Circle MintController'],
    ['0xa56687ff5096e83f6e2c673cda0b677f56bbfcdf5fe0555d5830c407ede193cb', 'ControllerConfigured(address,address)', 'minter', 'grant', 'who=t1:a target=t2:a', 'Circle MintController'],
    ['0x33d83959be2573f5453b12eb9d43b3499bc57d96bd2f067ba44803c859e81113', 'ControllerRemoved(address)', 'minter', 'revoke', 'who=t1:a', 'Circle MintController'],
    ['0x5326514eeca90494a14bedabcff812a0e683029ee85d1e23824d44fd14cd6ae7', 'PriceOracleSentinelUpdated(address,address)', 'authority', 'grant', 'prev=t1:a who=t2:a', 'Aave V3 PoolAddressesProvider'],
    ['0xc853974cfbf81487a14a23565917bee63f527853bcb5fa54f2ae1cdf8a38356d', 'PoolDataProviderUpdated(address,address)', 'authority', 'grant', 'prev=t1:a who=t2:a', 'Aave V3 PoolAddressesProvider'],
    ['0x9ef0e8c8e52743bb38b83b17d9429141d494b8041ca6d616a6c77cebae9cd8b7', 'AddressSet(bytes32,address,address)', 'authority', 'grant', 'id=t1:w prev=t2:a who=t3:a', 'Aave V3 PoolAddressesProvider'],
    ['0x3bbd45b5429b385e3fb37ad5cd1cd1435a3c8ec32196c7937597365a3fd3e99c', 'AddressSetAsProxy(bytes32,address,address,address)', 'proxy', 'grant', 'id=t1:w target=t2:a prev=d0:a who=t3:a', 'Aave V3 PoolAddressesProvider'],
    ['0x4a465a9bd819d9662563c1e11ae958f8109e437e7f4bf1c6ef0b9a7b3f35d478', 'ProxyCreated(bytes32,address,address)', 'proxy', 'notice', 'id=t1:w target=t2:a who=t3:a', 'Aave V3 PoolAddressesProvider'],
    ['0xe685c8cdecc6030c45030fd54778812cb84ed8e4467c38294403d68ba7860823', 'MarketIdSet(string,string)', 'authority', 'trace', '', 'Aave V3 PoolAddressesProvider'],
    ['0x22c5b7b2d8561d39f7f210b6b326a1aa69f15311163082308ac4877db6339dc1', 'AssetSourceUpdated(address,address)', 'authority', 'grant', 'target=t1:a who=t2:a', 'Aave V3 AaveOracle'],
    ['0xe188d542a5f11925d3a3af33703cdd30a43cb3e8066a3cf68b1b57f61a5a94b5', 'ReservePaused(address,bool)', 'pause', 'state', 'target=t1:a flag=d0:b', 'Aave V3 PoolConfigurator'],
    ['0xed8889f560326eb138920d842192f0eb3dd22b4f139c87a2c57538e05bae1278', 'OwnershipTransferRequested(address,address)', 'pending-owner', 'pending', 'prev=t1:a who=t2:a', 'Chainlink ConfirmedOwner'],
    ['0x8faa70878671ccd212d20771b795c50af8fd3ff6cf27f4bde57e5d4de0aeb673', 'DiamondCut((address,uint8,bytes4[])[],address,bytes)', 'proxy', 'param', '', 'EIP-2535 Diamond'],
    ['0xb532073b38c83145e3e5135377a08bf9aab55bc0fd7c1179cd4fb995d2a5159c', 'OwnerChanged(address,address)', 'owner', 'grant', 'prev=t1:a who=t2:a', 'Uniswap V3 Factory and forks'],
    ['0x167d3e9c1016ab80e58802ca9da10ce5c6a0f4debc46a2e7a2cd9e56899a4fb5', 'SetOwner(address)', 'owner', 'grant', 'who=t1:a', 'Morpho Blue'],
    ['0x238399d427b947898edb290f5ff0f9109849b1c3ba196a42e35f00c50a54b98b', 'PeerSet(uint32,bytes32)', 'authority', 'param', 'val=d0:u peer=d1:w', 'LayerZero V2 OApp / OFT'],
    ['0x1c145a4cd16d4148579b0f2296884ac4aa47536e4ef10a32e1cdc0dc3dd20ea4', 'GovSetGovernorAdmin(address)', 'owner', 'grant', 'who=t1|d0:a', 'Euler V2 EVault'],
    ['0xf31bb200dbf42bb9cecaa49dceb87eae178b024ad3cf2930b4aaac5cb0f96ec0', 'GovernorSet(address,address)', 'owner', 'grant', 'prev=t1:a who=t2:a', 'Euler EulerRouter'],
    ['0x40f7b3ef64c9e38288873dda008188d6c3cd146f84d77b978478a8731f71feb9', 'PermissionsUpdated(string,address,bool)', 'role', 'toggle', 'role=t1:sh who=d0:a flag=d1:b', 'Curvance CentralRegistry'],
    ['0xd8e127776f279a25ebbafc660f7deba16e71dcb8ff27626f743010802c27211d', 'PermissionsTransferred(string,address,address)', 'role', 'grant', 'role=t1:sh prev=d0:a who=d1:a', 'Curvance CentralRegistry'],
    ['0x1cf4c2f10398d18e27c3336eeadbf9ce9571462b7cb30d5d9a4024580f208d21', 'RoleAssigned(string,address)', 'role', 'grant', 'role=t1:sh who=t2|d0:a', 'Agora AUSD'],
    ['0x1e5d48c75f77ab7fd581247d777530d4e8c18432289e14017ba995532f6ca1cf', 'RoleRevoked(string,address)', 'role', 'revoke', 'role=t1:sh who=t2|d0:a', 'Agora AUSD'],
  ];
}
// Curvance CentralRegistry role names (indexed string roles: topic = keccak256(name)).
const STRING_ROLES = {
  '0x2e7a327ef83c2af7579c6634f2f5604519800c5f07626f27bd602fd11ed8e6ec': 'Market',
  '0x8ecde2db1c9deada80824fb0dace25074b3a12d7c3ed7ddc9f6b0da91ef1906b': 'Market Manager',
  '0xa283d319a515140afe046e9e5d327abdaec2af2b41b7532edc58fd36e4d9868c': 'DAO Permissions',
  '0xfaecd04042c11add5e5effceadd726e8d24ffbc8b26bd4dfa93f4e6d89d606af': 'Emergency Council',
  '0x787bfb812ef65292405e9c4e05f2befe48dae3e62d7ed27bada75d2384e733d3': 'Harvest',
  '0xcf3346ede9fe18a1c9bd06d1c53f7b47e4969bd3ed9fe3dc4d39e856bd24d7af': 'Auction',
  '0x8bdc034209cd34465f1fe5127e9f4c5350103200f3bf7dc8daa75003ccf585e0': 'Timelock',
};

// _internal: local tests only. EVENTS is exported with every row (core + extended).
module.exports = { actionFn, CONFIG, EVENTS: [...EVENTS, ...EXTENDED_EVENTS()], _internal: { decodeLog, roleInfo, EV: tableFor(true).EV, announcementMessage, parseSafe, parseTimelock, decodeExec, decodeMultiSend, normNet, postureKey } };
