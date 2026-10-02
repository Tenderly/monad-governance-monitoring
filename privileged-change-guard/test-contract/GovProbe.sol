// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title GovProbe
/// @notice TEST-ONLY contract for the privileged change guard template. It emits the
///         governance events of the common access-control families from one address:
///         OpenZeppelin Ownable and AccessControl, dapptools DSAuth, Maker wards
///         (Rely/Deny and the legacy anonymous LogNote) and OpenZeppelin Pausable.
/// @dev    Every privileged function is restricted to `controller` (the deployer), so the
///         deployer keeps full control whatever owner, authority, ward or role holder the
///         events announce. pause()/unpause() are restricted to `guardian`.
///         Role membership is enumerable so the guard can check who still holds a role.
contract GovProbe {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    address public immutable controller;
    address public guardian;
    address public owner;
    address public authority;
    bool public paused;
    mapping(address => uint256) public wards;

    mapping(bytes32 => mapping(address => bool)) private _hasRole;
    mapping(bytes32 => address[]) private _members;

    // OpenZeppelin Ownable
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    // OpenZeppelin AccessControl
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    // dapptools DSAuth
    event LogSetOwner(address indexed owner);
    event LogSetAuthority(address indexed authority);
    // Maker wards, dss style
    event Rely(address indexed usr);
    event Deny(address indexed usr);
    // OpenZeppelin Pausable
    event Paused(address account);
    event Unpaused(address account);

    error NotController();
    error NotGuardian();
    error AlreadyPaused();
    error NotPaused();

    modifier onlyController() {
        if (msg.sender != controller) revert NotController();
        _;
    }

    modifier onlyGuardian() {
        if (msg.sender != guardian) revert NotGuardian();
        _;
    }

    constructor(address guardian_) {
        controller = msg.sender;
        guardian = guardian_;
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
        _grant(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    // ------------------------------------------------------------ Ownable
    function transferOwnership(address newOwner) external onlyController {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ------------------------------------------------------------ AccessControl
    function grantRole(bytes32 role, address account) external onlyController {
        _grant(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyController {
        if (!_hasRole[role][account]) return;
        _hasRole[role][account] = false;
        address[] storage m = _members[role];
        for (uint256 i; i < m.length; i++) {
            if (m[i] == account) {
                m[i] = m[m.length - 1];
                m.pop();
                break;
            }
        }
        emit RoleRevoked(role, account, msg.sender);
    }

    function hasRole(bytes32 role, address account) external view returns (bool) {
        return _hasRole[role][account];
    }

    function getRoleMemberCount(bytes32 role) external view returns (uint256) {
        return _members[role].length;
    }

    function getRoleMember(bytes32 role, uint256 index) external view returns (address) {
        return _members[role][index];
    }

    function _grant(bytes32 role, address account) internal {
        if (_hasRole[role][account]) return;
        _hasRole[role][account] = true;
        _members[role].push(account);
        emit RoleGranted(role, account, msg.sender);
    }

    // ------------------------------------------------------------ DSAuth
    function setOwner(address owner_) external onlyController {
        owner = owner_;
        emit LogSetOwner(owner_);
    }

    function setAuthority(address authority_) external onlyController {
        authority = authority_;
        emit LogSetAuthority(authority_);
    }

    // ------------------------------------------------------------ Maker wards
    /// @notice dss-style rely: emits Rely(usr).
    function rely(address usr) external onlyController {
        wards[usr] = 1;
        emit Rely(usr);
    }

    /// @notice dss-style deny: emits Deny(usr).
    function deny(address usr) external onlyController {
        wards[usr] = 0;
        emit Deny(usr);
    }

    /// @notice Legacy MCD style: emits the anonymous LibNote log that rely(address) emits
    ///         on the original Maker contracts (topic0 = rely selector, left-aligned).
    function relyLegacy(address usr) external onlyController {
        wards[usr] = 1;
        _note(bytes4(keccak256("rely(address)")), usr);
    }

    /// @notice Legacy MCD style deny: anonymous LibNote with the deny(address) selector.
    function denyLegacy(address usr) external onlyController {
        wards[usr] = 0;
        _note(bytes4(keccak256("deny(address)")), usr);
    }

    /// @dev Same layout as makerdao/dss LibNote: log4(abi.encode(first 224 calldata bytes),
    ///      sig, caller, arg1, arg2). Calldata is rebuilt as if `sig(usr)` had been called.
    function _note(bytes4 sig, address usr) internal {
        bytes memory cd = new bytes(224);
        bytes memory head = abi.encodeWithSelector(sig, usr);
        for (uint256 i; i < head.length; i++) {
            cd[i] = head[i];
        }
        bytes memory data = abi.encode(cd);
        bytes32 t0 = bytes32(sig);
        bytes32 t1 = bytes32(uint256(uint160(msg.sender)));
        bytes32 t2 = bytes32(uint256(uint160(usr)));
        assembly {
            log4(add(data, 0x20), mload(data), t0, t1, t2, 0)
        }
    }

    // ------------------------------------------------------------ Pausable
    function pause() external onlyGuardian {
        if (paused) revert AlreadyPaused();
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyGuardian {
        if (!paused) revert NotPaused();
        paused = false;
        emit Unpaused(msg.sender);
    }

    function setGuardian(address guardian_) external onlyController {
        guardian = guardian_;
    }
}
