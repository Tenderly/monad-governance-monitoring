// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title SilentProbe
/// @notice Test-only contract for the privileged posture audit. `owner()` reads one storage slot.
///         The slot can be rewritten with an event (`setOwnerLoudly`, OpenZeppelin style
///         `OwnershipTransferred`) or without any event (`setOwnerSilently`), which is the shape of
///         a takeover that event alerts cannot see. It holds no funds and guards nothing.
/// @dev Who may write: the current owner, and the `controller` (the deployer, immutable). The
///      controller is a backstop so a probe whose owner was set to an address nobody holds a key
///      for can always be moved again. The constructor emits nothing, so every
///      `OwnershipTransferred` this contract ever logs comes from `setOwnerLoudly`.
contract SilentProbe {
    /// @dev Same signature as OpenZeppelin Ownable: topic0 is
    ///      0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotAuthorized();

    /// @notice Storage slot that holds the owner: keccak256("monadTpl.silentProbe.owner") - 1.
    bytes32 public constant OWNER_SLOT = bytes32(uint256(keccak256("monadTpl.silentProbe.owner")) - 1);

    /// @notice The deployer. Can always write the owner slot.
    address public immutable controller;

    constructor(address initialOwner) {
        controller = msg.sender;
        _write(initialOwner == address(0) ? msg.sender : initialOwner);
    }

    /// @notice Current owner, read straight from `OWNER_SLOT`.
    function owner() public view returns (address o) {
        bytes32 slot = OWNER_SLOT;
        assembly {
            o := sload(slot)
        }
    }

    /// @notice Writes the owner slot and emits nothing.
    function setOwnerSilently(address newOwner) external {
        _authorize();
        _write(newOwner);
    }

    /// @notice Writes the owner slot and emits `OwnershipTransferred(previousOwner, newOwner)`.
    function setOwnerLoudly(address newOwner) external {
        _authorize();
        address previous = owner();
        _write(newOwner);
        emit OwnershipTransferred(previous, newOwner);
    }

    function _authorize() internal view {
        if (msg.sender != controller && msg.sender != owner()) revert NotAuthorized();
    }

    function _write(address newOwner) internal {
        bytes32 slot = OWNER_SLOT;
        assembly {
            sstore(slot, newOwner)
        }
    }
}
