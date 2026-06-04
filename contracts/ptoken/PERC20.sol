// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {OrchardVerifier} from "../orchardverifier/OrchardVerifier.sol";
import {IEndpointCore} from "../interfaces/IEndpointCore.sol";
import {IPERC20} from "../interfaces/IPERC20.sol";

/// @title PERC20
/// @notice Reference implementation of the pERC20 standard (privacy-native fungible token).
///   Wraps the OrchardVerifier note state machine with ERC-20-like metadata + public totalSupply,
///   and exposes mint/burn/transfer over IPERC20.PrivacyCall.
contract PERC20 is OrchardVerifier, IPERC20 {
    string private _name;
    string private _symbol;
    uint8 private _decimals;
    address public immutable issuer;

    uint256 private _totalSupply;

    error NotIssuer();
    error AmountVbMismatch();
    error BurnSignBitSet();
    error SupplyUnderflow();
    error AmountTooLarge();
error ZeroIssuer();
error ZeroVerifier();

    modifier onlyIssuer() {
        if (msg.sender != issuer) revert NotIssuer();
        _;
    }

    /// @param issuer_ Token issuer; also acts as the per-asset compliance officer
    ///                (admin) — same address holds `mint`, `setFrozenRoot`, and
    ///                `setGroth16Verifier` authority. Use `transferAdmin`/`acceptAdmin`
    ///                to split later.
    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        address issuer_,
        address groth16Verifier_
    ) OrchardVerifier(issuer_, groth16Verifier_) {
    if (issuer_ == address(0)) revert ZeroIssuer();
    if (groth16Verifier_ == address(0)) revert ZeroVerifier();
        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
        issuer = issuer_;
        emit Perc20Created(address(this), issuer_, name_, symbol_, decimals_);
    }

    function name() external view returns (string memory) {
        return _name;
    }

    function symbol() external view returns (string memory) {
        return _symbol;
    }

    function decimals() external view returns (uint8) {
        return _decimals;
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    /// @inheritdoc IPERC20
    function cmxFrozenRoot() public view override(IPERC20, OrchardVerifier) returns (uint256) {
        return super.cmxFrozenRoot();
    }

    /// @inheritdoc IPERC20
    /// @dev M1: `onlyAdmin` (= issuer at deployment) may update the blacklist root.
    function setFrozenRoot(uint256 newRoot) external override onlyAdmin {
        uint256 old = _setFrozenRoot(newRoot);
        emit FrozenRootUpdated(old, newRoot);
    }

    /// @inheritdoc IPERC20
    /// @dev Per IPERC20: this standard intentionally does NOT emit the ERC-20 `Transfer`
    ///   event. Per-note observability is provided by `NoteAdded`/`NoteConfirmed`
    ///   (see IEndpointCore). Returns `true` on success to match ERC-20 calling conventions.
    /// @param call Privacy bundle payload:
    ///   - `call.actions` must be `abi.encode(IEndpointCore.BundleAction[])`.
    ///   - for transfer, actions are regular spend/output actions (`valueBalance = 0`).
    ///   - `call.bindingSig` is verified by `_executeBundle` against this contract + chain id.
    function transfer(PrivacyCall calldata call) external returns (bool) {
        // Decode the private action bundle provided by caller/wallet.
        IEndpointCore.BundleAction[] memory actions =
            abi.decode(call.actions, (IEndpointCore.BundleAction[]));
        // Transfer is value-neutral at the public layer: valueBalance = 0, amount = 0.
        _executeBundle(actions, 0, 0, bytes32(0), call.bindingSig);
        return true;
    }

    /// @inheritdoc IPERC20
    /// @param call Privacy bundle payload:
    ///   - `call.actions` must be `abi.encode(IEndpointCore.BundleAction[])`.
    ///   - for mint, actions are output-only (conventionally `nfOld == 0`).
    ///   - `call.bindingSig` must bind to `valueBalance = amount | (1 << 255)`.
    function mint(uint256 amount, PrivacyCall calldata call) external onlyIssuer {
        // Keep public amount within subgroup order so declared amount matches scalar semantics.
        if (amount >= SUBGROUP_ORDER) revert AmountTooLarge();
        // Mint is encoded as negative value-balance (bit255 = 1) with low 255 bits = amount.
        uint256 vb = amount | (1 << 255);
        _requireAmountMatchesVb(amount, vb);
        // Decode proof bundle and execute note-state transition with binding-signature checks.
        IEndpointCore.BundleAction[] memory actions =
            abi.decode(call.actions, (IEndpointCore.BundleAction[]));
        _executeBundle(actions, vb, amount, bytes32(0), call.bindingSig);
        // Public supply increases only after successful bundle verification/execution.
        _totalSupply += amount;
        emit Mint(issuer, amount);
    }

    /// @inheritdoc IPERC20
    /// @param call Privacy bundle payload:
    ///   - `call.actions` must be `abi.encode(IEndpointCore.BundleAction[])`.
    ///   - burn consumes existing notes and binds `valueBalance = amount`.
    ///   - `call.bindingSig` is validated in `_executeBundle` before any state mutation.
    function burn(uint256 amount, PrivacyCall calldata call) external {
        // Burn uses a non-negative public amount; sign bit must stay unset.
        if (amount >= (1 << 255)) revert BurnSignBitSet();
        // Keep the declared amount inside the prime subgroup range to avoid mod-l mismatch.
        if (amount >= SUBGROUP_ORDER) revert AmountTooLarge();
        _requireAmountMatchesVb(amount, amount);
        // Decode the proof bundle from IPERC20.PrivacyCall.
        IEndpointCore.BundleAction[] memory actions =
            abi.decode(call.actions, (IEndpointCore.BundleAction[]));
        // Verify proofs/signatures and apply note-state transitions first; this reverts atomically on failure.
        _executeBundle(actions, amount, amount, bytes32(0), call.bindingSig);
        // Only after bundle success, update public supply with an explicit underflow guard.
        if (_totalSupply < amount) revert SupplyUnderflow();
        _totalSupply -= amount;
        emit Burn(amount);
    }

    function _requireAmountMatchesVb(uint256 amount, uint256 valueBalance) internal pure {
        if ((valueBalance & ((1 << 255) - 1)) != amount) revert AmountVbMismatch();
    }
}
