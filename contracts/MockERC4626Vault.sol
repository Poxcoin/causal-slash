// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title MockERC4626Vault
 * @notice Realistic ERC-4626 yield strategy simulating Morpho Blue / Aave v3 on Base L2.
 */
contract MockERC4626Vault is ERC4626 {
    using SafeERC20 for IERC20;

    constructor(IERC20 asset_) ERC20("Morpho Blue Mock Vault", "mbUSDC") ERC4626(asset_) {}

    /**
     * @notice Simulates passive lending yield generation (e.g. 5-8% APY from borrowers).
     */
    function simulateYieldAccrual(uint256 yieldUSDC) external {
        IERC20(asset()).safeTransferFrom(msg.sender, address(this), yieldUSDC);
    }
}
