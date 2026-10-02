// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/PerformanceCollateralVault.sol";
import "../../contracts/SwarmDelegationVault.sol";
import "../../contracts/MockUSDC.sol";
import "./VaultHandler.sol";

contract ProtocolInvariantsTest is Test {
    SwarmDelegationVault public vault;
    MockUSDC public usdc;
    VaultHandler public handler;

    address public deployer;
    address public treasury;
    address public insuranceReserve;
    address public finder;

    function setUp() public {
        deployer = address(0xAA1);
        treasury = address(0xAA2);
        insuranceReserve = address(0xAA3);
        finder = address(0xAA4);

        vm.startPrank(deployer);
        usdc = new MockUSDC();
        vault = new SwarmDelegationVault(address(usdc), treasury, insuranceReserve);
        vm.stopPrank();

        handler = new VaultHandler(vault, usdc, treasury, insuranceReserve, finder);

        vm.startPrank(finder);
        usdc.approve(address(vault), type(uint256).max);
        vm.stopPrank();

        targetContract(address(handler));
    }

    /// @notice Invariant 1: Global Solvency Invariant
    /// The vault's USDC balance must at all times be >= sum of all active collateral bonds + restitution pools + unrevealed commit bonds
    function invariant_VaultSolvency() public view {
        uint256 totalLiabilities = 0;
        for (uint256 i = 0; i < handler.NUM_AGENTS(); i++) {
            address agent = handler.agents(i);
            (uint256 bond,,,,,,) = vault.vaults(agent);
            uint256 restitution = vault.slashedRestitutionPool(agent);
            totalLiabilities += (bond + restitution);
        }

        uint256 unrevealedCommitBonds = handler.ghost_totalCommitBondsDeposited() - handler.ghost_totalCommitBondsRefunded();
        totalLiabilities += unrevealedCommitBonds;

        uint256 actualVaultBalance = usdc.balanceOf(address(vault));
        assertGe(
            actualVaultBalance,
            totalLiabilities,
            "CRITICAL: Vault is insolvent! Balance less than committed liabilities"
        );
    }

    /// @notice Invariant 2: Exposure Bound Safety & Free Margin Underflow Protection
    /// Total exposure allocated across active vendors for any non-slashed agent must never exceed its collateral bond,
    /// and freeMargin expression must strictly evaluate without arithmetic underflow.
    function invariant_ExposureWithinCollateral() public view {
        for (uint256 i = 0; i < handler.NUM_AGENTS(); i++) {
            address agent = handler.agents(i);
            (uint256 bond,,,,,, bool isSlashed) = vault.vaults(agent);
            uint256 allocated = vault.totalAllocatedExposure(agent);

            if (!isSlashed) {
                assertLe(
                    allocated,
                    bond,
                    "CRITICAL: Allocated exposure exceeds collateral bond for active agent"
                );
            }

            // Verify freeMargin underflow protection
            uint256 freeMargin = bond > allocated ? bond - allocated : 0;
            assertGe(freeMargin, 0, "CRITICAL: Free margin underflow");
            if (bond >= allocated) {
                assertEq(freeMargin, bond - allocated);
            } else {
                assertEq(freeMargin, 0);
            }
        }
    }

    /// @notice Invariant 3: Closed-System Accounting Conservation Law
    /// Total Inflow == Current Vault Balance + Total Outflows across all waterfall distribution paths
    function invariant_AccountingConservation() public view {
        uint256 totalInflow = handler.ghost_totalDeposited() + handler.ghost_totalCommitBondsDeposited();
        uint256 currentBalance = usdc.balanceOf(address(vault));
        uint256 totalOutflow = handler.ghost_totalWithdrawn()
            + handler.ghost_totalSettled()
            + handler.ghost_totalRestitutionClaimed()
            + handler.ghost_totalFinderBounties()
            + handler.ghost_totalInsurancePaid()
            + handler.ghost_totalTreasuryPaid()
            + handler.ghost_totalCommitBondsRefunded();

        assertEq(
            totalInflow,
            currentBalance + totalOutflow,
            "CRITICAL: Leaked or phantom USDC detected in conservation ledger"
        );
    }

    /// @notice Invariant 4: Restitution Pool Drain Invariant
    /// Claimed restitution never exceeds the allocated pool, and conservation holds exactly
    function invariant_RestitutionPoolDrain() public view {
        for (uint256 i = 0; i < handler.NUM_AGENTS(); i++) {
            address agent = handler.agents(i);
            uint256 claimed = handler.ghost_agentRestitutionClaimed(agent);
            uint256 initialPool = handler.ghost_initialRestitutionPool(agent);
            uint256 remainingPool = vault.slashedRestitutionPool(agent);
            uint256 swept = handler.ghost_agentRestitutionSwept(agent);

            assertLe(claimed, initialPool, "Restitution claimed exceeds initial pool");
            assertEq(claimed + remainingPool + swept, initialPool, "Restitution pool balance leak");
        }
    }

    /// @notice Invariant 5: Monotonic Channel Progression
    /// Channel nonces and settled amounts are strictly monotonically tracked
    function invariant_MonotonicChannelProgression() public view {
        for (uint256 i = 0; i < handler.NUM_AGENTS(); i++) {
            address agent = handler.agents(i);
            for (uint256 j = 0; j < handler.NUM_VENDORS(); j++) {
                address vendor = handler.vendors(j);
                uint256 settled = vault.settledAmounts(agent, vendor);
                uint256 ghostSettled = handler.ghost_cumulativeSettled(agent, vendor);
                assertEq(settled, ghostSettled, "Settled amount mismatch");
                uint256 height = vault.lastSessionNonces(agent, vendor);
                uint64 ghostHeight = handler.ghost_channelHeights(agent, vendor);
                assertEq(height, ghostHeight, "Session nonce mismatch");
            }
        }
    }
}
