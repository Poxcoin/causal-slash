// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/PerformanceCollateralVault.sol";
import "../contracts/MockUSDC.sol";
import "../contracts/MockERC4626Vault.sol";

contract YieldStreamingCollateralTest is Test {
    PerformanceCollateralVault public vault;
    MockUSDC public usdc;
    MockERC4626Vault public morphoVault;

    address public deployer;
    address public treasury;
    address public insuranceReserve;
    address public finder;

    uint256 public agentSigningPk;
    address public agentSigner;
    address public agentOwner;

    uint256 public vendorPk;
    address public vendor;

    bytes32 public constant CHEQUE_TYPEHASH = keccak256(
        "Cheque(address agent,address vendor,uint256 cumulativeAmount,uint256 sessionNonce,uint256 deadline)"
    );

    function setUp() public {
        deployer = address(0x101);
        treasury = address(0x102);
        insuranceReserve = address(0x103);
        finder = address(0x104);

        agentSigningPk = 0xA11;
        agentSigner = vm.addr(agentSigningPk);
        agentOwner = address(0xA22);

        vendorPk = 0xB11;
        vendor = vm.addr(vendorPk);

        vm.startPrank(deployer);
        usdc = new MockUSDC();
        vault = new PerformanceCollateralVault(address(usdc), treasury, insuranceReserve);
        morphoVault = new MockERC4626Vault(IERC20(address(usdc)));

        // Fund participants
        usdc.mint(agentOwner, 100_000 * 1e6);
        usdc.mint(finder, 10 * 1e6);
        usdc.mint(deployer, 10_000 * 1e6);
        vm.stopPrank();

        vm.prank(agentOwner);
        usdc.approve(address(vault), type(uint256).max);

        vm.prank(finder);
        usdc.approve(address(vault), type(uint256).max);

        // Configure Yield Vault Strategy (80% yield deployment, 20% liquid cash buffer)
        vm.prank(treasury);
        vault.setYieldVault(address(morphoVault), 2000);
    }

    /// TEST 1: Auto-rebalance deploys 80% to Morpho Blue while maintaining 20% liquid cash
    function test_Yield_AutoRebalance_Maintains_20PercentCashBuffer() public {
        vm.prank(agentOwner);
        vault.depositCollateral(10_000 * 1e6, keccak256("root"), agentSigner);

        uint256 pureCash = usdc.balanceOf(address(vault));
        uint256 shares = morphoVault.balanceOf(address(vault));
        uint256 inYield = morphoVault.previewRedeem(shares);

        assertEq(pureCash, 2_000 * 1e6); // 20% liquid cash buffer
        assertEq(inYield, 8_000 * 1e6);  // 80% generating yield in Morpho Blue
        assertEq(vault.principalInYield(), 8_000 * 1e6);
    }

    /// TEST 2: Passive yield generation & harvesting to insurance and treasury
    function test_Yield_Accrual_And_Harvesting() public {
        vm.prank(agentOwner);
        vault.depositCollateral(10_000 * 1e6, keccak256("root"), agentSigner);

        // Simulate borrowers paying 6% APY: 600 USDC profit into Morpho vault
        vm.startPrank(deployer);
        usdc.approve(address(morphoVault), 600 * 1e6);
        morphoVault.simulateYieldAccrual(600 * 1e6);
        vm.stopPrank();

        uint256 insBefore = usdc.balanceOf(insuranceReserve);
        uint256 trsBefore = usdc.balanceOf(treasury);

        // Harvest yield
        vault.harvestYield();

        // 60% ($360) goes to Insurance Reserve (bad debt buffer), 40% ($240) goes to Treasury (accounting for 1-wei ERC-4626 share rounding)
        assertApproxEqAbs(usdc.balanceOf(insuranceReserve) - insBefore, 360 * 1e6, 2);
        assertApproxEqAbs(usdc.balanceOf(treasury) - trsBefore, 240 * 1e6, 2);
        assertApproxEqAbs(vault.totalYieldHarvested(), 600 * 1e6, 2);

        // Agent's collateral bond remains 100% full and intact
        (uint256 bond,,,,,,) = vault.vaults(agentOwner);
        assertEq(bond, 10_000 * 1e6);
    }

    /// TEST 3: Instant 0-second withdrawal automatically redeems from yield vault when cash is exceeded
    function test_Yield_InstantWithdraw_Seamlessly_Redeems_From_Vault() public {
        vm.prank(agentOwner);
        vault.depositCollateral(10_000 * 1e6, keccak256("root"), agentSigner);

        // Pure cash is only $2,000. Agent requests instant withdrawal of $6,000.
        uint256 balBefore = usdc.balanceOf(agentOwner);
        vm.prank(agentOwner);
        vault.instantWithdraw(6_000 * 1e6);

        // Agent immediately receives full $6,000 USDC in 0 seconds
        assertEq(usdc.balanceOf(agentOwner) - balBefore, 6_000 * 1e6);

        (uint256 bond,,,,,,) = vault.vaults(agentOwner);
        assertEq(bond, 4_000 * 1e6);
    }

    /// TEST 4: Closed-loop slashing foreclosure functions flawlessly while funds are generating yield
    function test_Yield_Slashing_Waterfall_Uncompromised() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10_000 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 2_000 * 1e6);
        vm.stopPrank();

        bytes32 salt = keccak256("salt_yield_slashing");
        bytes32 commit = keccak256(abi.encodePacked(agentSigningPk, finder, salt));

        vm.prank(finder);
        vault.commitFraudProof(agentOwner, commit);

        vm.roll(block.number + 2);

        uint256 finderBefore = usdc.balanceOf(finder);
        vm.prank(finder);
        vault.revealAndSlash(PerformanceCollateralVault.SlashArgs({
            maliciousAgent: agentOwner,
            extractedSk: agentSigningPk,
            salt: salt
        }));

        // Finder receives 15% guaranteed bounty ($1,500) + 1 USDC commit bond
        assertEq(usdc.balanceOf(finder) - finderBefore, 1_501 * 1e6);

        // Vendor claims $2,000 damage restitution
        bytes32 structHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, agentOwner, vendor, 2_000 * 1e6, 1, block.timestamp + 1000)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentSigningPk, vault.hashTypedDataV4(structHash));
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(vendor);
        vault.claimSlashedRestitution(agentOwner, 2_000 * 1e6, 1, block.timestamp + 1000, sig);
        assertEq(usdc.balanceOf(vendor), 2_000 * 1e6);
    }
}
