// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/PerformanceCollateralVault.sol";
import "../contracts/MockUSDC.sol";

contract ReliabilityInvariantsAuditTest is Test {
    PerformanceCollateralVault public vault;
    MockUSDC public usdc;

    address public deployer;
    address public treasury;
    address public insuranceReserve;
    address public finder;

    uint256 public vendor1Pk;
    address public vendor1;

    uint256 public vendor2Pk;
    address public vendor2;

    uint256 public agentOwnerPk;
    address public agentOwner;

    uint256 public agentSigningPk;
    address public agentSigner;

    bytes32 public constant CHEQUE_TYPEHASH = keccak256(
        "Cheque(address agent,address vendor,uint256 cumulativeAmount,uint256 sessionNonce,uint256 deadline)"
    );

    function setUp() public {
        deployer = address(0x111);
        treasury = address(0x222);
        insuranceReserve = address(0x333);
        finder = address(0x555);

        vendor1Pk = 0x4444;
        vendor1 = vm.addr(vendor1Pk);

        vendor2Pk = 0x6666;
        vendor2 = vm.addr(vendor2Pk);

        agentOwnerPk = 0xA11CE;
        agentOwner = vm.addr(agentOwnerPk);

        agentSigningPk = 0xB0B;
        agentSigner = vm.addr(agentSigningPk);

        vm.startPrank(deployer);
        usdc = new MockUSDC();
        vault = new PerformanceCollateralVault(address(usdc), treasury, insuranceReserve);

        usdc.mint(agentOwner, 1000 * 1e6);
        usdc.mint(finder, 1000 * 1e6);
        vm.stopPrank();

        vm.prank(agentOwner);
        usdc.approve(address(vault), type(uint256).max);

        vm.prank(finder);
        usdc.approve(address(vault), type(uint256).max);
    }

    function _signCheque(
        address agent,
        address vendor,
        uint256 cumulativeAmount,
        uint256 sessionNonce,
        uint256 deadline,
        uint256 signingKey
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, agent, vendor, cumulativeAmount, sessionNonce, deadline)
        );
        bytes32 digest = vault.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signingKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_Audit_Insolvency_Via_PendingWithdrawal_And_InstantWithdraw() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(100 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor1, 40 * 1e6);

        vault.initiateEmergencyWithdrawal(60 * 1e6);

        // Instant withdrawal of 60 must revert: 40 is allocated + 60 is pending withdrawal
        vm.expectRevert(PerformanceCollateralVault.InsufficientCollateral.selector);
        vault.instantWithdraw(60 * 1e6);
        vm.stopPrank();

        // Verify honest vendor settlement is fully protected and succeeds
        bytes memory chequeSig = _signCheque(
            agentOwner,
            vendor1,
            40 * 1e6,
            1,
            block.timestamp + 1 hours,
            agentSigningPk
        );

        vm.prank(vendor1);
        vault.settleCheque(agentOwner, 40 * 1e6, 1, block.timestamp + 1 hours, chequeSig);
        assertEq(usdc.balanceOf(vendor1), 40 * 1e6);
    }

    function test_Audit_PreAllocation_EmergencyWithdrawal_Race() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(100 * 1e6, keccak256("root"), agentSigner);
        vault.initiateEmergencyWithdrawal(100 * 1e6);

        // Attempting to allocate exposure when bond is already reserved by emergency withdrawal must revert
        vm.expectRevert(PerformanceCollateralVault.ExposureExceedsBond.selector);
        vault.allocateSessionExposure(vendor1, 100 * 1e6);
        vm.stopPrank();
    }

    function test_Audit_Slashing_Haircut_Undercollateralization() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(100 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor1, 50 * 1e6);
        vault.allocateSessionExposure(vendor2, 50 * 1e6);
        vm.stopPrank();

        assertEq(vault.totalAllocatedExposure(agentOwner), 100 * 1e6);

        bytes32 salt = bytes32(uint256(9999));
        bytes32 commitHash = keccak256(abi.encodePacked(agentSigningPk, finder, salt));

        vm.prank(finder);
        vault.commitFraudProof(agentOwner, commitHash);

        vm.roll(block.number + 5);

        PerformanceCollateralVault.SlashArgs memory args = PerformanceCollateralVault.SlashArgs({
            maliciousAgent: agentOwner,
            extractedSk: agentSigningPk,
            salt: salt
        });

        vm.prank(finder);
        vault.revealAndSlash(args);

        assertEq(vault.slashedRestitutionPool(agentOwner), 85 * 1e6);

        bytes memory cheque1 = _signCheque(agentOwner, vendor1, 50 * 1e6, 1, block.timestamp + 1 hours, agentSigningPk);
        vm.prank(vendor1);
        vault.claimSlashedRestitution(agentOwner, 50 * 1e6, 1, block.timestamp + 1 hours, cheque1);
        assertEq(usdc.balanceOf(vendor1), 50 * 1e6);

        assertEq(vault.slashedRestitutionPool(agentOwner), 35 * 1e6);

        bytes memory cheque2 = _signCheque(agentOwner, vendor2, 50 * 1e6, 1, block.timestamp + 1 hours, agentSigningPk);
        vm.prank(vendor2);
        vault.claimSlashedRestitution(agentOwner, 50 * 1e6, 1, block.timestamp + 1 hours, cheque2);
        assertEq(usdc.balanceOf(vendor2), 35 * 1e6);
    }

    function test_Audit_Settlement_Freeze_Via_SelfCommit() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(50 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor1, 20 * 1e6);
        vm.stopPrank();

        uint256 fixedDeadline = 2000;
        bytes memory chequeSig = _signCheque(agentOwner, vendor1, 20 * 1e6, 1, fixedDeadline, agentSigningPk);

        bytes32 dummyCommit = keccak256("dummy_commitment");
        vm.prank(agentOwner);
        vault.commitFraudProof(agentOwner, dummyCommit);

        vm.prank(vendor1);
        vm.expectRevert(PerformanceCollateralVault.TimelockActive.selector);
        vault.settleCheque(agentOwner, 20 * 1e6, 1, fixedDeadline, chequeSig);

        vm.warp(2001);
        vm.roll(block.number + 260);

        vm.prank(agentOwner);
        vault.cancelExpiredCommitment(dummyCommit);

        vm.prank(vendor1);
        vm.expectRevert(PerformanceCollateralVault.ChequeExpired.selector);
        vault.settleCheque(agentOwner, 20 * 1e6, 1, fixedDeadline, chequeSig);
    }
}
