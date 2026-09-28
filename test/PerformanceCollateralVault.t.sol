// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/PerformanceCollateralVault.sol";
import "../contracts/MockUSDC.sol";

contract PerformanceCollateralVaultTest is Test {
    PerformanceCollateralVault public vault;
    MockUSDC public usdc;

    address public deployer;
    address public treasury;
    address public insuranceReserve;
    uint256 public vendorPk;
    address public vendor;
    address public finder;

    uint256 public agentOwnerPk;
    address public agentOwner;

    uint256 public agentSigningPk;
    address public agentSigner;

    bytes32 public constant CHEQUE_TYPEHASH = keccak256(
        "Cheque(address agent,address vendor,uint256 cumulativeAmount,uint256 sessionNonce,uint256 deadline)"
    );

    bytes32 public constant MUTUAL_CLOSE_TYPEHASH = keccak256(
        "MutualClose(address agent,address vendor,uint256 finalSettledAmount,uint256 releasedExposure,uint256 sessionNonce,uint256 deadline)"
    );

    function setUp() public {
        deployer = address(0x1);
        treasury = address(0x2);
        insuranceReserve = address(0x3);
        finder = address(0x5);

        vendorPk = 0x4444;
        vendor = vm.addr(vendorPk);

        agentOwnerPk = 0xA11CE;
        agentOwner = vm.addr(agentOwnerPk);

        agentSigningPk = 0xB0B;
        agentSigner = vm.addr(agentSigningPk);

        vm.startPrank(deployer);
        usdc = new MockUSDC();
        vault = new PerformanceCollateralVault(address(usdc), treasury, insuranceReserve);

        // Fund agent owner with 100 USDC (6 decimals)
        usdc.mint(agentOwner, 100 * 1e6);
        vm.stopPrank();

        // Agent approves vault
        vm.prank(agentOwner);
        usdc.approve(address(vault), type(uint256).max);
    }

    function test_DepositCollateral() public {
        vm.prank(agentOwner);
        bytes32 merkleRoot = keccak256("nonce_tree_root");
        vault.depositCollateral(10 * 1e6, merkleRoot, agentSigner);

        (uint256 bond, bytes32 root, address signer, address owner,,, bool slashed) = vault.vaults(agentOwner);
        assertEq(bond, 10 * 1e6);
        assertEq(root, merkleRoot);
        assertEq(signer, agentSigner);
        assertEq(owner, agentOwner);
        assertFalse(slashed);
    }

    function test_InstantMarginRelease_ZeroSeconds() public {
        // 1. Deposit 10 USDC
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);

        // 2. Allocate 2 USDC exposure for vendor
        vault.allocateSessionExposure(vendor, 2 * 1e6);
        assertEq(vault.allocatedExposure(agentOwner), 2 * 1e6);

        // 3. Instant withdraw free unallocated capital (8 USDC) in 0 SECONDS
        uint256 balBefore = usdc.balanceOf(agentOwner);
        vault.instantWithdraw(8 * 1e6);
        uint256 balAfter = usdc.balanceOf(agentOwner);

        assertEq(balAfter - balBefore, 8 * 1e6);

        (uint256 remainingBond,,,,,,) = vault.vaults(agentOwner);
        assertEq(remainingBond, 2 * 1e6); // exactly covers active exposure

        // 4. Overdrawing active margin reverts in 0 seconds
        vm.expectRevert(PerformanceCollateralVault.InsufficientCollateral.selector);
        vault.instantWithdraw(1);
        vm.stopPrank();
    }

    function test_CooperativeSessionClose_ZeroSeconds() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 2 * 1e6);
        vm.stopPrank();

        // Vendor signs Mutual Close Receipt releasing exposure
        bytes32 structHash = keccak256(
            abi.encode(MUTUAL_CLOSE_TYPEHASH, agentOwner, vendor, 0, 2 * 1e6, 1, block.timestamp + 100)
        );
        bytes32 digest = vault.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(vendorPk, digest);
        bytes memory vendorSig = abi.encodePacked(r, s, v);

        vm.prank(agentOwner);
        vault.cooperativeCloseSession(vendor, 0, 2 * 1e6, 1, block.timestamp + 100, vendorSig);

        assertEq(vault.allocatedExposure(agentOwner), 0, "Allocated exposure reset to zero");

        // Now all remaining 10 USDC can be withdrawn instantly
        vm.prank(agentOwner);
        vault.instantWithdraw(10 * 1e6);
        (uint256 bond,,,,,,) = vault.vaults(agentOwner);
        assertEq(bond, 0);
    }

    function test_KeyDerivation_HomomorphicEcrecover() public view {
        // Test that O(1) ecrecover identity (~7,162 gas) recovers exact Ethereum address
        uint256 testSk = 0x937f9e83ca54b6d4f58c70d42fa88390885a6a3b2b115682852233f20b5f13d4;
        address expectedAddr = vm.addr(testSk);
        address derivedAddr = vault.deriveAddress(testSk);

        assertEq(derivedAddr, expectedAddr, "Homomorphic ecrecover must match secp256k1 public address");
    }

    function test_SlashingWaterfall_WithVerifiedCheque() public {
        uint256 rogueSk = 0x123456789ABCDEF;
        address rogueSigner = vm.addr(rogueSk);
        address rogueOwner = address(0x999);

        // Fund rogue agent
        vm.startPrank(deployer);
        usdc.mint(rogueOwner, 5 * 1e6);
        vm.stopPrank();

        vm.startPrank(rogueOwner);
        usdc.approve(address(vault), type(uint256).max);
        vault.depositCollateral(5 * 1e6, keccak256("root"), rogueSigner);
        vault.allocateSessionExposure(vendor, 2 * 1e6);
        vm.stopPrank();

        // Rogue agent signs 2.00 USDC cheque for vendor
        bytes32 chequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, rogueOwner, vendor, 2 * 1e6, 1, block.timestamp + 1000)
        );
        bytes32 digest = vault.hashTypedDataV4(chequeHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rogueSk, digest);
        bytes memory chequeSig = abi.encodePacked(r, s, v);

        // Phase 1: Finder commits fraud proof
        bytes32 salt = keccak256("salt_123");
        bytes32 commitHash = keccak256(abi.encodePacked(rogueSk, finder, salt));

        vm.prank(finder);
        vault.commitFraudProof(rogueOwner, commitHash);

        // Advance 2 blocks for MIN_COMMIT_DELAY
        vm.roll(block.number + 2);

        // Phase 2: Finder reveals & slashes
        uint256 finderBalBefore = usdc.balanceOf(finder);
        uint256 treasuryBalBefore = usdc.balanceOf(treasury);
        uint256 insuranceBalBefore = usdc.balanceOf(insuranceReserve);

        PerformanceCollateralVault.SlashArgs memory args = PerformanceCollateralVault.SlashArgs({
            maliciousAgent: rogueOwner,
            extractedSk: rogueSk,
            salt: salt,
            damagedVendor: vendor,
            chequeCumulativeAmount: 2 * 1e6,
            chequeSessionNonce: 1,
            chequeDeadline: block.timestamp + 1000,
            chequeSignature: chequeSig
        });

        vm.prank(finder);
        vault.revealAndSlash(args);

        // Assertions:
        // Slashed Total: $5.00
        // Vendor Damage: $2.00 (verified by cheque)
        // Remaining: $3.00
        // Finder Bounty: 15% of $5.00 = $0.75
        // Remaining for pool: $3.00 - $0.75 = $2.25
        // Insurance (60%): 60% of $2.25 = $1.35
        // Treasury (40%): 40% of $2.25 = $0.90
        assertEq(vault.claimableDamages(vendor), 2 * 1e6);
        assertEq(usdc.balanceOf(finder) - finderBalBefore, 750000);
        assertEq(usdc.balanceOf(insuranceReserve) - insuranceBalBefore, 1350000);
        assertEq(usdc.balanceOf(treasury) - treasuryBalBefore, 900000);

        // Vendor claims damage via pull pattern
        vm.prank(vendor);
        vault.claimDamage();
        assertEq(usdc.balanceOf(vendor), 2 * 1e6);
    }

    function test_SlashingWaterfall_AttackerCannotFakeDamages() public {
        uint256 rogueSk = 0x555555555;
        address rogueSigner = vm.addr(rogueSk);
        address rogueOwner = address(0x888);

        // Fund rogue agent
        vm.startPrank(deployer);
        usdc.mint(rogueOwner, 10 * 1e6);
        vm.stopPrank();

        vm.startPrank(rogueOwner);
        usdc.approve(address(vault), type(uint256).max);
        vault.depositCollateral(10 * 1e6, keccak256("root"), rogueSigner);
        vm.stopPrank();

        // Finder commits fraud proof
        bytes32 salt = keccak256("salt_finder");
        bytes32 commitHash = keccak256(abi.encodePacked(rogueSk, finder, salt));

        vm.prank(finder);
        vault.commitFraudProof(rogueOwner, commitHash);
        vm.roll(block.number + 2);

        // ATTACK: Finder attempts to pass himself as "damagedVendor" and claim 10 USDC without valid cheque signature!
        bytes memory fakeSig = new bytes(65);
        PerformanceCollateralVault.SlashArgs memory maliciousArgs = PerformanceCollateralVault.SlashArgs({
            maliciousAgent: rogueOwner,
            extractedSk: rogueSk,
            salt: salt,
            damagedVendor: finder, // trying to steal 100% of collateral!
            chequeCumulativeAmount: 10 * 1e6,
            chequeSessionNonce: 1,
            chequeDeadline: block.timestamp + 1000,
            chequeSignature: fakeSig // fake signature!
        });

        uint256 finderBalBefore = usdc.balanceOf(finder);
        uint256 insuranceBalBefore = usdc.balanceOf(insuranceReserve);
        uint256 treasuryBalBefore = usdc.balanceOf(treasury);

        vm.prank(finder);
        vault.revealAndSlash(maliciousArgs);

        // Contract DETECTED invalid cheque signature -> damage awarded = $0!
        // Finder ONLY gets legitimate 15% bounty ($1.50 USDC)!
        // Remaining $8.50 is safely protected:
        // Insurance (60% of $8.50) = $5.10 USDC
        // Treasury (40% of $8.50) = $3.40 USDC
        assertEq(vault.claimableDamages(finder), 0, "Attacker awarded ZERO fake damages!");
        assertEq(usdc.balanceOf(finder) - finderBalBefore, 1500000, "Finder receives strictly 15% bounty");
        assertEq(usdc.balanceOf(insuranceReserve) - insuranceBalBefore, 5100000, "Insurance Reserve is 100% protected");
        assertEq(usdc.balanceOf(treasury) - treasuryBalBefore, 3400000, "Treasury is 100% protected");
    }

    function testFuzz_SlashingWaterfallIntegrity(uint64 depositRaw, uint64 damageRaw) public {
        vm.assume(depositRaw >= 1e6 && depositRaw <= 1000000 * 1e6); // $1 to $1,000,000
        vm.assume(damageRaw <= depositRaw);

        uint256 deposit = uint256(depositRaw);
        uint256 damage = uint256(damageRaw);

        uint256 rogueSk = 0x999999;
        address rogueSigner = vm.addr(rogueSk);
        address rogueOwner = address(0x777);

        vm.startPrank(deployer);
        usdc.mint(rogueOwner, deposit);
        vm.stopPrank();

        vm.startPrank(rogueOwner);
        usdc.approve(address(vault), type(uint256).max);
        vault.depositCollateral(deposit, keccak256("root"), rogueSigner);
        vault.allocateSessionExposure(vendor, damage);
        vm.stopPrank();

        // Valid cheque for damage
        bytes32 chequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, rogueOwner, vendor, damage, 1, block.timestamp + 1000)
        );
        bytes32 digest = vault.hashTypedDataV4(chequeHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rogueSk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes32 salt = keccak256("salt_fuzz");
        vm.prank(finder);
        vault.commitFraudProof(rogueOwner, keccak256(abi.encodePacked(rogueSk, finder, salt)));
        vm.roll(block.number + 2);

        uint256 finderBefore = usdc.balanceOf(finder);
        uint256 insBefore = usdc.balanceOf(insuranceReserve);
        uint256 trsBefore = usdc.balanceOf(treasury);

        vm.prank(finder);
        vault.revealAndSlash(PerformanceCollateralVault.SlashArgs({
            maliciousAgent: rogueOwner,
            extractedSk: rogueSk,
            salt: salt,
            damagedVendor: vendor,
            chequeCumulativeAmount: damage,
            chequeSessionNonce: 1,
            chequeDeadline: block.timestamp + 1000,
            chequeSignature: sig
        }));

        uint256 vendorDmg = vault.claimableDamages(vendor);
        uint256 finderGain = usdc.balanceOf(finder) - finderBefore;
        uint256 insGain = usdc.balanceOf(insuranceReserve) - insBefore;
        uint256 trsGain = usdc.balanceOf(treasury) - trsBefore;

        // Conservation of Value Invariant: Sum of distributed parts == total deposited collateral
        assertEq(vendorDmg + finderGain + insGain + trsGain, deposit, "Zero loss, exact conservation of USDC");
    }

    function test_PreventKeyOverwrite() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root1"), agentSigner);

        // Depositing with a different signing address must revert
        address fakeSigner = address(0xDEADBEEF);
        vm.expectRevert(PerformanceCollateralVault.Unauthorized.selector);
        vault.depositCollateral(1 * 1e6, keccak256("root2"), fakeSigner);

        // Depositing with same signing address succeeds and accumulates bond
        vault.depositCollateral(5 * 1e6, keccak256("root3"), agentSigner);
        (uint256 bond,, address signer,,,,) = vault.vaults(agentOwner);
        assertEq(bond, 15 * 1e6);
        assertEq(signer, agentSigner);
        vm.stopPrank();
    }

    function test_InstantWithdrawBlockedDuringDispute() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vm.stopPrank();

        // Finder commits fraud proof naming agentOwner as targetAgent
        bytes32 salt = keccak256("dispute_salt");
        bytes32 commitHash = keccak256(abi.encodePacked(agentSigningPk, finder, salt));

        vm.prank(finder);
        vault.commitFraudProof(agentOwner, commitHash);

        // Agent tries to frontrun slash by withdrawing free collateral
        vm.startPrank(agentOwner);
        vm.expectRevert(PerformanceCollateralVault.TimelockActive.selector);
        vault.instantWithdraw(5 * 1e6);
        vm.stopPrank();

        // After dispute lock window (256 blocks), instantWithdraw is unblocked if not revealed
        vm.roll(block.number + 257);
        vm.prank(agentOwner);
        vault.instantWithdraw(5 * 1e6);
        (uint256 remainingBond,,,,,,) = vault.vaults(agentOwner);
        assertEq(remainingBond, 5 * 1e6);
    }

    function test_ProtocolFeeGenesisZeroAndConfigurable() public {
        // 1. Verify genesis fee is 0 bps
        assertEq(vault.protocolFeeBps(), 0);

        vm.startPrank(agentOwner);
        vault.depositCollateral(20 * 1e6, keccak256("root"), agentSigner);
        vm.stopPrank();

        // Sign cheque for 2 USDC
        bytes32 chequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, agentOwner, vendor, 2 * 1e6, 1, block.timestamp + 1000)
        );
        bytes32 digest = vault.hashTypedDataV4(chequeHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentSigningPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Settle cheque at 0 bps fee: vendor receives 100% of delta (2 USDC)
        uint256 vendorBefore = usdc.balanceOf(vendor);
        uint256 treasuryBefore = usdc.balanceOf(treasury);

        vm.prank(vendor);
        vault.settleCheque(agentOwner, 2 * 1e6, 1, block.timestamp + 1000, sig);

        assertEq(usdc.balanceOf(vendor) - vendorBefore, 2 * 1e6, "Vendor receives 100% of delta at 0 fee");
        assertEq(usdc.balanceOf(treasury) - treasuryBefore, 0, "Treasury receives 0 fee at genesis");

        // 2. Non-treasury cannot configure fee
        vm.prank(agentOwner);
        vm.expectRevert(PerformanceCollateralVault.Unauthorized.selector);
        vault.setProtocolFeeBps(5);

        // 3. Treasury cannot exceed MAX_FEE_BPS (25 bps)
        vm.startPrank(treasury);
        vm.expectRevert(PerformanceCollateralVault.FeeExceedsCap.selector);
        vault.setProtocolFeeBps(26);

        // 4. Treasury configures 5 bps promotional/standard fee
        vault.setProtocolFeeBps(5); // 5 bps = 0.05%
        assertEq(vault.protocolFeeBps(), 5);
        vm.stopPrank();

        // Sign next cheque for 12 USDC (delta = 10 USDC)
        chequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, agentOwner, vendor, 12 * 1e6, 2, block.timestamp + 1000)
        );
        digest = vault.hashTypedDataV4(chequeHash);
        (v, r, s) = vm.sign(agentSigningPk, digest);
        sig = abi.encodePacked(r, s, v);

        vendorBefore = usdc.balanceOf(vendor);
        treasuryBefore = usdc.balanceOf(treasury);

        vm.prank(vendor);
        vault.settleCheque(agentOwner, 12 * 1e6, 2, block.timestamp + 1000, sig);

        // Delta = 10 USDC (10,000,000 micro-USDC)
        // Fee = 10,000,000 * 5 / 10,000 = 5,000 micro-USDC ($0.005)
        // Vendor gets 9,995,000 micro-USDC ($9.995)
        assertEq(usdc.balanceOf(treasury) - treasuryBefore, 5000, "Treasury receives exact 5 bps fee");
        assertEq(usdc.balanceOf(vendor) - vendorBefore, 9995000, "Vendor receives delta minus fee");
    }

    function test_SlashingWaterfallGuaranteedFinderBounty() public {
        uint256 rogueSk = 0x777888999;
        address rogueSigner = vm.addr(rogueSk);
        address rogueOwner = address(0x333);

        vm.startPrank(deployer);
        usdc.mint(rogueOwner, 10 * 1e6);
        vm.stopPrank();

        vm.startPrank(rogueOwner);
        usdc.approve(address(vault), type(uint256).max);
        vault.depositCollateral(10 * 1e6, keccak256("root"), rogueSigner);
        vault.allocateSessionExposure(vendor, 10 * 1e6);
        vm.stopPrank();

        // Attacker produces a 10 USDC cheque to their vendor trying to self-slash 100% of collateral
        bytes32 chequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, rogueOwner, vendor, 10 * 1e6, 1, block.timestamp + 1000)
        );
        bytes32 digest = vault.hashTypedDataV4(chequeHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rogueSk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes32 salt = keccak256("bounty_priority_salt");
        vm.prank(finder);
        vault.commitFraudProof(rogueOwner, keccak256(abi.encodePacked(rogueSk, finder, salt)));
        vm.roll(block.number + 2);

        uint256 finderBefore = usdc.balanceOf(finder);

        vm.prank(finder);
        vault.revealAndSlash(PerformanceCollateralVault.SlashArgs({
            maliciousAgent: rogueOwner,
            extractedSk: rogueSk,
            salt: salt,
            damagedVendor: vendor,
            chequeCumulativeAmount: 10 * 1e6,
            chequeSessionNonce: 1,
            chequeDeadline: block.timestamp + 1000,
            chequeSignature: sig
        }));

        // 1. Finder bounty is guaranteed 15% ($1.50) FIRST
        assertEq(usdc.balanceOf(finder) - finderBefore, 1500000, "Finder receives guaranteed 15% bounty");

        // 2. Vendor damage is capped by remaining funds ($8.50)
        assertEq(vault.claimableDamages(vendor), 8500000, "Vendor damage capped at remaining $8.50");
    }

    function test_SlashingWaterfall_ExtractedSkCannotDrainZeroExposure() public {
        uint256 rogueSk = 0xABC999111;
        address rogueSigner = vm.addr(rogueSk);
        address rogueOwner = address(0x444);

        vm.startPrank(deployer);
        usdc.mint(rogueOwner, 10 * 1e6);
        vm.stopPrank();

        vm.startPrank(rogueOwner);
        usdc.approve(address(vault), type(uint256).max);
        vault.depositCollateral(10 * 1e6, keccak256("root"), rogueSigner);
        // NOTE: allocatedExposure is ZERO (agent did NOT allocate exposure to vendor)!
        assertEq(vault.allocatedExposure(rogueOwner), 0);
        vm.stopPrank();

        // Attacker creates a 100% cryptographically valid cheque for 10 USDC to their fake vendor
        bytes32 chequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, rogueOwner, vendor, 10 * 1e6, 1, block.timestamp + 1000)
        );
        bytes32 digest = vault.hashTypedDataV4(chequeHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rogueSk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes32 salt = keccak256("zero_exposure_salt");
        vm.prank(finder);
        vault.commitFraudProof(rogueOwner, keccak256(abi.encodePacked(rogueSk, finder, salt)));
        vm.roll(block.number + 2);

        uint256 finderBefore = usdc.balanceOf(finder);
        uint256 insBefore = usdc.balanceOf(insuranceReserve);
        uint256 trsBefore = usdc.balanceOf(treasury);

        vm.prank(finder);
        vault.revealAndSlash(PerformanceCollateralVault.SlashArgs({
            maliciousAgent: rogueOwner,
            extractedSk: rogueSk,
            salt: salt,
            damagedVendor: vendor,
            chequeCumulativeAmount: 10 * 1e6,
            chequeSessionNonce: 1,
            chequeDeadline: block.timestamp + 1000,
            chequeSignature: sig
        }));

        // INVARIANT VERIFIED:
        // 1. Damage awarded to fake vendor is STRICTLY 0 because allocatedExposure == 0!
        assertEq(vault.claimableDamages(vendor), 0, "Vendor damage strictly 0 for zero exposure");
        // 2. Finder receives 15% bounty ($1.50)
        assertEq(usdc.balanceOf(finder) - finderBefore, 1500000, "Finder receives 15% bounty");
        // 3. Remainder ($8.50) split 60% Insurance ($5.10) and 40% Treasury ($3.40)
        assertEq(usdc.balanceOf(insuranceReserve) - insBefore, 5100000, "Insurance gets 60% of remainder");
        assertEq(usdc.balanceOf(treasury) - trsBefore, 3400000, "Treasury gets 40% of remainder");
    }

    function test_CooperativeCloseBlockedDuringDispute() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 2 * 1e6);
        vm.stopPrank();

        // Dispute committed against agentOwner
        bytes32 salt = keccak256("coop_dispute_salt");
        bytes32 commitHash = keccak256(abi.encodePacked(agentSigningPk, finder, salt));

        vm.prank(finder);
        vault.commitFraudProof(agentOwner, commitHash);

        // Vendor signs mutual close
        bytes32 structHash = keccak256(
            abi.encode(MUTUAL_CLOSE_TYPEHASH, agentOwner, vendor, 0, 2 * 1e6, 1, block.timestamp + 100)
        );
        bytes32 digest = vault.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(vendorPk, digest);
        bytes memory vendorSig = abi.encodePacked(r, s, v);

        // Attempting cooperativeCloseSession during dispute must revert TimelockActive!
        vm.prank(agentOwner);
        vm.expectRevert(PerformanceCollateralVault.TimelockActive.selector);
        vault.cooperativeCloseSession(vendor, 0, 2 * 1e6, 1, block.timestamp + 100, vendorSig);
    }

    function test_CooperativeCloseSession_WithProtocolFee() public {
        // Configure 5 bps fee
        vm.prank(treasury);
        vault.setProtocolFeeBps(5);

        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 5 * 1e6);
        vm.stopPrank();

        // Vendor signs mutual close with 4 USDC settled amount (delta = 4 USDC)
        bytes32 structHash = keccak256(
            abi.encode(MUTUAL_CLOSE_TYPEHASH, agentOwner, vendor, 4 * 1e6, 5 * 1e6, 1, block.timestamp + 100)
        );
        bytes32 digest = vault.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(vendorPk, digest);
        bytes memory vendorSig = abi.encodePacked(r, s, v);

        uint256 vendorBefore = usdc.balanceOf(vendor);
        uint256 trsBefore = usdc.balanceOf(treasury);

        vm.prank(agentOwner);
        vault.cooperativeCloseSession(vendor, 4 * 1e6, 5 * 1e6, 1, block.timestamp + 100, vendorSig);

        // Delta = 4 USDC (4,000,000 micro-USDC)
        // Fee = 4,000,000 * 5 / 10,000 = 2,000 micro-USDC ($0.002)
        // Vendor gets 3,998,000 micro-USDC ($3.998)
        assertEq(usdc.balanceOf(treasury) - trsBefore, 2000, "Treasury receives 5 bps fee on close");
        assertEq(usdc.balanceOf(vendor) - vendorBefore, 3998000, "Vendor receives delta minus fee on close");
    }
}
