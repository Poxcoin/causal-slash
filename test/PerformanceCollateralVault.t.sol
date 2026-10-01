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
        // Fund finder with 100 USDC (for commit bonds)
        usdc.mint(finder, 100 * 1e6);
        vm.stopPrank();

        // Agent approves vault
        vm.prank(agentOwner);
        usdc.approve(address(vault), type(uint256).max);

        // Finder approves vault
        vm.prank(finder);
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
            salt: salt
        });

        vm.prank(finder);
        vault.revealAndSlash(args);

        // Assertions:
        // Slashed Total: $5.00
        // Finder Bounty: 15% of $5.00 = $0.75 + $1.00 COMMIT_BOND returned = +$1.75
        // Total reserved for vendor restitution: $2.00
        // Remaining unallocated for pool: $5.00 - $0.75 - $2.00 = $2.25
        // Insurance (60%): 60% of $2.25 = $1.35
        // Treasury (40%): 40% of $2.25 = $0.90
        assertEq(usdc.balanceOf(finder) - finderBalBefore, 750000 + 1 * 1e6);
        assertEq(vault.slashedRestitutionPool(rogueOwner), 2 * 1e6);
        assertEq(usdc.balanceOf(insuranceReserve) - insuranceBalBefore, 1350000);
        assertEq(usdc.balanceOf(treasury) - treasuryBalBefore, 900000);

        // Vendor claims restitution with valid cheque
        uint256 vendorBefore = usdc.balanceOf(vendor);
        vm.prank(vendor);
        vault.claimSlashedRestitution(rogueOwner, 2 * 1e6, 1, block.timestamp + 1000, chequeSig);
        assertEq(usdc.balanceOf(vendor) - vendorBefore, 2 * 1e6);
        assertEq(vault.slashedRestitutionPool(rogueOwner), 0);
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

        // Finder reveals and slashes
        vm.prank(finder);
        vault.revealAndSlash(PerformanceCollateralVault.SlashArgs({
            maliciousAgent: rogueOwner,
            extractedSk: rogueSk,
            salt: salt
        }));

        // ATTACK: Finder or attacker attempts to call claimSlashedRestitution for an address with 0 allocated exposure!
        bytes memory fakeSig = new bytes(65);
        vm.prank(finder);
        vm.expectRevert(PerformanceCollateralVault.InsufficientCollateral.selector);
        vault.claimSlashedRestitution(rogueOwner, 10 * 1e6, 1, block.timestamp + 1000, fakeSig);
    }

    function testFuzz_SlashingWaterfallIntegrity(uint64 depositRaw, uint64 damageRaw) public {
        vm.assume(depositRaw >= 2 * 1e6 && depositRaw <= 1000000 * 1e6); // $2 to $1,000,000
        uint256 deposit = uint256(depositRaw);
        uint256 damage = (deposit * 30) / 100; // 30% exposure allocated to vendor
        vm.assume(damage > 0 && damage <= (deposit * 85) / 100);

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
            salt: salt
        }));

        // Vendor claims damage
        uint256 vendorBefore = usdc.balanceOf(vendor);
        vm.prank(vendor);
        vault.claimSlashedRestitution(rogueOwner, damage, 1, block.timestamp + 1000, sig);

        uint256 vendorDmg = usdc.balanceOf(vendor) - vendorBefore;
        uint256 finderGain = (usdc.balanceOf(finder) - finderBefore) - 1 * 1e6; // minus returned commit bond
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
        assertEq(vault.protocolFeeBps(), 0);

        vm.startPrank(agentOwner);
        vault.depositCollateral(20 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 15 * 1e6);
        vm.stopPrank();

        // Sign cheque for 2 USDC
        bytes32 chequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, agentOwner, vendor, 2 * 1e6, 1, block.timestamp + 1000)
        );
        bytes32 digest = vault.hashTypedDataV4(chequeHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentSigningPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Settle cheque at 0 bps fee
        uint256 vendorBefore = usdc.balanceOf(vendor);
        uint256 treasuryBefore = usdc.balanceOf(treasury);

        vm.prank(vendor);
        vault.settleCheque(agentOwner, 2 * 1e6, 1, block.timestamp + 1000, sig);

        assertEq(usdc.balanceOf(vendor) - vendorBefore, 2 * 1e6, "Vendor receives 100% of delta at 0 fee");
        assertEq(usdc.balanceOf(treasury) - treasuryBefore, 0, "Treasury receives 0 fee at genesis");

        // Non-treasury cannot configure fee
        vm.prank(agentOwner);
        vm.expectRevert(PerformanceCollateralVault.Unauthorized.selector);
        vault.setProtocolFeeBps(5);

        // Treasury cannot exceed MAX_FEE_BPS (25 bps)
        vm.startPrank(treasury);
        vm.expectRevert(PerformanceCollateralVault.FeeExceedsCap.selector);
        vault.setProtocolFeeBps(26);

        // Treasury configures 5 bps promotional/standard fee
        vault.setProtocolFeeBps(5);
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

        bytes32 salt = keccak256("bounty_priority_salt");
        vm.prank(finder);
        vault.commitFraudProof(rogueOwner, keccak256(abi.encodePacked(rogueSk, finder, salt)));
        vm.roll(block.number + 2);

        uint256 finderBefore = usdc.balanceOf(finder);

        vm.prank(finder);
        vault.revealAndSlash(PerformanceCollateralVault.SlashArgs({
            maliciousAgent: rogueOwner,
            extractedSk: rogueSk,
            salt: salt
        }));

        // 1. Finder bounty is guaranteed 15% ($1.50) + 1 USDC bond return
        assertEq(usdc.balanceOf(finder) - finderBefore, 1500000 + 1 * 1e6, "Finder receives guaranteed 15% bounty + bond");
        // 2. Restitution pool is capped by remaining funds ($8.50)
        assertEq(vault.slashedRestitutionPool(rogueOwner), 8500000, "Restitution pool capped at remaining $8.50");
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
        assertEq(vault.allocatedExposure(rogueOwner), 0);
        vm.stopPrank();

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
            salt: salt
        }));

        // Because totalAllocatedExposure was 0, restitution pool is strictly 0!
        assertEq(vault.slashedRestitutionPool(rogueOwner), 0);
        assertEq(usdc.balanceOf(finder) - finderBefore, 1500000 + 1 * 1e6);
        assertEq(usdc.balanceOf(insuranceReserve) - insBefore, 5100000);
        assertEq(usdc.balanceOf(treasury) - trsBefore, 3400000);
    }

    function test_CooperativeCloseBlockedDuringDispute() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 2 * 1e6);
        vm.stopPrank();

        bytes32 salt = keccak256("coop_dispute_salt");
        bytes32 commitHash = keccak256(abi.encodePacked(agentSigningPk, finder, salt));

        vm.prank(finder);
        vault.commitFraudProof(agentOwner, commitHash);

        bytes32 structHash = keccak256(
            abi.encode(MUTUAL_CLOSE_TYPEHASH, agentOwner, vendor, 0, 2 * 1e6, 1, block.timestamp + 100)
        );
        bytes32 digest = vault.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(vendorPk, digest);
        bytes memory vendorSig = abi.encodePacked(r, s, v);

        vm.prank(agentOwner);
        vm.expectRevert(PerformanceCollateralVault.TimelockActive.selector);
        vault.cooperativeCloseSession(vendor, 0, 2 * 1e6, 1, block.timestamp + 100, vendorSig);
    }

    function test_CooperativeCloseSession_WithProtocolFee() public {
        vm.prank(treasury);
        vault.setProtocolFeeBps(5);

        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 5 * 1e6);
        vm.stopPrank();

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

        assertEq(usdc.balanceOf(treasury) - trsBefore, 2000, "Treasury receives 5 bps fee on close");
        assertEq(usdc.balanceOf(vendor) - vendorBefore, 3998000, "Vendor receives delta minus fee on close");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW SECURITY EXPLOIT MITIGATION TESTS (Claude Code Audit Findings)
    // ─────────────────────────────────────────────────────────────────────────

    function test_AntiSelfSlashing_AccompliceCannotStealHonestVendorQuota() public {
        // Honest vendor gets $4 allocation
        address honestVendor = vendor;
        // Rogue agent sets up an accomplice address
        address accomplice = address(0x9999);

        uint256 rogueSk = 0xDEAD123;
        address rogueSigner = vm.addr(rogueSk);
        address rogueOwner = address(0x555);

        vm.startPrank(deployer);
        usdc.mint(rogueOwner, 10 * 1e6);
        vm.stopPrank();

        vm.startPrank(rogueOwner);
        usdc.approve(address(vault), type(uint256).max);
        vault.depositCollateral(10 * 1e6, keccak256("root"), rogueSigner);
        // Allocate $4 to honest vendor
        vault.allocateSessionExposure(honestVendor, 4 * 1e6);
        vm.stopPrank();

        // Honest vendor served services and holds 3 USDC cheque
        bytes32 honestChequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, rogueOwner, honestVendor, 3 * 1e6, 1, block.timestamp + 1000)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rogueSk, vault.hashTypedDataV4(honestChequeHash));
        bytes memory honestSig = abi.encodePacked(r, s, v);

        // Rogue agent triggers slashing via finder
        bytes32 salt = keccak256("self_slash_salt");
        vm.prank(finder);
        vault.commitFraudProof(rogueOwner, keccak256(abi.encodePacked(rogueSk, finder, salt)));
        vm.roll(block.number + 2);

        vm.prank(finder);
        vault.revealAndSlash(PerformanceCollateralVault.SlashArgs({
            maliciousAgent: rogueOwner,
            extractedSk: rogueSk,
            salt: salt
        }));

        // ATTACK: Accomplice tries to claim honest vendor's exposure using a cheque signed by rogueSk!
        bytes32 accompliceChequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, rogueOwner, accomplice, 4 * 1e6, 1, block.timestamp + 1000)
        );
        (v, r, s) = vm.sign(rogueSk, vault.hashTypedDataV4(accompliceChequeHash));
        bytes memory accompliceSig = abi.encodePacked(r, s, v);

        vm.prank(accomplice);
        // REVERTS because accomplice has 0 pre-allocated exposure!
        vm.expectRevert(PerformanceCollateralVault.InsufficientCollateral.selector);
        vault.claimSlashedRestitution(rogueOwner, 4 * 1e6, 1, block.timestamp + 1000, accompliceSig);

        // Honest vendor claims restitution successfully!
        uint256 honestBefore = usdc.balanceOf(honestVendor);
        vm.prank(honestVendor);
        vault.claimSlashedRestitution(rogueOwner, 3 * 1e6, 1, block.timestamp + 1000, honestSig);
        assertEq(usdc.balanceOf(honestVendor) - honestBefore, 3 * 1e6, "Honest vendor successfully reimbursed");
    }

    function test_AntiGriefingDoS_CommitmentRequiresBondAndBurnsOnTimeout() public {
        address griefer = address(0x666);
        vm.startPrank(deployer);
        usdc.mint(griefer, 5 * 1e6);
        vm.stopPrank();

        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vm.stopPrank();

        bytes32 junkHash = keccak256("junk");

        // Griefer tries to commit without approving USDC bond -> reverts
        vm.prank(griefer);
        vm.expectRevert();
        vault.commitFraudProof(agentOwner, junkHash);

        // Griefer approves and deposits 1 USDC COMMIT_BOND
        vm.prank(griefer);
        usdc.approve(address(vault), 1 * 1e6);

        vm.prank(griefer);
        vault.commitFraudProof(agentOwner, junkHash);

        // Target agent's instant withdrawal is temporarily locked
        vm.prank(agentOwner);
        vm.expectRevert(PerformanceCollateralVault.TimelockActive.selector);
        vault.instantWithdraw(5 * 1e6);

        // Griefer does NOT reveal within 256 blocks (fake commit)
        vm.roll(block.number + 257);

        // Anyone (e.g. agent) cancels expired commitment
        uint256 insBefore = usdc.balanceOf(insuranceReserve);
        vault.cancelExpiredCommitment(junkHash);

        // Griefer's 1 USDC bond was forfeited to insurance reserve!
        assertEq(usdc.balanceOf(insuranceReserve) - insBefore, 1 * 1e6, "Griefer bond forfeited to insurance");

        // Agent's instant withdrawal is immediately unblocked!
        vm.prank(agentOwner);
        vault.instantWithdraw(5 * 1e6);
        (uint256 bond,,,,,,) = vault.vaults(agentOwner);
        assertEq(bond, 5 * 1e6);
    }

    function test_NoPhantomExposureAccumulation() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        // Allocate 5 USDC to vendor
        vault.allocateSessionExposure(vendor, 5 * 1e6);
        assertEq(vault.allocatedExposure(agentOwner), 5 * 1e6);
        assertEq(vault.vendorExposure(agentOwner, vendor), 5 * 1e6);
        vm.stopPrank();

        // Vendor settles 3 USDC cheque
        bytes32 chequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, agentOwner, vendor, 3 * 1e6, 1, block.timestamp + 1000)
        );
        bytes32 digest = vault.hashTypedDataV4(chequeHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentSigningPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(vendor);
        vault.settleCheque(agentOwner, 3 * 1e6, 1, block.timestamp + 1000, sig);

        // Invariant: settling delta reduces allocated exposure to prevent phantom lock
        assertEq(vault.allocatedExposure(agentOwner), 2 * 1e6, "Total allocated exposure reduced by settled delta");
        assertEq(vault.vendorExposure(agentOwner, vendor), 2 * 1e6, "Vendor exposure reduced by settled delta");

        // Free collateral is now 7 USDC (Bond was 10 - 3 = 7, allocated is 2, free = 5)
        vm.prank(agentOwner);
        vault.instantWithdraw(5 * 1e6);
        (uint256 remainingBond,,,,,,) = vault.vaults(agentOwner);
        assertEq(remainingBond, 2 * 1e6);
    }

    function test_SettleChequeBlockedDuringDispute() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 5 * 1e6);
        vm.stopPrank();

        // Sign a valid 4 USDC cheque
        bytes32 chequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, agentOwner, vendor, 4 * 1e6, 1, block.timestamp + 1000)
        );
        bytes32 digest = vault.hashTypedDataV4(chequeHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentSigningPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Commit fraud proof against agent
        bytes32 commitHash = keccak256("fraud_commit_hash");
        vm.prank(finder);
        vault.commitFraudProof(agentOwner, commitHash);

        // Attempt to drain collateral via settleCheque during dispute window
        vm.prank(vendor);
        vm.expectRevert(PerformanceCollateralVault.TimelockActive.selector);
        vault.settleCheque(agentOwner, 4 * 1e6, 1, block.timestamp + 1000, sig);
    }

    function test_SweepUnclaimedRestitution_RequiresEmergencyDisputePeriod() public {
        uint256 rogueSk = 0xC0FFEE;
        address rogueSigner = vault.deriveAddress(rogueSk);
        address rogueOwner = address(0x999);

        vm.startPrank(deployer);
        usdc.mint(rogueOwner, 100 * 1e6);
        vm.stopPrank();

        vm.startPrank(rogueOwner);
        usdc.approve(address(vault), type(uint256).max);
        vault.depositCollateral(10 * 1e6, keccak256("root"), rogueSigner);
        vault.allocateSessionExposure(vendor, 5 * 1e6);
        vm.stopPrank();

        // Whistleblower commits fraud proof
        bytes32 salt = keccak256("salt_sweep_test");
        bytes32 commitHash = keccak256(abi.encodePacked(rogueSk, finder, salt));
        vm.prank(finder);
        vault.commitFraudProof(rogueOwner, commitHash);

        vm.roll(block.number + 2);

        // Foreclose via revealAndSlash
        vm.prank(finder);
        vault.revealAndSlash(PerformanceCollateralVault.SlashArgs({
            maliciousAgent: rogueOwner,
            extractedSk: rogueSk,
            salt: salt
        }));

        // Invariant: restitution pool contains 5 USDC allocated exposure
        assertEq(vault.slashedRestitutionPool(rogueOwner), 5 * 1e6);

        // MEV bot or frontrunner immediately tries to sweep unclaimed restitution
        address mevBot = address(0xDEADBEEF);
        vm.prank(mevBot);
        vm.expectRevert(PerformanceCollateralVault.TimelockActive.selector);
        vault.sweepUnclaimedRestitution(rogueOwner);

        // Fast forward 3 hours 59 minutes (still in dispute period)
        vm.warp(block.timestamp + 4 hours - 1);
        vm.prank(mevBot);
        vm.expectRevert(PerformanceCollateralVault.TimelockActive.selector);
        vault.sweepUnclaimedRestitution(rogueOwner);

        // Fast forward past the 4-hour emergency dispute period
        vm.warp(block.timestamp + 1);
        uint256 insBefore = usdc.balanceOf(insuranceReserve);
        uint256 tresBefore = usdc.balanceOf(treasury);

        vm.prank(mevBot);
        vault.sweepUnclaimedRestitution(rogueOwner);

        // Pool is now empty
        assertEq(vault.slashedRestitutionPool(rogueOwner), 0);
        // 60% of 5 USDC = 3 USDC to insurance, 40% = 2 USDC to treasury
        assertEq(usdc.balanceOf(insuranceReserve) - insBefore, 3 * 1e6);
        assertEq(usdc.balanceOf(treasury) - tresBefore, 2 * 1e6);
    }

    function test_EmergencyWithdrawalBlockedDuringDispute() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        // Initiate emergency withdrawal of 5 USDC
        vault.initiateEmergencyWithdrawal(5 * 1e6);
        vm.stopPrank();

        // 3 hours later, fraud is committed against the agent
        vm.warp(block.timestamp + 3 hours);
        bytes32 commitHash = keccak256("commit_during_emergency");
        vm.prank(finder);
        vault.commitFraudProof(agentOwner, commitHash);

        // 4 hours have passed since initiateEmergencyWithdrawal, but disputeLock is active
        vm.warp(block.timestamp + 2 hours);
        vm.prank(agentOwner);
        vm.expectRevert(PerformanceCollateralVault.TimelockActive.selector);
        vault.finalizeEmergencyWithdrawal();
    }

    function _generateSchnorrCheque(
        uint64 channelHeight,
        uint64 cumulativeAmountUSDC,
        uint256 nonceK
    ) internal view returns (
        bytes32 agentPubX,
        bytes32 agentPubY,
        bytes32 vendorPubX,
        bytes32 vendorPubY,
        bytes32 challengeE,
        bytes32 sigS
    ) {
        agentPubX = 0x5d45cb81aa765d69ca52e3869491ecf0e8fdf6a63d64e65b5213647ee4973ae5;
        agentPubY = 0xa4a4a32b51a76d77773517e7c103a7dcfdab36fe3cafa2bdb17f82b12fd019db;
        vendorPubX = 0x71550e6c83a9381f35c568d1a80e11fa3e0efc97dfd0e0f17492a2edb64c37a9;
        vendorPubY = 0xb9043eebf5c3fece2bc13ccd260914ef4a220a55782ab6f6744bcd7aa4d5e2d6;

        uint8 agentPrefix = 0x03;
        uint8 vendorPrefix = 0x02;
        bytes memory preimage = abi.encodePacked(
            agentPrefix, agentPubX,
            vendorPrefix, vendorPubX,
            channelHeight,
            cumulativeAmountUSDC
        );
        uint256 N = vault.SECP256K1_N();
        challengeE = bytes32(uint256(sha256(preimage)) % N);
        uint256 s = addmod(nonceK, mulmod(uint256(challengeE), agentSigningPk, N), N);
        sigS = bytes32(s);
    }

    function test_OptimisticSchnorr_HappyPath_AfterDisputePeriod() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 5 * 1e6);
        vm.stopPrank();

        // Mint USDC to vendor for commit bond
        vm.prank(deployer);
        usdc.mint(vendor, 10 * 1e6);
        vm.prank(vendor);
        usdc.approve(address(vault), type(uint256).max);

        uint256 nonceK = 0x123456789ABCDEF;
        (
            bytes32 aPubX, bytes32 aPubY,
            bytes32 vPubX, bytes32 vPubY,
            bytes32 e, bytes32 s
        ) = _generateSchnorrCheque(1, 2 * 1e6, nonceK);

        // Vendor commits cheque
        vm.prank(vendor);
        vault.commitSchnorrCheque(agentOwner, aPubX, aPubY, vPubX, vPubY, 1, 2 * 1e6, e, s);

        // Verify 1 USDC bond deducted from vendor
        assertEq(usdc.balanceOf(vendor), 9 * 1e6);

        // Agent cannot instantWithdraw during dispute lock
        vm.prank(agentOwner);
        vm.expectRevert(PerformanceCollateralVault.TimelockActive.selector);
        vault.instantWithdraw(1 * 1e6);

        // Cannot finalize before 4 hours
        vm.warp(block.timestamp + 3 hours);
        vm.prank(vendor);
        vm.expectRevert(PerformanceCollateralVault.TimelockActive.selector);
        vault.finalizeSchnorrCheque(agentOwner, vendor);

        // Warp past 4 hours dispute period
        vm.warp(block.timestamp + 2 hours);
        vm.prank(vendor);
        vault.finalizeSchnorrCheque(agentOwner, vendor);

        // Vendor received 2 USDC earned + 1 USDC bond refund = 12 USDC total
        assertEq(usdc.balanceOf(vendor), 12 * 1e6);
        (uint256 remainingBond,,,,,,) = vault.vaults(agentOwner);
        assertEq(remainingBond, 8 * 1e6);
        assertEq(vault.settledAmounts(agentOwner, vendor), 2 * 1e6);
        assertEq(vault.lastSessionNonces(agentOwner, vendor), 1);
        // Quota relieved: 5 USDC - 2 USDC = 3 USDC
        assertEq(vault.vendorExposure(agentOwner, vendor), 3 * 1e6);
    }

    function test_OptimisticSchnorr_CooperativeImmediateConfirmation() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 5 * 1e6);
        vm.stopPrank();

        vm.prank(deployer);
        usdc.mint(vendor, 10 * 1e6);
        vm.prank(vendor);
        usdc.approve(address(vault), type(uint256).max);

        (
            bytes32 aPubX, bytes32 aPubY,
            bytes32 vPubX, bytes32 vPubY,
            bytes32 e, bytes32 s
        ) = _generateSchnorrCheque(1, 4 * 1e6, 0xABCDEF112233);

        vm.prank(vendor);
        vault.commitSchnorrCheque(agentOwner, aPubX, aPubY, vPubX, vPubY, 1, 4 * 1e6, e, s);

        // Agent cooperatively finalizes immediately in 0 SECONDS
        vm.prank(agentOwner);
        vault.finalizeSchnorrCheque(agentOwner, vendor);

        assertEq(usdc.balanceOf(vendor), 14 * 1e6); // 9 USDC + 4 USDC delta + 1 USDC bond refund
        assertEq(vault.settledAmounts(agentOwner, vendor), 4 * 1e6);
    }

    function test_OptimisticSchnorr_DisputeWithMutualClose_ForfeitsVendorBond() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 5 * 1e6);
        vm.stopPrank();

        vm.prank(deployer);
        usdc.mint(vendor, 10 * 1e6);
        vm.prank(vendor);
        usdc.approve(address(vault), type(uint256).max);

        (
            bytes32 aPubX, bytes32 aPubY,
            bytes32 vPubX, bytes32 vPubY,
            bytes32 e, bytes32 s
        ) = _generateSchnorrCheque(1, 2 * 1e6, 0x111);

        vm.prank(vendor);
        vault.commitSchnorrCheque(agentOwner, aPubX, aPubY, vPubX, vPubY, 1, 2 * 1e6, e, s);

        // Agent possesses vendor-signed MutualClose at higher nonce 2
        bytes32 structHash = keccak256(
            abi.encode(MUTUAL_CLOSE_TYPEHASH, agentOwner, vendor, 2 * 1e6, 0, 2, block.timestamp + 1000)
        );
        (uint8 v, bytes32 r, bytes32 sigS_ec) = vm.sign(vendorPk, vault.hashTypedDataV4(structHash));
        bytes memory vendorSig = abi.encodePacked(r, sigS_ec, v);

        uint256 agentBalBefore = usdc.balanceOf(agentOwner);

        // Agent disputes commit with MutualClose
        vm.prank(agentOwner);
        vault.disputeCommitWithMutualClose(vendor, 2 * 1e6, 0, 2, block.timestamp + 1000, vendorSig);

        // Vendor's 1 USDC commit bond forfeited to agentOwner
        assertEq(usdc.balanceOf(agentOwner) - agentBalBefore, 1 * 1e6);

        // Finalize now reverts (commitment was disputed/cancelled)
        vm.warp(block.timestamp + 5 hours);
        vm.prank(vendor);
        vm.expectRevert(PerformanceCollateralVault.NoActiveCommitment.selector);
        vault.finalizeSchnorrCheque(agentOwner, vendor);
    }

    function test_OptimisticSchnorr_DisputeForgedScalarWithNonce_ForfeitsVendorBond() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 5 * 1e6);
        vm.stopPrank();

        vm.prank(deployer);
        usdc.mint(vendor, 10 * 1e6);
        vm.prank(vendor);
        usdc.approve(address(vault), type(uint256).max);

        uint256 realNonceK = 0x55555555;
        (
            bytes32 aPubX, bytes32 aPubY,
            bytes32 vPubX, bytes32 vPubY,
            bytes32 e,
        ) = _generateSchnorrCheque(1, 3 * 1e6, realNonceK);

        // Rogue vendor commits FORGED scalar s
        bytes32 forgedS = bytes32(uint256(0x999999999999));
        vm.prank(vendor);
        vault.commitSchnorrCheque(agentOwner, aPubX, aPubY, vPubX, vPubY, 1, 3 * 1e6, e, forgedS);

        uint256 agentBalBefore = usdc.balanceOf(agentOwner);

        // Agent reveals nonce k to mathematically prove scalar forgery
        vm.prank(agentOwner);
        vault.disputeCommitWithNonce(vendor, realNonceK);

        // Bond forfeited to agent as restitution
        assertEq(usdc.balanceOf(agentOwner) - agentBalBefore, 1 * 1e6);
    }

    function test_OptimisticSchnorr_DisputeWithNonce_FailsIfSignatureGenuine() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 5 * 1e6);
        vm.stopPrank();

        vm.prank(deployer);
        usdc.mint(vendor, 10 * 1e6);
        vm.prank(vendor);
        usdc.approve(address(vault), type(uint256).max);

        uint256 realNonceK = 0x7777777;
        (
            bytes32 aPubX, bytes32 aPubY,
            bytes32 vPubX, bytes32 vPubY,
            bytes32 e, bytes32 s
        ) = _generateSchnorrCheque(1, 3 * 1e6, realNonceK);

        // Honest vendor commits genuine cheque
        vm.prank(vendor);
        vault.commitSchnorrCheque(agentOwner, aPubX, aPubY, vPubX, vPubY, 1, 3 * 1e6, e, s);

        // Malicious agent attempts to falsely dispute valid signature
        vm.prank(agentOwner);
        vm.expectRevert(PerformanceCollateralVault.InvalidSignature.selector);
        vault.disputeCommitWithNonce(vendor, realNonceK);
    }

    function test_OptimisticSchnorr_Monotonic_And_HashMismatch_Rejections() public {
        vm.startPrank(agentOwner);
        vault.depositCollateral(10 * 1e6, keccak256("root"), agentSigner);
        vault.allocateSessionExposure(vendor, 5 * 1e6);
        vm.stopPrank();

        vm.prank(deployer);
        usdc.mint(vendor, 10 * 1e6);
        vm.prank(vendor);
        usdc.approve(address(vault), type(uint256).max);

        (
            bytes32 aPubX, bytes32 aPubY,
            bytes32 vPubX, bytes32 vPubY,
            bytes32 e, bytes32 s
        ) = _generateSchnorrCheque(1, 2 * 1e6, 0x123);

        // 1. Corrupted challenge hash reverts with HashMismatch
        vm.prank(vendor);
        vm.expectRevert(PerformanceCollateralVault.HashMismatch.selector);
        vault.commitSchnorrCheque(agentOwner, aPubX, aPubY, vPubX, vPubY, 1, 2 * 1e6, bytes32(uint256(e) ^ 0xFF), s);

        // Settle a genuine cheque at height 5 for 3 USDC via ECDSA settleCheque
        bytes32 structHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, agentOwner, vendor, 3 * 1e6, 5, block.timestamp + 1000)
        );
        (uint8 v, bytes32 r, bytes32 sigS_ec) = vm.sign(agentSigningPk, vault.hashTypedDataV4(structHash));
        vm.prank(vendor);
        vault.settleCheque(agentOwner, 3 * 1e6, 5, block.timestamp + 1000, abi.encodePacked(r, sigS_ec, v));

        // 2. Committing height <= lastSessionNonce (h=5) reverts with InvalidSessionNonce
        (
            bytes32 aPubX2, bytes32 aPubY2,
            bytes32 vPubX2, bytes32 vPubY2,
            bytes32 e2, bytes32 s2
        ) = _generateSchnorrCheque(5, 4 * 1e6, 0x456);

        vm.prank(vendor);
        vm.expectRevert(PerformanceCollateralVault.InvalidSessionNonce.selector);
        vault.commitSchnorrCheque(agentOwner, aPubX2, aPubY2, vPubX2, vPubY2, 5, 4 * 1e6, e2, s2);

        // 3. Committing cumulativeAmount <= settledAmounts (3 USDC) reverts with NothingToSettle
        (
            bytes32 aPubX3, bytes32 aPubY3,
            bytes32 vPubX3, bytes32 vPubY3,
            bytes32 e3, bytes32 s3
        ) = _generateSchnorrCheque(6, 2 * 1e6, 0x789);

        vm.prank(vendor);
        vm.expectRevert(PerformanceCollateralVault.NothingToSettle.selector);
        vault.commitSchnorrCheque(agentOwner, aPubX3, aPubY3, vPubX3, vPubY3, 6, 2 * 1e6, e3, s3);
    }
}
