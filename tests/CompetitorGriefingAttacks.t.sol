// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/PerformanceCollateralVault.sol";
import "../contracts/MockUSDC.sol";

contract CompetitorGriefingAttacksTest is Test {
    PerformanceCollateralVault public vault;
    MockUSDC public usdc;

    address public deployer;
    address public treasury;
    address public insuranceReserve;

    uint256 public honestAgentSigningPk;
    address public honestAgentSigner;
    address public honestAgentOwner;

    uint256 public honestVendorPk;
    address public honestVendor;

    address public competitorSybil1;
    address public competitorSybil2;
    address public competitorSybil3;
    address public competitorMEVBot;

    bytes32 public constant CHEQUE_TYPEHASH = keccak256(
        "Cheque(address agent,address vendor,uint256 cumulativeAmount,uint256 sessionNonce,uint256 deadline)"
    );

    function setUp() public {
        deployer = address(0x101);
        treasury = address(0x102);
        insuranceReserve = address(0x103);

        honestAgentSigningPk = 0xAA11;
        honestAgentSigner = vm.addr(honestAgentSigningPk);
        honestAgentOwner = address(0xAA22);

        honestVendorPk = 0xBB11;
        honestVendor = vm.addr(honestVendorPk);

        competitorSybil1 = address(0xCC01);
        competitorSybil2 = address(0xCC02);
        competitorSybil3 = address(0xCC03);
        competitorMEVBot = address(0xEE01);

        vm.startPrank(deployer);
        usdc = new MockUSDC();
        vault = new PerformanceCollateralVault(address(usdc), treasury, insuranceReserve);

        // Fund honest agent with $100,000 USDC
        usdc.mint(honestAgentOwner, 100_000 * 1e6);

        // Fund competitor sybils with $10 USDC each for griefing attempts
        usdc.mint(competitorSybil1, 10 * 1e6);
        usdc.mint(competitorSybil2, 10 * 1e6);
        usdc.mint(competitorSybil3, 10 * 1e6);
        usdc.mint(competitorMEVBot, 10 * 1e6);
        vm.stopPrank();

        vm.prank(honestAgentOwner);
        usdc.approve(address(vault), type(uint256).max);

        vm.prank(competitorSybil1);
        usdc.approve(address(vault), type(uint256).max);

        vm.prank(competitorSybil2);
        usdc.approve(address(vault), type(uint256).max);

        vm.prank(competitorSybil3);
        usdc.approve(address(vault), type(uint256).max);

        vm.prank(competitorMEVBot);
        usdc.approve(address(vault), type(uint256).max);
    }

    /// ATTACK 1: Rolling Commit Griefing
    /// Competitor attempts to lock honest agent's $100,000 collateral indefinitely using fake commitments.
    /// Demonstrates that each griefing window costs competitor 1 USDC burned to insurance reserve,
    /// and honest agent unfreezes full collateral upon expiration with zero fund loss.
    function test_Competitor_RollingCommitGriefing_DrainsAttackerCapital() public {
        vm.prank(honestAgentOwner);
        vault.depositCollateral(100_000 * 1e6, keccak256("root"), honestAgentSigner);

        bytes32 fakeCommit1 = keccak256("fake_commit_1");
        bytes32 fakeCommit2 = keccak256("fake_commit_2");

        // Round 1: Sybil 1 commits fake fraud proof
        uint256 initialInsurance = usdc.balanceOf(insuranceReserve);
        vm.prank(competitorSybil1);
        vault.commitFraudProof(honestAgentOwner, fakeCommit1);

        // Verify Sybil 1 paid 1 USDC bond
        assertEq(usdc.balanceOf(competitorSybil1), 9 * 1e6);

        // Sybil 2 attempts simultaneous commit to extend lock, but gets rejected by active timelock
        vm.prank(competitorSybil2);
        vm.expectRevert(PerformanceCollateralVault.TimelockActive.selector);
        vault.commitFraudProof(honestAgentOwner, fakeCommit2);

        // Fast forward 257 blocks past MAX_COMMIT_WINDOW (256 blocks)
        vm.roll(block.number + 257);

        // Honest agent or keeper cancels expired commitment
        vm.prank(honestAgentOwner);
        vault.cancelExpiredCommitment(fakeCommit1);

        // Competitor's 1 USDC bond was forfeited directly to protocol insurance reserve
        assertEq(usdc.balanceOf(insuranceReserve) - initialInsurance, 1 * 1e6);

        // Honest agent can immediately withdraw 100% of collateral ($100,000 USDC)
        uint256 balBefore = usdc.balanceOf(honestAgentOwner);
        vm.prank(honestAgentOwner);
        vault.instantWithdraw(100_000 * 1e6);
        assertEq(usdc.balanceOf(honestAgentOwner) - balBefore, 100_000 * 1e6);
    }

    /// ATTACK 2: MEV Frontrunning Bounty Hijacking
    /// Honest finder uncovers equivocation. Predatory MEV bot monitors mempool to hijack 15% bounty ($15,000 USDC).
    /// Proves cryptographic binding prevents MEV bot from claiming bounty or revealing someone else's commitment.
    function test_Competitor_MEVBot_CannotFrontrunBounty() public {
        uint256 rogueSk = 0xCAFE;
        address rogueSigner = vault.deriveAddress(rogueSk);
        address rogueAgent = address(0x8888);

        vm.startPrank(deployer);
        usdc.mint(rogueAgent, 100_000 * 1e6);
        vm.stopPrank();

        vm.startPrank(rogueAgent);
        usdc.approve(address(vault), type(uint256).max);
        vault.depositCollateral(100_000 * 1e6, keccak256("root"), rogueSigner);
        vm.stopPrank();

        address honestFinder = address(0x9999);
        vm.startPrank(deployer);
        usdc.mint(honestFinder, 10 * 1e6);
        vm.stopPrank();

        vm.prank(honestFinder);
        usdc.approve(address(vault), type(uint256).max);

        bytes32 honestSalt = keccak256("honest_finder_salt");
        bytes32 honestCommit = keccak256(abi.encodePacked(rogueSk, honestFinder, honestSalt));

        // Honest finder commits
        vm.prank(honestFinder);
        vault.commitFraudProof(rogueAgent, honestCommit);

        vm.roll(block.number + 2);

        // MEV bot observes mempool and attempts revealAndSlash using honestFinder's salt
        vm.prank(competitorMEVBot);
        vm.expectRevert(PerformanceCollateralVault.HashMismatch.selector);
        vault.revealAndSlash(PerformanceCollateralVault.SlashArgs({
            maliciousAgent: rogueAgent,
            extractedSk: rogueSk,
            salt: honestSalt
        }));

        // MEV bot cannot reveal because commit hash is strictly bound to msg.sender
        // Honest finder executes reveal safely and claims 15,000 USDC bounty + 1 USDC bond
        uint256 honestBalBefore = usdc.balanceOf(honestFinder);
        vm.prank(honestFinder);
        vault.revealAndSlash(PerformanceCollateralVault.SlashArgs({
            maliciousAgent: rogueAgent,
            extractedSk: rogueSk,
            salt: honestSalt
        }));

        assertEq(usdc.balanceOf(honestFinder) - honestBalBefore, 15_001 * 1e6);
    }

    /// ATTACK 3: Sybil Restitution Theft
    /// Competitor deploys a fake vendor to steal restitution from slashed agent's pool.
    /// Proves unallocated Sybil vendors are strictly blocked by quota checks.
    function test_Competitor_SybilVendor_CannotStealRestitution() public {
        uint256 rogueSk = 0xFEED;
        address rogueSigner = vault.deriveAddress(rogueSk);
        address rogueAgent = address(0x7777);

        vm.startPrank(deployer);
        usdc.mint(rogueAgent, 10_000 * 1e6);
        vm.stopPrank();

        vm.startPrank(rogueAgent);
        usdc.approve(address(vault), type(uint256).max);
        vault.depositCollateral(10_000 * 1e6, keccak256("root"), rogueSigner);
        // Honest vendor is allocated 3,000 USDC exposure
        vault.allocateSessionExposure(honestVendor, 3_000 * 1e6);
        vm.stopPrank();

        // Slash rogue agent
        bytes32 salt = keccak256("salt");
        bytes32 commit = keccak256(abi.encodePacked(rogueSk, competitorSybil1, salt));
        vm.prank(competitorSybil1);
        vault.commitFraudProof(rogueAgent, commit);

        vm.roll(block.number + 2);
        vm.prank(competitorSybil1);
        vault.revealAndSlash(PerformanceCollateralVault.SlashArgs({
            maliciousAgent: rogueAgent,
            extractedSk: rogueSk,
            salt: salt
        }));

        // Competitor Sybil 2 (zero pre-allocated quota) attempts to claim damages
        bytes32 structHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, rogueAgent, competitorSybil2, 1_000 * 1e6, 1, block.timestamp + 1000)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rogueSk, vault.hashTypedDataV4(structHash));
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(competitorSybil2);
        vm.expectRevert(PerformanceCollateralVault.InsufficientCollateral.selector);
        vault.claimSlashedRestitution(rogueAgent, 1_000 * 1e6, 1, block.timestamp + 1000, sig);
    }

    /// ATTACK 4: Cheque Amount Tampering & Counterfeiting
    /// Competitor vendor receives a signed cheque for $10 USDC, tampers amount to $1,000 USDC.
    /// Proves cryptographic signature rejection prevents balance inflation.
    function test_Competitor_ChequeAmountTampering_Rejected() public {
        vm.startPrank(honestAgentOwner);
        vault.depositCollateral(5_000 * 1e6, keccak256("root"), honestAgentSigner);
        vault.allocateSessionExposure(honestVendor, 2_000 * 1e6);
        vm.stopPrank();

        // Agent signs legitimate cheque for 10 USDC
        bytes32 structHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, honestAgentOwner, honestVendor, 10 * 1e6, 1, block.timestamp + 1000)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(honestAgentSigningPk, vault.hashTypedDataV4(structHash));
        bytes memory sig = abi.encodePacked(r, s, v);

        // Competitor tries to submit tampered cumulative amount of 1,000 USDC with original signature
        vm.prank(honestVendor);
        vm.expectRevert(PerformanceCollateralVault.InvalidSignature.selector);
        vault.settleCheque(honestAgentOwner, 1_000 * 1e6, 1, block.timestamp + 1000, sig);

        // Original 10 USDC cheque settles perfectly
        vm.prank(honestVendor);
        vault.settleCheque(honestAgentOwner, 10 * 1e6, 1, block.timestamp + 1000, sig);
        assertEq(usdc.balanceOf(honestVendor), 10 * 1e6);
    }

    /// ATTACK 5: Cooperative Close Nonce Replay
    /// Competitor vendor cooperatively closes session at nonce 1, then attempts to settle old cheque from nonce 1.
    /// Proves sessionNonce monotonicity strictly invalidates stale cheques after close.
    function test_Competitor_ReplayAfterCooperativeClose_Rejected() public {
        vm.startPrank(honestAgentOwner);
        vault.depositCollateral(5_000 * 1e6, keccak256("root"), honestAgentSigner);
        vault.allocateSessionExposure(honestVendor, 1_000 * 1e6);
        vm.stopPrank();

        // Vendor creates EIP-712 mutual close signature at sessionNonce = 2
        bytes32 closeHash = keccak256(
            abi.encode(
                vault.MUTUAL_CLOSE_TYPEHASH(),
                honestAgentOwner,
                honestVendor,
                100 * 1e6,
                1_000 * 1e6,
                2,
                block.timestamp + 1000
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(honestVendorPk, vault.hashTypedDataV4(closeHash));
        bytes memory closeSig = abi.encodePacked(r, s, v);

        vm.prank(honestAgentOwner);
        vault.cooperativeCloseSession(honestVendor, 100 * 1e6, 1_000 * 1e6, 2, block.timestamp + 1000, closeSig);

        // Vendor attempts to settle an old cheque with sessionNonce = 1
        bytes32 oldChequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, honestAgentOwner, honestVendor, 200 * 1e6, 1, block.timestamp + 1000)
        );
        (uint8 vc, bytes32 rc, bytes32 sc) = vm.sign(honestAgentSigningPk, vault.hashTypedDataV4(oldChequeHash));
        bytes memory chequeSig = abi.encodePacked(rc, sc, vc);

        vm.prank(honestVendor);
        vm.expectRevert(PerformanceCollateralVault.InvalidSessionNonce.selector);
        vault.settleCheque(honestAgentOwner, 200 * 1e6, 1, block.timestamp + 1000, chequeSig);
    }
}
