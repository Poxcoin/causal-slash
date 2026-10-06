// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/SwarmDelegationVault.sol";
import "../contracts/MockUSDC.sol";

contract SwarmDelegationVaultTest is Test {
    SwarmDelegationVault public vault;
    MockUSDC public usdc;

    address public deployer;
    address public treasury;
    address public insuranceReserve;
    address public finder;

    uint256 public masterAgentPk;
    address public masterAgent;

    uint256 public masterSigningPk;
    address public masterSigner;

    uint256 public subAgent1Pk;
    address public subAgent1Signer;

    uint256 public subAgent2Pk;
    address public subAgent2Signer;

    uint256 public vendorPk;
    address public vendor;

    function setUp() public {
        deployer = address(0x1);
        treasury = address(0x2);
        insuranceReserve = address(0x3);
        finder = address(0x5);

        vendorPk = 0x4444;
        vendor = vm.addr(vendorPk);

        masterAgentPk = 0xA11CE;
        masterAgent = vm.addr(masterAgentPk);

        masterSigningPk = 0xB0B;
        masterSigner = vm.addr(masterSigningPk);

        subAgent1Pk = 0x1111;
        subAgent1Signer = vm.addr(subAgent1Pk);

        subAgent2Pk = 0x2222;
        subAgent2Signer = vm.addr(subAgent2Pk);

        vm.startPrank(deployer);
        usdc = new MockUSDC();
        vault = new SwarmDelegationVault(address(usdc), treasury, insuranceReserve);

        // Fund master with 10,000,000 USDC
        usdc.mint(masterAgent, 10_000_000 * 1e6);
        vm.stopPrank();

        vm.prank(masterAgent);
        usdc.approve(address(vault), type(uint256).max);
    }

    function _setupMasterVaultWithSwarm(
        uint256 collateralBond,
        bytes32 swarmRoot,
        uint256 depth
    ) internal {
        vm.prank(masterAgent);
        vault.depositCollateral(collateralBond, bytes32(uint256(0x999)), masterSigner);

        vm.prank(masterAgent);
        vault.setSwarmMerkleRoot(swarmRoot, depth);
    }

    function test_Swarm_Deposit_And_SetMerkleRoot() public {
        bytes32 sampleRoot = keccak256("swarm_merkle_root_v1");
        _setupMasterVaultWithSwarm(1_000_000 * 1e6, sampleRoot, 32);

        assertEq(vault.swarmMerkleRoots(masterAgent), sampleRoot);
        assertEq(vault.swarmTreeDepths(masterAgent), 32);

        (uint256 bond, , address signingAddr, , , , bool isSlashed) = vault.vaults(masterAgent);
        assertEq(bond, 1_000_000 * 1e6);
        assertEq(signingAddr, masterSigner);
        assertFalse(isSlashed);
    }

    function test_Swarm_SetMerkleRoot_DepthExceeded_Reverts() public {
        vm.prank(masterAgent);
        vault.depositCollateral(100 * 1e6, bytes32(0), masterSigner);

        vm.prank(masterAgent);
        vm.expectRevert(SwarmDelegationVault.DepthExceeded.selector);
        vault.setSwarmMerkleRoot(keccak256("root"), 33);
    }

    function test_Swarm_SubAgent_CascadeSlashing_Success() public {
        uint256 masterBond = 100_000 * 1e6; // $100,000 USDC
        uint256 subAgentQuota = 5_000 * 1e6; // $5,000 USDC
        bytes32 nonceRoot1 = keccak256("nonce_root_1");
        bytes32 nonceRoot2 = keccak256("nonce_root_2");
        uint256 expiry = block.timestamp + 7 days;

        // Build a 2-leaf Merkle tree (depth 1)
        bytes32 leaf0 = vault.computeSubAgentLeaf(subAgent1Signer, subAgentQuota, nonceRoot1, expiry, 0);
        bytes32 leaf1 = vault.computeSubAgentLeaf(subAgent2Signer, subAgentQuota, nonceRoot2, expiry, 1);

        bytes32 root = keccak256(abi.encodePacked(leaf0, leaf1));
        _setupMasterVaultWithSwarm(masterBond, root, 1);

        // Finder provides proof for leaf0
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        SwarmDelegationVault.SwarmSlashArgs memory slashArgs = SwarmDelegationVault.SwarmSlashArgs({
            masterAgent: masterAgent,
            leafHash: leaf0,
            merkleProof: proof,
            leafIndex: 0,
            extractedSk: subAgent1Pk,
            subAgentQuota: subAgentQuota,
            nonceRoot: nonceRoot1,
            expiry: expiry
        });

        uint256 finderBefore = usdc.balanceOf(finder);
        uint256 insuranceBefore = usdc.balanceOf(insuranceReserve);
        uint256 treasuryBefore = usdc.balanceOf(treasury);

        vm.prank(finder);
        vault.slashSwarmSubAgent(slashArgs);

        // Verification of state updates
        (uint256 remainingBond, , , , , , bool isSlashed) = vault.vaults(masterAgent);
        assertEq(remainingBond, masterBond - subAgentQuota);
        assertFalse(isSlashed); // Master remains active, penalty was deducted
        assertEq(vault.swarmSlashedTotals(masterAgent), subAgentQuota);
        assertTrue(vault.slashedNullifiers(leaf0));

        // Verification of Waterfall Distribution
        // 15% finder bounty = 750 USDC
        // Remaining 4250 USDC: 60% insurance (2550 USDC), 40% treasury (1700 USDC)
        uint256 expectedBounty = (subAgentQuota * 15) / 100;
        uint256 remaining = subAgentQuota - expectedBounty;
        uint256 expectedInsurance = (remaining * 60) / 100;
        uint256 expectedTreasury = remaining - expectedInsurance;

        assertEq(usdc.balanceOf(finder) - finderBefore, expectedBounty);
        assertEq(usdc.balanceOf(insuranceReserve) - insuranceBefore, expectedInsurance);
        assertEq(usdc.balanceOf(treasury) - treasuryBefore, expectedTreasury);
    }

    function test_Swarm_SubAgent_DoubleSlash_Rejected() public {
        uint256 masterBond = 100_000 * 1e6;
        uint256 subAgentQuota = 5_000 * 1e6;
        bytes32 nonceRoot = keccak256("nonce_root");
        uint256 expiry = block.timestamp + 1 days;

        bytes32 leaf0 = vault.computeSubAgentLeaf(subAgent1Signer, subAgentQuota, nonceRoot, expiry, 0);
        bytes32 leaf1 = keccak256("sibling");
        bytes32 root = keccak256(abi.encodePacked(leaf0, leaf1));

        _setupMasterVaultWithSwarm(masterBond, root, 1);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        SwarmDelegationVault.SwarmSlashArgs memory slashArgs = SwarmDelegationVault.SwarmSlashArgs({
            masterAgent: masterAgent,
            leafHash: leaf0,
            merkleProof: proof,
            leafIndex: 0,
            extractedSk: subAgent1Pk,
            subAgentQuota: subAgentQuota,
            nonceRoot: nonceRoot,
            expiry: expiry
        });

        vm.prank(finder);
        vault.slashSwarmSubAgent(slashArgs);

        // Attempting to slash the same leaf again MUST revert
        vm.prank(finder);
        vm.expectRevert(SwarmDelegationVault.SubAgentAlreadySlashed.selector);
        vault.slashSwarmSubAgent(slashArgs);
    }

    function test_Swarm_InvalidMerkleProof_Rejected() public {
        uint256 masterBond = 100_000 * 1e6;
        uint256 subAgentQuota = 5_000 * 1e6;
        bytes32 nonceRoot = keccak256("nonce_root");
        uint256 expiry = block.timestamp + 1 days;

        bytes32 leaf0 = vault.computeSubAgentLeaf(subAgent1Signer, subAgentQuota, nonceRoot, expiry, 0);
        bytes32 leaf1 = keccak256("sibling");
        bytes32 root = keccak256(abi.encodePacked(leaf0, leaf1));

        _setupMasterVaultWithSwarm(masterBond, root, 1);

        // Provide invalid sibling proof
        bytes32[] memory badProof = new bytes32[](1);
        badProof[0] = keccak256("corrupted_sibling");

        SwarmDelegationVault.SwarmSlashArgs memory slashArgs = SwarmDelegationVault.SwarmSlashArgs({
            masterAgent: masterAgent,
            leafHash: leaf0,
            merkleProof: badProof,
            leafIndex: 0,
            extractedSk: subAgent1Pk,
            subAgentQuota: subAgentQuota,
            nonceRoot: nonceRoot,
            expiry: expiry
        });

        vm.prank(finder);
        vm.expectRevert(SwarmDelegationVault.InvalidMerkleProof.selector);
        vault.slashSwarmSubAgent(slashArgs);
    }

    function test_Swarm_ForgedPrivateKey_Rejected() public {
        uint256 masterBond = 100_000 * 1e6;
        uint256 subAgentQuota = 5_000 * 1e6;
        bytes32 nonceRoot = keccak256("nonce_root");
        uint256 expiry = block.timestamp + 1 days;

        bytes32 leaf0 = vault.computeSubAgentLeaf(subAgent1Signer, subAgentQuota, nonceRoot, expiry, 0);
        bytes32 leaf1 = keccak256("sibling");
        bytes32 root = keccak256(abi.encodePacked(leaf0, leaf1));

        _setupMasterVaultWithSwarm(masterBond, root, 1);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        // Provide a random private key that does not derive subAgent1Signer
        uint256 forgedSk = 0x999999;

        SwarmDelegationVault.SwarmSlashArgs memory slashArgs = SwarmDelegationVault.SwarmSlashArgs({
            masterAgent: masterAgent,
            leafHash: leaf0,
            merkleProof: proof,
            leafIndex: 0,
            extractedSk: forgedSk,
            subAgentQuota: subAgentQuota,
            nonceRoot: nonceRoot,
            expiry: expiry
        });

        vm.prank(finder);
        vm.expectRevert(PerformanceCollateralVault.HashMismatch.selector);
        vault.slashSwarmSubAgent(slashArgs);
    }

    function _signSwarmCheque(
        uint256 signerPk,
        address master,
        address chequeVendor,
        uint64 height,
        uint64 cumulativeAmount
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                vault.SWARM_CHEQUE_TYPEHASH(),
                master,
                chequeVendor,
                height,
                cumulativeAmount
            )
        );
        bytes32 digest = vault.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_Swarm_SettleCheque_Success() public {
        uint256 masterBond = 100_000 * 1e6;
        bytes32 leaf0 = keccak256(abi.encodePacked(subAgent1Signer));
        bytes32 leaf1 = keccak256(abi.encodePacked(subAgent2Signer));
        bytes32 root = leaf0 <= leaf1
            ? keccak256(abi.encodePacked(leaf0, leaf1))
            : keccak256(abi.encodePacked(leaf1, leaf0));

        _setupMasterVaultWithSwarm(masterBond, root, 1);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        uint64 channelHeight = 1;
        uint64 cumulativeAmount = 1_500 * 1e6; // $1,500 USDC
        bytes memory sig = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, channelHeight, cumulativeAmount);

        uint256 vendorBalBefore = usdc.balanceOf(vendor);
        vm.prank(vendor);
        vault.settleSwarmCheque(masterAgent, channelHeight, cumulativeAmount, proof, sig);

        assertEq(usdc.balanceOf(vendor) - vendorBalBefore, 1_500 * 1e6);
        (uint256 remainingBond, , , , , , ) = vault.vaults(masterAgent);
        assertEq(remainingBond, masterBond - 1_500 * 1e6);
        assertEq(vault.swarmSettledAmounts(subAgent1Signer, vendor), 1_500 * 1e6);
        assertEq(vault.swarmChannelHeights(subAgent1Signer, vendor), channelHeight);
        assertEq(vault.subAgentTotalSettled(subAgent1Signer), 1_500 * 1e6);
    }

    function test_Swarm_SettleCheque_Monotonic_Rejection() public {
        uint256 masterBond = 100_000 * 1e6;
        bytes32 leaf0 = keccak256(abi.encodePacked(subAgent1Signer));
        bytes32 leaf1 = keccak256(abi.encodePacked(subAgent2Signer));
        bytes32 root = leaf0 <= leaf1
            ? keccak256(abi.encodePacked(leaf0, leaf1))
            : keccak256(abi.encodePacked(leaf1, leaf0));

        _setupMasterVaultWithSwarm(masterBond, root, 1);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        // 1. Initial settlement at height 1, cumulative 1000 USDC
        bytes memory sig1 = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 1, 1_000 * 1e6);
        vm.prank(vendor);
        vault.settleSwarmCheque(masterAgent, 1, 1_000 * 1e6, proof, sig1);

        // 2. Replayed height (same height 1, higher amount) -> reverts InvalidSessionNonce
        bytes memory sigReplay = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 1, 2_000 * 1e6);
        vm.prank(vendor);
        vm.expectRevert(PerformanceCollateralVault.InvalidSessionNonce.selector);
        vault.settleSwarmCheque(masterAgent, 1, 2_000 * 1e6, proof, sigReplay);

        // 3. Decreasing/same amount at higher height -> reverts NothingToSettle
        bytes memory sigStaleAmt = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 2, 1_000 * 1e6);
        vm.prank(vendor);
        vm.expectRevert(PerformanceCollateralVault.NothingToSettle.selector);
        vault.settleSwarmCheque(masterAgent, 2, 1_000 * 1e6, proof, sigStaleAmt);

        bytes memory sigDecAmt = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 2, 800 * 1e6);
        vm.prank(vendor);
        vm.expectRevert(PerformanceCollateralVault.NothingToSettle.selector);
        vault.settleSwarmCheque(masterAgent, 2, 800 * 1e6, proof, sigDecAmt);

        // 4. Valid monotonic progression: height 2, cumulative 2500 USDC (delta 1500 USDC)
        bytes memory sig2 = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 2, 2_500 * 1e6);
        uint256 vendorBefore = usdc.balanceOf(vendor);
        vm.prank(vendor);
        vault.settleSwarmCheque(masterAgent, 2, 2_500 * 1e6, proof, sig2);
        assertEq(usdc.balanceOf(vendor) - vendorBefore, 1_500 * 1e6);
        assertEq(vault.swarmSettledAmounts(subAgent1Signer, vendor), 2_500 * 1e6);
        assertEq(vault.swarmChannelHeights(subAgent1Signer, vendor), 2);
    }

    function test_Swarm_SettleCheque_SubAgentCap_Enforced() public {
        uint256 masterBond = 100_000 * 1e6;
        bytes32 leaf0 = keccak256(abi.encodePacked(subAgent1Signer));
        bytes32 leaf1 = keccak256(abi.encodePacked(subAgent2Signer));
        bytes32 root = leaf0 <= leaf1
            ? keccak256(abi.encodePacked(leaf0, leaf1))
            : keccak256(abi.encodePacked(leaf1, leaf0));

        _setupMasterVaultWithSwarm(masterBond, root, 1);

        // Master restricts subAgent1 to 2,000 USDC cap
        vm.prank(masterAgent);
        vault.setSubAgentCap(subAgent1Signer, 2_000 * 1e6);
        assertEq(vault.subAgentCaps(masterAgent, subAgent1Signer), 2_000 * 1e6);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        // SubAgent signs cheque for 5,000 USDC (exceeds cap of 2,000 USDC)
        bytes memory sig = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 1, 5_000 * 1e6);

        uint256 vendorBefore = usdc.balanceOf(vendor);
        vm.prank(vendor);
        // Settlement succeeds, but payout is clamped to 2,000 USDC
        vault.settleSwarmCheque(masterAgent, 1, 5_000 * 1e6, proof, sig);

        assertEq(usdc.balanceOf(vendor) - vendorBefore, 2_000 * 1e6);
        assertEq(vault.subAgentTotalSettled(subAgent1Signer), 2_000 * 1e6);

        // Next cheque after cap exhausted reverts with SubAgentCapExceeded
        bytes memory sig2 = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 2, 7_000 * 1e6);
        vm.prank(vendor);
        vm.expectRevert(SwarmDelegationVault.SubAgentCapExceeded.selector);
        vault.settleSwarmCheque(masterAgent, 2, 7_000 * 1e6, proof, sig2);
    }

    function test_Swarm_TimelockedRoot_PreviousEpochSettlement() public {
        uint256 masterBond = 100_000 * 1e6;

        // Root 1 contains subAgent1
        bytes32 leaf0 = keccak256(abi.encodePacked(subAgent1Signer));
        bytes32 leaf1 = keccak256(abi.encodePacked(subAgent2Signer));
        bytes32 root1 = leaf0 <= leaf1
            ? keccak256(abi.encodePacked(leaf0, leaf1))
            : keccak256(abi.encodePacked(leaf1, leaf0));

        _setupMasterVaultWithSwarm(masterBond, root1, 1);

        // SubAgent1 signs a cheque for 1,200 USDC
        bytes memory sig = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 1, 1_200 * 1e6);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        // Master updates delegation root to Root 2 (excluding subAgent1)
        bytes32 root2 = keccak256("new_swarm_epoch_root");
        vm.prank(masterAgent);
        vault.setDelegationRoot(root2, 1);

        assertEq(vault.swarmMerkleRoots(masterAgent), root2);
        assertEq(vault.previousRoots(masterAgent), root1);
        assertEq(vault.previousRootExpiries(masterAgent), block.timestamp + 7 days);

        // Warp 2 days forward (well within 7-day grace period)
        vm.warp(block.timestamp + 2 days);

        // Settlement against archived previous root succeeds
        uint256 vendorBefore = usdc.balanceOf(vendor);
        vm.prank(vendor);
        vault.settleSwarmCheque(masterAgent, 1, 1_200 * 1e6, proof, sig);

        assertEq(usdc.balanceOf(vendor) - vendorBefore, 1_200 * 1e6);
    }

    function test_Swarm_TimelockedRoot_RootRugSlashing_Repelled() public {
        uint256 masterBond = 100_000 * 1e6;
        uint256 subAgentQuota = 10_000 * 1e6;
        bytes32 nonceRoot = keccak256("nonce_root");
        uint256 expiry = block.timestamp + 14 days;

        bytes32 leaf0 = vault.computeSubAgentLeaf(subAgent1Signer, subAgentQuota, nonceRoot, expiry, 0);
        bytes32 leaf1 = keccak256("sibling_node");
        bytes32 root1 = keccak256(abi.encodePacked(leaf0, leaf1));

        _setupMasterVaultWithSwarm(masterBond, root1, 1);

        // Whistleblower searcher discovers equivocation and prepares slashing proof
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        SwarmDelegationVault.SwarmSlashArgs memory slashArgs = SwarmDelegationVault.SwarmSlashArgs({
            masterAgent: masterAgent,
            leafHash: leaf0,
            merkleProof: proof,
            leafIndex: 0,
            extractedSk: subAgent1Pk,
            subAgentQuota: subAgentQuota,
            nonceRoot: nonceRoot,
            expiry: expiry
        });

        // Malicious master detects impending slash and front-runs with setDelegationRoot to rug the root!
        bytes32 rugRoot = keccak256("malicious_root_rug");
        vm.prank(masterAgent);
        vault.setDelegationRoot(rugRoot, 1);

        assertEq(vault.swarmMerkleRoots(masterAgent), rugRoot);
        assertEq(vault.previousRoots(masterAgent), root1);

        // Searcher's slash transaction is mined. Vault checks previousRoots within grace period!
        uint256 finderBefore = usdc.balanceOf(finder);
        vm.prank(finder);
        vault.slashSwarmSubAgent(slashArgs);

        // Slashing succeeds! Master bond is slashed, searcher receives 15% bounty!
        (uint256 remainingBond, , , , , , ) = vault.vaults(masterAgent);
        assertEq(remainingBond, masterBond - subAgentQuota);
        assertEq(usdc.balanceOf(finder) - finderBefore, (subAgentQuota * 15) / 100);
        assertTrue(vault.slashedNullifiers(leaf0));
    }

    function test_Swarm_TimelockedRoot_ExpiredPreviousRoot_Reverts() public {
        uint256 masterBond = 100_000 * 1e6;

        bytes32 leaf0 = keccak256(abi.encodePacked(subAgent1Signer));
        bytes32 leaf1 = keccak256(abi.encodePacked(subAgent2Signer));
        bytes32 root1 = leaf0 <= leaf1
            ? keccak256(abi.encodePacked(leaf0, leaf1))
            : keccak256(abi.encodePacked(leaf1, leaf0));

        _setupMasterVaultWithSwarm(masterBond, root1, 1);

        bytes memory sig = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 1, 500 * 1e6);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        // Master updates root to Root 2
        bytes32 root2 = keccak256("root_epoch_2");
        vm.prank(masterAgent);
        vault.setDelegationRoot(root2, 1);

        // Warp 8 days forward (grace period 7 days expired!)
        vm.warp(block.timestamp + 8 days);

        // Settlement against expired root reverts with InvalidMerkleProof
        vm.prank(vendor);
        vm.expectRevert(SwarmDelegationVault.InvalidMerkleProof.selector);
        vault.settleSwarmCheque(masterAgent, 1, 500 * 1e6, proof, sig);
    }

    /// @notice Proves rapid multiple root updates (Root A -> Root B -> Root C) do not rug Root A within 7 days.
    function test_Swarm_MultiRootUpdate_GracePeriodPreserved() public {
        uint256 masterBond = 100_000 * 1e6;

        bytes32 leaf0 = keccak256(abi.encodePacked(subAgent1Signer));
        bytes32 leaf1 = keccak256(abi.encodePacked(subAgent2Signer));
        bytes32 rootA = leaf0 <= leaf1
            ? keccak256(abi.encodePacked(leaf0, leaf1))
            : keccak256(abi.encodePacked(leaf1, leaf0));

        _setupMasterVaultWithSwarm(masterBond, rootA, 1);

        bytes memory sig = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 1, 1_000 * 1e6);
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        // Rapid updates: Root A -> Root B -> Root C within seconds
        bytes32 rootB = keccak256("intermediate_root_B");
        vm.prank(masterAgent);
        vault.setDelegationRoot(rootB, 1);

        bytes32 rootC = keccak256("active_root_C");
        vm.prank(masterAgent);
        vault.setDelegationRoot(rootC, 1);

        assertEq(vault.swarmMerkleRoots(masterAgent), rootC);
        assertTrue(vault.isRootValid(masterAgent, rootA));

        // Advance 3 days (within 7-day grace window)
        vm.warp(block.timestamp + 3 days);

        // SubAgent under Root A settles successfully despite 2 successive root updates!
        uint256 vendorBefore = usdc.balanceOf(vendor);
        vm.prank(vendor);
        vault.settleSwarmCheque(masterAgent, 1, 1_000 * 1e6, proof, sig);
        assertEq(usdc.balanceOf(vendor) - vendorBefore, 1_000 * 1e6);
    }

    /// @notice Proves slashed sub-agents are quarantined and cannot subsequently drain master bond via cheques.
    function test_Swarm_SlashedSubAgent_CannotSettle() public {
        uint256 masterBond = 100_000 * 1e6;
        uint256 subAgentQuota = 10_000 * 1e6;
        bytes32 nonceRoot = keccak256("nonce_root");
        uint256 expiry = block.timestamp + 14 days;

        bytes32 leaf0 = vault.computeSubAgentLeaf(subAgent1Signer, subAgentQuota, nonceRoot, expiry, 0);
        bytes32 leaf1 = keccak256("sibling");
        bytes32 root = keccak256(abi.encodePacked(leaf0, leaf1));

        _setupMasterVaultWithSwarm(masterBond, root, 1);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        // Searcher slashes subAgent1
        SwarmDelegationVault.SwarmSlashArgs memory slashArgs = SwarmDelegationVault.SwarmSlashArgs({
            masterAgent: masterAgent,
            leafHash: leaf0,
            merkleProof: proof,
            leafIndex: 0,
            extractedSk: subAgent1Pk,
            subAgentQuota: subAgentQuota,
            nonceRoot: nonceRoot,
            expiry: expiry
        });

        vm.prank(finder);
        vault.slashSwarmSubAgent(slashArgs);
        assertTrue(vault.slashedSubAgents(masterAgent, subAgent1Signer));

        // SubAgent1 (or colluding vendor) tries to settle a streaming cheque
        bytes memory sig = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 1, 5_000 * 1e6);
        vm.prank(vendor);
        vm.expectRevert(SwarmDelegationVault.SubAgentAlreadySlashed.selector);
        vault.settleSwarmCheque(masterAgent, 1, 5_000 * 1e6, proof, sig);
    }

    /// @notice Proves clamped delta records lastSettled + delta, enabling remaining payout after cap increase.
    function test_Swarm_ClampedDelta_CanSettleRemainderAfterCapIncrease() public {
        uint256 masterBond = 100_000 * 1e6;
        bytes32 leaf0 = keccak256(abi.encodePacked(subAgent1Signer));
        bytes32 leaf1 = keccak256(abi.encodePacked(subAgent2Signer));
        bytes32 root = leaf0 <= leaf1
            ? keccak256(abi.encodePacked(leaf0, leaf1))
            : keccak256(abi.encodePacked(leaf1, leaf0));

        _setupMasterVaultWithSwarm(masterBond, root, 1);

        // Cap subAgent1 at 2,000 USDC
        vm.prank(masterAgent);
        vault.setSubAgentCap(subAgent1Signer, 2_000 * 1e6);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        // SubAgent signs 5,000 USDC cheque
        bytes memory sig = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 1, 5_000 * 1e6);

        // Settle first tranche: clamped to 2,000 USDC
        vm.prank(vendor);
        vault.settleSwarmCheque(masterAgent, 1, 5_000 * 1e6, proof, sig);
        assertEq(vault.swarmSettledAmounts(subAgent1Signer, vendor), 2_000 * 1e6);
        assertEq(vault.subAgentTotalSettled(subAgent1Signer), 2_000 * 1e6);

        // Master raises cap to 6,000 USDC
        vm.prank(masterAgent);
        vault.setSubAgentCap(subAgent1Signer, 6_000 * 1e6);

        // SubAgent issues updated height cheque for the same 5,000 USDC
        bytes memory sig2 = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 2, 5_000 * 1e6);

        uint256 vendorBefore = usdc.balanceOf(vendor);
        vm.prank(vendor);
        vault.settleSwarmCheque(masterAgent, 2, 5_000 * 1e6, proof, sig2);

        // Remaining 3,000 USDC is settled cleanly without lost funds!
        assertEq(usdc.balanceOf(vendor) - vendorBefore, 3_000 * 1e6);
        assertEq(vault.swarmSettledAmounts(subAgent1Signer, vendor), 5_000 * 1e6);
        assertEq(vault.subAgentTotalSettled(subAgent1Signer), 5_000 * 1e6);
    }

    /// @notice Proves swarm settlements cannot starve collateral reserved for session vendors.
    function test_Swarm_SettleCheque_CannotStarveAllocatedExposure() public {
        uint256 masterBond = 10_000 * 1e6;
        bytes32 leaf0 = keccak256(abi.encodePacked(subAgent1Signer));
        bytes32 leaf1 = keccak256(abi.encodePacked(subAgent2Signer));
        bytes32 root = leaf0 <= leaf1
            ? keccak256(abi.encodePacked(leaf0, leaf1))
            : keccak256(abi.encodePacked(leaf1, leaf0));

        _setupMasterVaultWithSwarm(masterBond, root, 1);

        // Master allocates 8,000 USDC to direct enterprise session vendor
        address directVendor = address(0x999);
        vm.prank(masterAgent);
        vault.allocateSessionExposure(directVendor, 8_000 * 1e6);
        assertEq(vault.totalAllocatedExposure(masterAgent), 8_000 * 1e6);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = leaf1;

        // SubAgent attempts to settle 3,000 USDC cheque (free margin is only 2,000 USDC!)
        bytes memory sig = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 1, 3_000 * 1e6);
        vm.prank(vendor);
        vm.expectRevert(PerformanceCollateralVault.InsufficientCollateral.selector);
        vault.settleSwarmCheque(masterAgent, 1, 3_000 * 1e6, proof, sig);

        // Settle within free margin (2,000 USDC) succeeds
        bytes memory sigValid = _signSwarmCheque(subAgent1Pk, masterAgent, vendor, 1, 2_000 * 1e6);
        vm.prank(vendor);
        vault.settleSwarmCheque(masterAgent, 1, 2_000 * 1e6, proof, sigValid);
        assertEq(vault.swarmSettledAmounts(subAgent1Signer, vendor), 2_000 * 1e6);
    }
}
