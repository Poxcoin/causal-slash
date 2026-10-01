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

    function setUp() public {
        deployer = address(0x1);
        treasury = address(0x2);
        insuranceReserve = address(0x3);
        finder = address(0x5);

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
}
