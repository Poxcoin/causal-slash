// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "./PerformanceCollateralVault.sol";

/**
 * @title SwarmDelegationVault
 * @notice Hierarchical Performance Collateral & Swarm Merkle Tree Slashing Engine.
 *
 * Implements the Billion-Agent Scaling Architecture:
 * 1. Zero On-Chain State Per Sub-Agent:
 *    A single master collateral bond sponsors millions of ephemeral worker sub-agents
 *    committed cryptographically via a 32-level Merkle tree root (swarmMerkleRoot).
 * 2. Cascading O(1) Schnorr EOTS Slashing:
 *    When any ephemeral sub-agent equivocates (double-signs at the same sequence height),
 *    the Schnorr Bloodhound searcher algebraically extracts its private key.
 *    The smart contract derives the sub-agent address via O(1) homomorphic ecrecover,
 *    verifies the Merkle inclusion proof against swarmMerkleRoot, verifies the leaf nullifier,
 *    and cascades the penalty deduction directly to the master enterprise bond.
 * 3. Closed-Loop Slashing Waterfall:
 *    - 15% guaranteed finder bounty to the searcher disclosing the proof.
 *    - Residual surplus split: 60% to Insurance Reserve, 40% to Protocol Treasury.
 * 4. Replay & Double-Spend Protection:
 *    - Nullifier bitmap permanently quarantines slashed leaf hashes.
 */
contract SwarmDelegationVault is PerformanceCollateralVault {
    using SafeERC20 for IERC20;

    uint256 public constant MAX_SWARM_TREE_DEPTH = 32;

    mapping(address => bytes32) public swarmMerkleRoots;
    mapping(address => uint256) public swarmTreeDepths;
    mapping(bytes32 => bool) public slashedNullifiers;
    mapping(address => uint256) public swarmSlashedTotals;

    event SwarmMerkleRootUpdated(address indexed masterAgent, bytes32 indexed newRoot, uint256 maxDepth);
    event SwarmSubAgentSlashed(
        address indexed masterAgent,
        address indexed subAgentSigner,
        bytes32 indexed leafHash,
        uint256 penaltyUSDC,
        uint256 finderBounty,
        address finder
    );

    error InvalidMerkleProof();
    error SubAgentAlreadySlashed();
    error DepthExceeded();
    error MasterVaultInactive();

    struct SwarmSlashArgs {
        address masterAgent;
        bytes32 leafHash;
        bytes32[] merkleProof;
        uint256 leafIndex;
        uint256 extractedSk;
        uint256 subAgentQuota;
        bytes32 nonceRoot;
        uint256 expiry;
    }

    constructor(
        address _usdcToken,
        address _treasury,
        address _insuranceReserve
    ) PerformanceCollateralVault(_usdcToken, _treasury, _insuranceReserve) {}

    /**
     * @notice Anchor or update the Swarm Merkle Root for an enterprise master bond.
     * @param _swarmMerkleRoot 32-byte cryptographic root committing to all sub-agent capabilities.
     * @param _maxDepth Maximum depth of the Merkle tree (must be <= 32).
     */
    function setSwarmMerkleRoot(bytes32 _swarmMerkleRoot, uint256 _maxDepth) external {
        AgentVault storage vault = vaults[msg.sender];
        if (vault.collateralBond == 0) revert InsufficientCollateral();
        if (vault.isSlashed) revert AlreadySlashed();
        if (_maxDepth > MAX_SWARM_TREE_DEPTH || _maxDepth == 0) revert DepthExceeded();

        swarmMerkleRoots[msg.sender] = _swarmMerkleRoot;
        swarmTreeDepths[msg.sender] = _maxDepth;

        emit SwarmMerkleRootUpdated(msg.sender, _swarmMerkleRoot, _maxDepth);
    }

    /**
     * @notice Cryptographically computes the canonical Merkle leaf for a sub-agent.
     * @dev Leaf schema: H(subAgentAddress || quotaUSDC || nonceRoot || expiry || leafIndex)
     */
    function computeSubAgentLeaf(
        address subAgentAddress,
        uint256 quotaUSDC,
        bytes32 nonceRoot,
        uint256 expiry,
        uint256 leafIndex
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(subAgentAddress, quotaUSDC, nonceRoot, expiry, leafIndex));
    }

    /**
     * @notice Verifies standard binary Merkle inclusion proof.
     */
    function verifyMerkleProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof,
        uint256 index
    ) public pure returns (bool) {
        bytes32 current = leaf;
        uint256 len = proof.length;
        for (uint256 i = 0; i < len; ) {
            if (((index >> i) & 1) == 0) {
                current = keccak256(abi.encodePacked(current, proof[i]));
            } else {
                current = keccak256(abi.encodePacked(proof[i], current));
            }
            unchecked {
                ++i;
            }
        }
        return current == root;
    }

    /**
     * @notice Cascading O(1) slashing of an enterprise master bond for sub-agent equivocation.
     * @dev Validates extracted private key, leaf identity, Merkle proof, and nullifier before execution.
     */
    function slashSwarmSubAgent(SwarmSlashArgs calldata args) external nonReentrant {
        AgentVault storage vault = vaults[args.masterAgent];
        if (vault.isSlashed) revert AlreadySlashed();
        uint256 masterBond = vault.collateralBond;
        if (masterBond == 0) revert InsufficientCollateral();

        bytes32 root = swarmMerkleRoots[args.masterAgent];
        if (root == bytes32(0)) revert MasterVaultInactive();
        if (args.merkleProof.length > swarmTreeDepths[args.masterAgent]) revert DepthExceeded();

        // 1. O(1) secp256k1 key derivation (~7,162 gas)
        address derivedSigner = deriveAddress(args.extractedSk);

        // 2. Leaf integrity verification
        bytes32 expectedLeaf = computeSubAgentLeaf(
            derivedSigner,
            args.subAgentQuota,
            args.nonceRoot,
            args.expiry,
            args.leafIndex
        );
        if (expectedLeaf != args.leafHash) revert HashMismatch();

        // 3. Merkle path verification against anchored swarm root
        if (!verifyMerkleProof(root, args.leafHash, args.merkleProof, args.leafIndex)) {
            revert InvalidMerkleProof();
        }

        // 4. Nullifier check to prevent double-slashing of the same sub-agent leaf
        if (slashedNullifiers[args.leafHash]) revert SubAgentAlreadySlashed();
        slashedNullifiers[args.leafHash] = true;

        // 5. Cascade Foreclosure: penalty = min(masterBond, subAgentQuota)
        uint256 penalty = masterBond > args.subAgentQuota ? args.subAgentQuota : masterBond;
        if (penalty == 0) revert InsufficientCollateral();

        vault.collateralBond = masterBond - penalty;
        swarmSlashedTotals[args.masterAgent] += penalty;

        _ensureLiquidCash(penalty);

        // Waterfall Distribution:
        // Priority 1: 15% guaranteed finder bounty to whistleblower searcher
        uint256 finderBounty = (penalty * 15) / 100;
        uint256 remaining = penalty - finderBounty;

        // Priority 2: Residual surplus split: 60% Insurance Reserve, 40% Protocol Treasury
        uint256 insuranceAmount = (remaining * 60) / 100;
        uint256 treasuryAmount = remaining - insuranceAmount;

        if (finderBounty > 0) {
            usdc.safeTransfer(msg.sender, finderBounty);
        }
        if (insuranceAmount > 0) {
            usdc.safeTransfer(insuranceReserve, insuranceAmount);
        }
        if (treasuryAmount > 0) {
            usdc.safeTransfer(treasury, treasuryAmount);
        }

        emit SwarmSubAgentSlashed(
            args.masterAgent,
            derivedSigner,
            args.leafHash,
            penalty,
            finderBounty,
            msg.sender
        );
    }
}
