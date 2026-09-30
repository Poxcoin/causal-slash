// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC4626.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title PerformanceCollateralVault
 * @notice Automated Performance Collateral Vault & Liquidated Damages Settlement Engine.
 * Denominated strictly in USD / USDC (6 decimal places: micro-USDC).
 *
 * Architectural Invariants:
 * 1. 0-Second Instant Margin Release: Free collateral (Bond - totalAllocatedExposure) is withdrawable in 0s.
 * 2. 0-Second Cooperative Close: Mutual close receipt releases session exposure immediately.
 * 3. Closed-Loop Slashing Waterfall (Anti-Self-Slashing & No 0xdead burn):
 *    - 15% guaranteed finder bounty to incentivize cryptographic key disclosure.
 *    - Priority restitution strictly isolated to active vendors with prior registered quotas.
 *    - Remainder split: 60% Insurance Reserve (bad-debt buffer), 40% Protocol Treasury.
 * 4. Anti-Spam Commit Bonds: Griefing DoS eliminated via 1 USDC slashable bond on fraud commitments.
 * 5. Dynamic Quota Relief: On-chain cheque settlement automatically deducts allocated exposure, eliminating phantom locks.
 * 6. O(1) secp256k1 Key Derivation Identity: Instant foreclosure in ~7,162 gas.
 * 7. Yield Streaming Collateral: Idle USDC is routed into ERC-4626 lending vaults (Morpho / Aave)
 *    with a 20% liquid cash buffer and synchronous on-demand redemptions.
 */
contract PerformanceCollateralVault is EIP712, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // secp256k1 curve parameters for O(1) key extraction identity
    uint256 public constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 public constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint8 public constant V_BASE = 27;

    bytes32 public constant CHEQUE_TYPEHASH = keccak256(
        "Cheque(address agent,address vendor,uint256 cumulativeAmount,uint256 sessionNonce,uint256 deadline)"
    );

    bytes32 public constant MUTUAL_CLOSE_TYPEHASH = keccak256(
        "MutualClose(address agent,address vendor,uint256 finalSettledAmount,uint256 releasedExposure,uint256 sessionNonce,uint256 deadline)"
    );

    uint256 public constant EMERGENCY_DISPUTE_PERIOD = 4 hours; // Safe dispute window against L2 reorg/sequencer delays
    uint256 public constant MIN_COMMIT_DELAY = 1;
    uint256 public constant MAX_COMMIT_WINDOW = 256;
    uint256 public constant COMMIT_BOND = 1 * 1e6; // 1 USDC anti-spam bond

    uint256 public protocolFeeBps = 0; // 0 bps promotional genesis fee (bootstrap phase)
    uint256 public constant MAX_FEE_BPS = 25; // 0.25% hard cap to protect agents

    IERC20 public immutable usdc;
    address public immutable treasury;
    address public immutable insuranceReserve;

    // Yield Streaming Strategy Integration (Morpho Blue / Aave v3 ERC-4626)
    IERC4626 public yieldVault;
    uint256 public cashReserveBps = 2000; // 20% liquid cash buffer (2000 / 10000)
    uint256 public principalInYield;
    uint256 public totalYieldHarvested;

    event YieldVaultConfigured(address indexed yieldVault, uint256 cashReserveBps);
    event YieldHarvested(uint256 totalYield, uint256 insuranceAmount, uint256 treasuryAmount);

    struct AgentVault {
        uint256 collateralBond;      // Total deposited USDC (6 decimals)
        bytes32 nonceMerkleRoot;     // Anchored root of deterministic Schnorr nonces
        address signingAddress;      // Agent's secp256k1 signing address
        address agentOwner;          // Managing owner address
        uint256 pendingWithdrawal;   // Requested emergency withdrawal amount
        uint256 withdrawalTimestamp; // Timestamp when emergency withdrawal was initiated
        bool isSlashed;              // Foreclosure status
    }

    struct FraudCommitment {
        address targetAgent;
        address committer;
        uint256 commitBlock;
        bool revealed;
    }

    struct SlashArgs {
        address maliciousAgent;
        uint256 extractedSk;
        bytes32 salt;
    }

    mapping(address => AgentVault) public vaults;
    mapping(bytes32 => FraudCommitment) public commitments;
    mapping(address => mapping(address => uint256)) public settledAmounts;     // agent => vendor => settled USDC
    mapping(address => mapping(address => uint256)) public lastSessionNonces;
    mapping(address => mapping(address => uint256)) public vendorExposure;     // agent => vendor => active quota
    mapping(address => uint256) public totalAllocatedExposure;                 // agent => sum of active reserved session buffers
    mapping(address => uint256) public slashedRestitutionPool;                 // agent => restitution pool for active vendors
    mapping(address => uint256) public disputeLocks;                           // agent => block number until which instantWithdraw is locked
    mapping(address => uint256) public slashTimestamps;                        // agent => timestamp when slashed

    event CollateralDeposited(address indexed agent, uint256 amountUSDC, bytes32 indexed merkleRoot, address signingAddress);
    event InstantMarginWithdrawn(address indexed agent, uint256 amountUSDC, uint256 remainingBond);
    event ExposureAllocated(address indexed agent, address indexed vendor, uint256 exposureDelta, uint256 totalAllocated);
    event CooperativeSessionClosed(address indexed agent, address indexed vendor, uint256 finalAmount, uint256 releasedExposure);
    event EmergencyWithdrawalInitiated(address indexed agent, uint256 amountUSDC, uint256 unlockTimestamp);
    event EmergencyWithdrawalFinalized(address indexed agent, uint256 amountUSDC);
    event EmergencyWithdrawalCancelled(address indexed agent);
    event ChequeSettled(address indexed agent, address indexed vendor, uint256 deltaUSDC, uint256 cumulativeUSDC);
    event FraudCommitted(bytes32 indexed commitHash, address indexed finder, uint256 blockNumber);
    event CollateralForeclosed(address indexed agent, address indexed finder, uint256 bountyUSDC, address indexed damagedVendor, uint256 damageUSDC, uint256 insuranceUSDC, uint256 treasuryUSDC);
    event DamageClaimed(address indexed vendor, uint256 amountUSDC);
    event ProtocolFeeUpdated(uint256 newFeeBps);
    event CommitmentExpiredAndForfeited(bytes32 indexed commitHash, address indexed committer, address indexed targetAgent);

    error AlreadySlashed();
    error InsufficientCollateral();
    error InvalidKey();
    error CommitTooEarly();
    error CommitExpired();
    error HashMismatch();
    error TransferFailed();
    error InvalidSignature();
    error ChequeExpired();
    error InvalidSessionNonce();
    error NothingToSettle();
    error TimelockActive();
    error NoPendingWithdrawal();
    error Unauthorized();
    error ExposureExceedsBond();
    error FeeExceedsCap();
    error AlreadyCommitted();
    error NoActiveCommitment();
    error InvalidAddress();
    error InvalidAmount();

    constructor(
        address _usdcToken,
        address _treasury,
        address _insuranceReserve
    ) EIP712("CausalSlashVault", "2.0") {
        if (_usdcToken == address(0) || _treasury == address(0) || _insuranceReserve == address(0)) {
            revert TransferFailed();
        }
        usdc = IERC20(_usdcToken);
        treasury = _treasury;
        insuranceReserve = _insuranceReserve;
    }

    /**
     * @notice Deposit USDC performance collateral and anchor Merkle root of nonces.
     */
    function depositCollateral(
        uint256 amountUSDC,
        bytes32 _merkleRoot,
        address _signingAddress
    ) external nonReentrant {
        if (_signingAddress == address(0)) revert InvalidKey();
        if (amountUSDC == 0) revert InsufficientCollateral();

        AgentVault storage vault = vaults[msg.sender];
        if (vault.isSlashed) revert AlreadySlashed();
        if (vault.signingAddress != address(0) && vault.signingAddress != _signingAddress) {
            revert Unauthorized();
        }

        usdc.safeTransferFrom(msg.sender, address(this), amountUSDC);

        vault.collateralBond += amountUSDC;
        vault.nonceMerkleRoot = _merkleRoot;
        vault.signingAddress = _signingAddress;
        vault.agentOwner = msg.sender;

        _rebalanceToYieldVault();

        emit CollateralDeposited(msg.sender, vault.collateralBond, _merkleRoot, _signingAddress);
    }

    /**
     * @notice Backward-compatible getter for total allocated exposure.
     */
    function allocatedExposure(address agent) external view returns (uint256) {
        return totalAllocatedExposure[agent];
    }

    /**
     * @notice Instant Margin Release (0 seconds wait time).
     * Withdraws free, unallocated collateral immediately.
     */
    function instantWithdraw(uint256 amountUSDC) external nonReentrant {
        AgentVault storage vault = vaults[msg.sender];
        if (vault.agentOwner != msg.sender) revert Unauthorized();
        if (vault.isSlashed) revert AlreadySlashed();
        if (block.number <= disputeLocks[msg.sender]) revert TimelockActive();
        if (amountUSDC == 0) revert InsufficientCollateral();

        uint256 totalBond = vault.collateralBond;
        uint256 reserved = totalAllocatedExposure[msg.sender] + vault.pendingWithdrawal;
        
        if (totalBond < reserved || amountUSDC > (totalBond - reserved)) {
            revert InsufficientCollateral();
        }

        _ensureLiquidCash(amountUSDC);
        vault.collateralBond -= amountUSDC;
        usdc.safeTransfer(msg.sender, amountUSDC);

        emit InstantMarginWithdrawn(msg.sender, amountUSDC, vault.collateralBond);
    }

    /**
     * @notice Reserve exposure quota for an active streaming session with a specific vendor.
     * Enforces global invariant: totalAllocatedExposure + pendingWithdrawal <= collateralBond.
     */
    function allocateSessionExposure(address vendor, uint256 exposureAmount) external nonReentrant {
        if (vendor == address(0)) revert InvalidAddress();
        AgentVault storage vault = vaults[msg.sender];
        if (vault.agentOwner != msg.sender) revert Unauthorized();
        if (vault.isSlashed) revert AlreadySlashed();
        if (block.number <= disputeLocks[msg.sender]) revert TimelockActive();

        uint256 newTotalAllocated = totalAllocatedExposure[msg.sender] + exposureAmount;
        if (newTotalAllocated + vault.pendingWithdrawal > vault.collateralBond) revert ExposureExceedsBond();

        totalAllocatedExposure[msg.sender] = newTotalAllocated;
        vendorExposure[msg.sender][vendor] += exposureAmount;

        emit ExposureAllocated(msg.sender, vendor, exposureAmount, newTotalAllocated);
    }

    /**
     * @notice Cooperative Instant Session Close (0 seconds wait time).
     * Releases active session exposure and settles final balance with mutual vendor signature.
     */
    function cooperativeCloseSession(
        address vendor,
        uint256 finalSettledAmount,
        uint256 releasedExposure,
        uint256 sessionNonce,
        uint256 deadline,
        bytes calldata vendorSignature
    ) external nonReentrant {
        if (block.timestamp > deadline) revert ChequeExpired();
        AgentVault storage vault = vaults[msg.sender];
        if (vault.agentOwner != msg.sender) revert Unauthorized();
        if (vault.isSlashed) revert AlreadySlashed();
        if (block.number <= disputeLocks[msg.sender]) revert TimelockActive();

        if (sessionNonce <= lastSessionNonces[msg.sender][vendor]) revert InvalidSessionNonce();
        lastSessionNonces[msg.sender][vendor] = sessionNonce;

        // Verify Vendor's EIP-712 Mutual Close signature
        if (
            ECDSA.recover(
                _hashTypedDataV4(
                    keccak256(
                        abi.encode(MUTUAL_CLOSE_TYPEHASH, msg.sender, vendor, finalSettledAmount, releasedExposure, sessionNonce, deadline)
                    )
                ),
                vendorSignature
            ) != vendor
        ) revert InvalidSignature();

        // Release allocated exposure per vendor and globally
        uint256 currentVendorQuota = vendorExposure[msg.sender][vendor];
        if (releasedExposure > currentVendorQuota) {
            releasedExposure = currentVendorQuota;
        }
        if (releasedExposure > 0) {
            vendorExposure[msg.sender][vendor] -= releasedExposure;
            if (releasedExposure > totalAllocatedExposure[msg.sender]) {
                totalAllocatedExposure[msg.sender] = 0;
            } else {
                totalAllocatedExposure[msg.sender] -= releasedExposure;
            }
        }

        // Settle delta if any remains
        if (finalSettledAmount > settledAmounts[msg.sender][vendor]) {
            uint256 delta = finalSettledAmount - settledAmounts[msg.sender][vendor];
            if (delta > vault.collateralBond) revert InsufficientCollateral();
            settledAmounts[msg.sender][vendor] = finalSettledAmount;
            vault.collateralBond -= delta;

            uint256 freeMargin = vault.collateralBond > totalAllocatedExposure[msg.sender]
                ? vault.collateralBond - totalAllocatedExposure[msg.sender]
                : 0;
            if (vault.pendingWithdrawal > freeMargin) {
                vault.pendingWithdrawal = freeMargin;
            }

            uint256 fee = (delta * protocolFeeBps) / 10000;
            _ensureLiquidCash(delta);
            usdc.safeTransfer(vendor, delta - fee);
            if (fee > 0) {
                usdc.safeTransfer(treasury, fee);
            }
            emit ChequeSettled(msg.sender, vendor, delta, finalSettledAmount);
        }

        emit CooperativeSessionClosed(msg.sender, vendor, finalSettledAmount, releasedExposure);
    }

    /**
     * @notice Emergency Slow Path: Initiate withdrawal subject to 4-hour dispute window.
     * Capped strictly to unallocated collateral to protect active vendor sessions.
     */
    function initiateEmergencyWithdrawal(uint256 amountUSDC) external nonReentrant {
        AgentVault storage vault = vaults[msg.sender];
        if (vault.agentOwner != msg.sender) revert Unauthorized();
        if (vault.isSlashed) revert AlreadySlashed();
        if (block.number <= disputeLocks[msg.sender]) revert TimelockActive();

        uint256 freeCollateral = vault.collateralBond > totalAllocatedExposure[msg.sender]
            ? vault.collateralBond - totalAllocatedExposure[msg.sender]
            : 0;

        if (amountUSDC == 0 || amountUSDC > freeCollateral) revert InsufficientCollateral();

        vault.pendingWithdrawal = amountUSDC;
        vault.withdrawalTimestamp = block.timestamp;

        emit EmergencyWithdrawalInitiated(msg.sender, amountUSDC, block.timestamp + EMERGENCY_DISPUTE_PERIOD);
    }

    /**
     * @notice Finalize emergency withdrawal after 4-hour dispute window.
     */
    function finalizeEmergencyWithdrawal() external nonReentrant {
        AgentVault storage vault = vaults[msg.sender];
        if (vault.agentOwner != msg.sender) revert Unauthorized();
        if (vault.isSlashed) revert AlreadySlashed();
        if (block.number <= disputeLocks[msg.sender]) revert TimelockActive();
        if (vault.pendingWithdrawal == 0) revert NoPendingWithdrawal();

        uint256 unlockTime = vault.withdrawalTimestamp + EMERGENCY_DISPUTE_PERIOD;
        if (block.timestamp < unlockTime) revert TimelockActive();

        uint256 amountToTransfer = vault.pendingWithdrawal;
        if (amountToTransfer > vault.collateralBond) {
            amountToTransfer = vault.collateralBond;
        }

        _ensureLiquidCash(amountToTransfer);
        vault.collateralBond -= amountToTransfer;
        vault.pendingWithdrawal = 0;
        vault.withdrawalTimestamp = 0;

        usdc.safeTransfer(vault.agentOwner, amountToTransfer);
        emit EmergencyWithdrawalFinalized(msg.sender, amountToTransfer);
    }

    /**
     * @notice Cancel pending emergency withdrawal.
     */
    function cancelEmergencyWithdrawal() external nonReentrant {
        AgentVault storage vault = vaults[msg.sender];
        if (vault.agentOwner != msg.sender) revert Unauthorized();
        vault.pendingWithdrawal = 0;
        vault.withdrawalTimestamp = 0;
        emit EmergencyWithdrawalCancelled(msg.sender);
    }

    /**
     * @notice Vendor settles cumulative off-chain EIP-712 streaming cheque in USDC.
     * Automatically reduces allocated exposure to prevent phantom quota locks.
     */
    function settleCheque(
        address agent,
        uint256 cumulativeAmountUSDC,
        uint256 sessionNonce,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant {
        if (block.timestamp > deadline) revert ChequeExpired();
        AgentVault storage vault = vaults[agent];
        if (vault.signingAddress == address(0)) revert InvalidKey();
        if (vault.isSlashed) revert AlreadySlashed();
        if (block.number <= disputeLocks[agent]) revert TimelockActive();

        if (sessionNonce <= lastSessionNonces[agent][msg.sender]) revert InvalidSessionNonce();
        lastSessionNonces[agent][msg.sender] = sessionNonce;

        if (cumulativeAmountUSDC <= settledAmounts[agent][msg.sender]) revert NothingToSettle();
        uint256 delta = cumulativeAmountUSDC - settledAmounts[agent][msg.sender];

        if (delta > vault.collateralBond) revert InsufficientCollateral();

        // Verify EIP-712 signature
        if (
            ECDSA.recover(
                _hashTypedDataV4(
                    keccak256(
                        abi.encode(CHEQUE_TYPEHASH, agent, msg.sender, cumulativeAmountUSDC, sessionNonce, deadline)
                    )
                ),
                signature
            ) != vault.signingAddress
        ) revert InvalidSignature();

        // State update (CEI)
        settledAmounts[agent][msg.sender] = cumulativeAmountUSDC;
        vault.collateralBond -= delta;

        // Dynamic quota relief: deduct from active vendor exposure and total exposure
        uint256 activeQuota = vendorExposure[agent][msg.sender];
        uint256 exposureToRelieve = delta > activeQuota ? activeQuota : delta;
        if (exposureToRelieve > 0) {
            vendorExposure[agent][msg.sender] -= exposureToRelieve;
            if (exposureToRelieve > totalAllocatedExposure[agent]) {
                totalAllocatedExposure[agent] = 0;
            } else {
                totalAllocatedExposure[agent] -= exposureToRelieve;
            }
        }

        // Dynamic clamping of pending emergency withdrawal to free collateral
        uint256 freeMargin = vault.collateralBond > totalAllocatedExposure[agent]
            ? vault.collateralBond - totalAllocatedExposure[agent]
            : 0;
        if (vault.pendingWithdrawal > freeMargin) {
            vault.pendingWithdrawal = freeMargin;
        }

        uint256 fee = (delta * protocolFeeBps) / 10000;
        _ensureLiquidCash(delta);
        usdc.safeTransfer(msg.sender, delta - fee);
        if (fee > 0) {
            usdc.safeTransfer(treasury, fee);
        }
        emit ChequeSettled(agent, msg.sender, delta, cumulativeAmountUSDC);
    }

    /**
     * @notice Phase 1: Submit commitment hash C = keccak256(extractedSk, finder, salt).
     * Requires 1 USDC COMMIT_BOND to eliminate griefing DoS attacks.
     */
    function commitFraudProof(address targetAgent, bytes32 _commitHash) external nonReentrant {
        if (targetAgent == address(0)) revert InvalidKey();
        if (vaults[targetAgent].collateralBond == 0) revert InsufficientCollateral();
        if (vaults[targetAgent].isSlashed) revert AlreadySlashed();
        if (block.number <= disputeLocks[targetAgent]) revert TimelockActive();
        if (commitments[_commitHash].commitBlock != 0) revert AlreadyCommitted();

        // Anti-spam commit bond deposit
        usdc.safeTransferFrom(msg.sender, address(this), COMMIT_BOND);

        commitments[_commitHash] = FraudCommitment({
            targetAgent: targetAgent,
            committer: msg.sender,
            commitBlock: block.number,
            revealed: false
        });
        disputeLocks[targetAgent] = block.number + MAX_COMMIT_WINDOW;

        emit FraudCommitted(_commitHash, msg.sender, block.number);
    }

    /**
     * @notice Cancel an expired commitment (> 256 blocks) that failed to reveal.
     * Forfeits the 1 USDC COMMIT_BOND to Insurance Reserve and unlocks the target agent.
     */
    function cancelExpiredCommitment(bytes32 _commitHash) external nonReentrant {
        FraudCommitment storage comm = commitments[_commitHash];
        if (comm.commitBlock == 0 || comm.revealed) revert NoActiveCommitment();
        if (block.number <= comm.commitBlock + MAX_COMMIT_WINDOW) revert TimelockActive();

        comm.revealed = true;
        address targetAgent = comm.targetAgent;
        if (disputeLocks[targetAgent] <= block.number) {
            disputeLocks[targetAgent] = 0;
        }

        // Forfeit commit bond to insurance reserve
        usdc.safeTransfer(insuranceReserve, COMMIT_BOND);
        emit CommitmentExpiredAndForfeited(_commitHash, comm.committer, targetAgent);
    }

    /**
     * @notice Phase 2: Reveal extracted private key and execute closed-loop foreclosure waterfall.
     * Anti-Self-Slashing: Finder ONLY receives 15% bounty. Damage restitution is quarantined
     * into slashedRestitutionPool and can ONLY be claimed by vendors with pre-registered exposure.
     */
    function revealAndSlash(SlashArgs calldata args) external nonReentrant {
        AgentVault storage vault = vaults[args.maliciousAgent];
        if (vault.isSlashed) revert AlreadySlashed();
        uint256 totalBond = vault.collateralBond;
        if (totalBond == 0) revert InsufficientCollateral();

        bytes32 computedHash = keccak256(abi.encodePacked(args.extractedSk, msg.sender, args.salt));
        FraudCommitment storage comm = commitments[computedHash];
        if (comm.commitBlock == 0) revert HashMismatch();
        if (comm.revealed) revert AlreadySlashed();
        if (block.number < comm.commitBlock + MIN_COMMIT_DELAY) revert CommitTooEarly();
        if (block.number > comm.commitBlock + MAX_COMMIT_WINDOW) revert CommitExpired();
        if (comm.targetAgent != args.maliciousAgent) revert Unauthorized();
        if (comm.committer != msg.sender) revert Unauthorized();

        comm.revealed = true;

        // O(1) ecrecover identity key verification (~7,162 gas)
        address derivedSigner = deriveAddress(args.extractedSk);
        if (derivedSigner != vault.signingAddress) revert InvalidKey();

        // Foreclose vault permanently
        vault.isSlashed = true;
        vault.collateralBond = 0;
        vault.pendingWithdrawal = 0;
        vault.withdrawalTimestamp = 0;
        slashTimestamps[args.maliciousAgent] = block.timestamp;

        _ensureLiquidCash(totalBond + COMMIT_BOND);

        // Return anti-spam commit bond to honest finder
        usdc.safeTransfer(msg.sender, COMMIT_BOND);

        // 1. Priority 1: Guaranteed 15% Whistleblower / Finder Bounty
        uint256 bounty = (totalBond * 15) / 100;
        uint256 remaining = totalBond - bounty;

        // 2. Priority 2: Restitution Reserve for Pre-allocated Active Vendors
        uint256 totalReserved = totalAllocatedExposure[args.maliciousAgent];
        uint256 restitutionAllocation = remaining > totalReserved ? totalReserved : remaining;
        slashedRestitutionPool[args.maliciousAgent] = restitutionAllocation;
        remaining -= restitutionAllocation;

        // 3. Priority 3: Remainder split: 60% to Insurance Reserve, 40% to Protocol Treasury
        uint256 insuranceAmount = (remaining * 60) / 100;
        uint256 treasuryAmount = remaining - insuranceAmount;

        // Execute distributions
        if (bounty > 0) {
            usdc.safeTransfer(msg.sender, bounty);
        }
        if (insuranceAmount > 0) {
            usdc.safeTransfer(insuranceReserve, insuranceAmount);
        }
        if (treasuryAmount > 0) {
            usdc.safeTransfer(treasury, treasuryAmount);
        }

        emit CollateralForeclosed(
            args.maliciousAgent,
            msg.sender,
            bounty,
            address(0),
            restitutionAllocation,
            insuranceAmount,
            treasuryAmount
        );
    }

    /**
     * @notice Damaged vendor claims restitution from the slashed restitution pool with a valid cheque.
     * Guaranteed capped by the vendor's pre-allocated exposure quota (Anti-Self-Slashing).
     */
    function claimSlashedRestitution(
        address maliciousAgent,
        uint256 cumulativeAmountUSDC,
        uint256 sessionNonce,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant {
        if (block.timestamp > deadline) revert ChequeExpired();
        AgentVault storage vault = vaults[maliciousAgent];
        if (!vault.isSlashed) revert Unauthorized();

        uint256 activeQuota = vendorExposure[maliciousAgent][msg.sender];
        if (activeQuota == 0) revert InsufficientCollateral();

        if (sessionNonce <= lastSessionNonces[maliciousAgent][msg.sender]) revert InvalidSessionNonce();
        lastSessionNonces[maliciousAgent][msg.sender] = sessionNonce;

        if (cumulativeAmountUSDC <= settledAmounts[maliciousAgent][msg.sender]) revert NothingToSettle();
        uint256 delta = cumulativeAmountUSDC - settledAmounts[maliciousAgent][msg.sender];

        // Cap restitution by active vendor quota and remaining restitution pool
        if (delta > activeQuota) {
            delta = activeQuota;
        }
        if (delta > slashedRestitutionPool[maliciousAgent]) {
            delta = slashedRestitutionPool[maliciousAgent];
        }
        if (delta == 0) revert NothingToSettle();

        // Verify EIP-712 cheque signature from agent's signingAddress
        bytes32 structHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, maliciousAgent, msg.sender, cumulativeAmountUSDC, sessionNonce, deadline)
        );
        if (
            ECDSA.recover(_hashTypedDataV4(structHash), signature) != vault.signingAddress
        ) revert InvalidSignature();

        settledAmounts[maliciousAgent][msg.sender] += delta;
        vendorExposure[maliciousAgent][msg.sender] -= delta;
        slashedRestitutionPool[maliciousAgent] -= delta;

        _ensureLiquidCash(delta);
        usdc.safeTransfer(msg.sender, delta);
        emit DamageClaimed(msg.sender, delta);
    }

    /**
     * @notice Sweeps unclaimed restitution after emergency dispute period to insurance and treasury.
     */
    function sweepUnclaimedRestitution(address maliciousAgent) external nonReentrant {
        AgentVault storage vault = vaults[maliciousAgent];
        if (!vault.isSlashed) revert Unauthorized();
        if (block.timestamp < slashTimestamps[maliciousAgent] + EMERGENCY_DISPUTE_PERIOD) {
            revert TimelockActive();
        }

        uint256 unclaimed = slashedRestitutionPool[maliciousAgent];
        if (unclaimed == 0) revert NothingToSettle();

        slashedRestitutionPool[maliciousAgent] = 0;
        uint256 insuranceAmount = (unclaimed * 60) / 100;
        uint256 treasuryAmount = unclaimed - insuranceAmount;

        _ensureLiquidCash(unclaimed);
        if (insuranceAmount > 0) {
            usdc.safeTransfer(insuranceReserve, insuranceAmount);
        }
        if (treasuryAmount > 0) {
            usdc.safeTransfer(treasury, treasuryAmount);
        }
    }

    /**
     * @notice Configure external ERC-4626 yield strategy (Morpho Blue / Aave v3 on Base L2).
     */
    function setYieldVault(address _yieldVault, uint256 _cashReserveBps) external {
        if (msg.sender != treasury) revert Unauthorized();
        if (_cashReserveBps > 10000) revert InvalidAmount();

        if (address(yieldVault) != address(0) && address(yieldVault) != _yieldVault) {
            uint256 currentShares = yieldVault.balanceOf(address(this));
            if (currentShares > 0) {
                yieldVault.redeem(currentShares, address(this), address(this));
            }
            principalInYield = 0;
        }

        yieldVault = IERC4626(_yieldVault);
        cashReserveBps = _cashReserveBps;
        if (_yieldVault != address(0)) {
            usdc.forceApprove(_yieldVault, type(uint256).max);
            _rebalanceToYieldVault();
        }
        emit YieldVaultConfigured(_yieldVault, _cashReserveBps);
    }

    /**
     * @notice Internal balance rebalancer: routes idle cash above liquid reserve to yield strategy.
     */
    function _rebalanceToYieldVault() internal {
        if (address(yieldVault) == address(0)) return;
        uint256 currentCash = usdc.balanceOf(address(this));
        uint256 totalShares = yieldVault.balanceOf(address(this));
        uint256 totalInYield = totalShares > 0 ? yieldVault.previewRedeem(totalShares) : 0;
        uint256 totalManaged = currentCash + totalInYield;
        uint256 targetCash = (totalManaged * cashReserveBps) / 10000;
        if (currentCash > targetCash) {
            uint256 excess = currentCash - targetCash;
            if (excess >= 1e6) { // Minimum $1.00 deposit
                yieldVault.deposit(excess, address(this));
                principalInYield += excess;
            }
        }
    }

    /**
     * @notice Internal liquidity guarantee: synchronously redeems from yield vault if pure cash is deficient.
     */
    function _ensureLiquidCash(uint256 neededCash) internal {
        uint256 currentCash = usdc.balanceOf(address(this));
        if (currentCash < neededCash && address(yieldVault) != address(0)) {
            uint256 deficit = neededCash - currentCash;
            uint256 totalShares = yieldVault.balanceOf(address(this));
            uint256 maxRedeemable = totalShares > 0 ? yieldVault.previewRedeem(totalShares) : 0;
            uint256 toWithdraw = deficit > maxRedeemable ? maxRedeemable : deficit;
            if (toWithdraw > 0) {
                yieldVault.withdraw(toWithdraw, address(this), address(this));
                if (toWithdraw > principalInYield) {
                    principalInYield = 0;
                } else {
                    principalInYield -= toWithdraw;
                }
            }
        }
    }

    /**
     * @notice Harvest accrued lending yield and distribute to insurance reserve and treasury.
     */
    function harvestYield() external nonReentrant returns (uint256 yieldAmount) {
        if (address(yieldVault) == address(0)) return 0;
        uint256 totalShares = yieldVault.balanceOf(address(this));
        if (totalShares == 0) return 0;
        uint256 totalValue = yieldVault.previewRedeem(totalShares);
        if (totalValue > principalInYield) {
            yieldAmount = totalValue - principalInYield;
            if (yieldAmount >= 1e6) {
                yieldVault.withdraw(yieldAmount, address(this), address(this));
                totalYieldHarvested += yieldAmount;

                uint256 insAmt = (yieldAmount * 60) / 100;
                uint256 trsAmt = yieldAmount - insAmt;
                if (insAmt > 0) usdc.safeTransfer(insuranceReserve, insAmt);
                if (trsAmt > 0) usdc.safeTransfer(treasury, trsAmt);

                emit YieldHarvested(yieldAmount, insAmt, trsAmt);
            }
        }
    }

    /**
     * @notice Set protocol fee basis points (capped at MAX_FEE_BPS = 25 bps / 0.25%).
     */
    function setProtocolFeeBps(uint256 newFeeBps) external {
        if (msg.sender != treasury) revert Unauthorized();
        if (newFeeBps > MAX_FEE_BPS) revert FeeExceedsCap();
        protocolFeeBps = newFeeBps;
        emit ProtocolFeeUpdated(newFeeBps);
    }

    /**
     * @notice Derives public Ethereum address from private key scalar in O(1) (~7,162 gas).
     */
    function deriveAddress(uint256 sk) public pure returns (address) {
        if (sk == 0 || sk >= SECP256K1_N) revert InvalidKey();
        uint256 rSk = mulmod(GX, sk, SECP256K1_N);
        uint256 e = addmod(1, SECP256K1_N - rSk, SECP256K1_N);
        address recovered = ecrecover(bytes32(e), V_BASE, bytes32(GX), bytes32(uint256(1)));
        if (recovered == address(0)) revert InvalidKey();
        return recovered;
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function hashTypedDataV4(bytes32 structHash) external view returns (bytes32) {
        return _hashTypedDataV4(structHash);
    }
}
