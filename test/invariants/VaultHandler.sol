// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/PerformanceCollateralVault.sol";
import "../../contracts/SwarmDelegationVault.sol";
import "../../contracts/MockUSDC.sol";

contract VaultHandler is Test {
    SwarmDelegationVault public vault;
    MockUSDC public usdc;

    address public treasury;
    address public insuranceReserve;
    address public finder;

    uint256 public constant NUM_AGENTS = 3;
    uint256 public constant NUM_VENDORS = 2;

    address[NUM_AGENTS] public agents;
    uint256[NUM_AGENTS] public agentPks;
    address[NUM_AGENTS] public agentSigners;

    address[NUM_VENDORS] public vendors;
    uint256[NUM_VENDORS] public vendorPks;

    // Subagent keys for Swarm delegation testing
    uint256[NUM_AGENTS] public subAgentPks;
    address[NUM_AGENTS] public subAgentSigners;

    // Ghost accounting variables for exact conservation law
    uint256 public ghost_totalDeposited;
    uint256 public ghost_totalWithdrawn;
    uint256 public ghost_totalSettled;
    uint256 public ghost_totalRestitutionClaimed;
    uint256 public ghost_totalFinderBounties;
    uint256 public ghost_totalInsurancePaid;
    uint256 public ghost_totalTreasuryPaid;
    uint256 public ghost_totalCommitBondsDeposited;
    uint256 public ghost_totalCommitBondsRefunded;

    mapping(address => uint256) public ghost_agentDeposits;
    mapping(address => mapping(address => uint64)) public ghost_channelHeights;
    mapping(address => mapping(address => uint256)) public ghost_cumulativeSettled;

    mapping(address => uint256) public ghost_initialRestitutionPool;
    mapping(address => uint256) public ghost_agentRestitutionClaimed;
    mapping(address => uint256) public ghost_agentRestitutionSwept;

    bytes32 public constant CHEQUE_TYPEHASH = keccak256(
        "Cheque(address agent,address vendor,uint256 cumulativeAmount,uint256 sessionNonce,uint256 deadline)"
    );

    bytes32 public constant MUTUAL_CLOSE_TYPEHASH = keccak256(
        "MutualClose(address agent,address vendor,uint256 finalSettledAmount,uint256 releasedExposure,uint256 sessionNonce,uint256 deadline)"
    );

    constructor(
        SwarmDelegationVault _vault,
        MockUSDC _usdc,
        address _treasury,
        address _insurance,
        address _finder
    ) {
        vault = _vault;
        usdc = _usdc;
        treasury = _treasury;
        insuranceReserve = _insurance;
        finder = _finder;

        for (uint256 i = 0; i < NUM_AGENTS; i++) {
            agentPks[i] = 0x1000 + i + 1;
            agentSigners[i] = vm.addr(agentPks[i]);
            agents[i] = address(uint160(0x2000 + i + 1));
            subAgentPks[i] = 0x5000 + i + 1;
            subAgentSigners[i] = vm.addr(subAgentPks[i]);

            vm.label(agents[i], string.concat("Agent_", vm.toString(i)));
            vm.label(agentSigners[i], string.concat("Signer_", vm.toString(i)));
            vm.label(subAgentSigners[i], string.concat("SubAgent_", vm.toString(i)));
        }

        for (uint256 j = 0; j < NUM_VENDORS; j++) {
            vendorPks[j] = 0x3000 + j + 1;
            vendors[j] = vm.addr(vendorPks[j]);
            vm.label(vendors[j], string.concat("Vendor_", vm.toString(j)));
        }

        // Fund finder with USDC for commit bonds
        usdc.mint(finder, 10_000 * 1e6);
    }

    function _getFreeCollateral(address agent) internal view returns (uint256) {
        (uint256 bond,,,, uint256 pending,, bool isSlashed) = vault.vaults(agent);
        if (isSlashed) return 0;
        uint256 allocated = vault.totalAllocatedExposure(agent);
        uint256 reserved = allocated + pending;
        return bond > reserved ? bond - reserved : 0;
    }

    function deposit(uint256 agentIdxSeed, uint256 amountRaw) public {
        uint256 agentIdx = agentIdxSeed % NUM_AGENTS;
        address agent = agents[agentIdx];
        uint256 amount = bound(amountRaw, 1e6, 50_000 * 1e6); // $1 to $50,000

        (uint256 bond,, address signer,,,, bool isSlashed) = vault.vaults(agent);
        if (isSlashed) return;

        usdc.mint(agent, amount);
        vm.startPrank(agent);
        usdc.approve(address(vault), amount);
        address targetSigner = signer == address(0) ? agentSigners[agentIdx] : signer;
        vault.depositCollateral(amount, keccak256(abi.encodePacked("root", agent)), targetSigner);
        vm.stopPrank();

        ghost_totalDeposited += amount;
        ghost_agentDeposits[agent] += amount;
    }

    function allocateExposure(uint256 agentIdxSeed, uint256 vendorIdxSeed, uint256 amountRaw) public {
        uint256 agentIdx = agentIdxSeed % NUM_AGENTS;
        uint256 vendorIdx = vendorIdxSeed % NUM_VENDORS;
        address agent = agents[agentIdx];
        address vendor = vendors[vendorIdx];

        (uint256 bond,,,,,, bool isSlashed) = vault.vaults(agent);
        if (bond == 0 || isSlashed) return;
        if (block.number <= vault.disputeLocks(agent)) return;

        uint256 unallocated = _getFreeCollateral(agent);
        if (unallocated == 0) return;

        uint256 amount = bound(amountRaw, 1, unallocated);

        vm.prank(agent);
        vault.allocateSessionExposure(vendor, amount);
    }

    function cooperativeClose(
        uint256 agentIdxSeed,
        uint256 vendorIdxSeed,
        uint256 releasePctRaw
    ) public {
        uint256 agentIdx = agentIdxSeed % NUM_AGENTS;
        uint256 vendorIdx = vendorIdxSeed % NUM_VENDORS;
        address agent = agents[agentIdx];
        address vendor = vendors[vendorIdx];

        (uint256 bond,,,,,, bool isSlashed) = vault.vaults(agent);
        if (bond == 0 || isSlashed) return;
        if (block.number <= vault.disputeLocks(agent)) return;

        uint256 allocated = vault.vendorExposure(agent, vendor);
        if (allocated == 0) return;

        uint256 releasePct = bound(releasePctRaw, 1, 100);
        uint256 releasedExposure = (allocated * releasePct) / 100;
        if (releasedExposure == 0) releasedExposure = allocated;

        uint256 currentSettled = ghost_cumulativeSettled[agent][vendor];
        uint64 newHeight = ghost_channelHeights[agent][vendor] + 1;
        uint256 sessionNonce = uint256(newHeight);
        uint256 deadline = block.timestamp + 1000;

        // Mutual Close EIP-712 signature by Vendor
        bytes32 structHash = keccak256(
            abi.encode(
                MUTUAL_CLOSE_TYPEHASH,
                agent,
                vendor,
                currentSettled,
                releasedExposure,
                sessionNonce,
                deadline
            )
        );
        bytes32 digest = vault.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(vendorPks[vendorIdx], digest);
        bytes memory vendorSig = abi.encodePacked(r, s, v);

        vm.prank(agent);
        vault.cooperativeCloseSession(
            vendor,
            currentSettled,
            releasedExposure,
            sessionNonce,
            deadline,
            vendorSig
        );

        ghost_channelHeights[agent][vendor] = newHeight;
    }

    function instantWithdraw(uint256 agentIdxSeed, uint256 amountRaw) public {
        uint256 agentIdx = agentIdxSeed % NUM_AGENTS;
        address agent = agents[agentIdx];

        (uint256 bond,,,,,, bool isSlashed) = vault.vaults(agent);
        if (bond == 0 || isSlashed) return;
        if (block.number <= vault.disputeLocks(agent)) return;

        uint256 unallocated = _getFreeCollateral(agent);
        if (unallocated == 0) return;

        uint256 amount = bound(amountRaw, 1, unallocated);

        vm.prank(agent);
        vault.instantWithdraw(amount);

        ghost_totalWithdrawn += amount;
    }

    function settleCheque(uint256 agentIdxSeed, uint256 vendorIdxSeed, uint256 deltaRaw) public {
        uint256 agentIdx = agentIdxSeed % NUM_AGENTS;
        uint256 vendorIdx = vendorIdxSeed % NUM_VENDORS;
        address agent = agents[agentIdx];
        address vendor = vendors[vendorIdx];

        (uint256 bond,, address signer,,,, bool isSlashed) = vault.vaults(agent);
        if (bond == 0 || isSlashed || signer == address(0)) return;
        if (block.number <= vault.disputeLocks(agent)) return;

        uint256 allocated = vault.vendorExposure(agent, vendor);
        if (allocated == 0) return;

        uint256 maxDelta = allocated > bond ? bond : allocated;
        if (maxDelta == 0) return;

        uint256 prevCumulative = ghost_cumulativeSettled[agent][vendor];
        uint256 delta = bound(deltaRaw, 1, maxDelta);
        uint256 newCumulative = prevCumulative + delta;
        uint64 newHeight = ghost_channelHeights[agent][vendor] + 1;
        uint256 sessionNonce = uint256(newHeight);
        uint256 deadline = block.timestamp + 1000;

        bytes32 chequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, agent, vendor, newCumulative, sessionNonce, deadline)
        );
        bytes32 digest = vault.hashTypedDataV4(chequeHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPks[agentIdx], digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(vendor);
        vault.settleCheque(agent, newCumulative, sessionNonce, deadline, sig);

        ghost_channelHeights[agent][vendor] = newHeight;
        ghost_cumulativeSettled[agent][vendor] = newCumulative;
        ghost_totalSettled += delta;
    }

    function initiateEmergencyWithdrawal(uint256 agentIdxSeed, uint256 amountRaw) public {
        uint256 agentIdx = agentIdxSeed % NUM_AGENTS;
        address agent = agents[agentIdx];

        (uint256 bond,,,, uint256 pending,, bool isSlashed) = vault.vaults(agent);
        if (bond == 0 || isSlashed || pending > 0) return;
        if (block.number <= vault.disputeLocks(agent)) return;

        uint256 unallocated = _getFreeCollateral(agent);
        if (unallocated == 0) return;

        uint256 amount = bound(amountRaw, 1, unallocated);

        vm.prank(agent);
        vault.initiateEmergencyWithdrawal(amount);
    }

    function finalizeEmergencyWithdrawal(uint256 agentIdxSeed) public {
        uint256 agentIdx = agentIdxSeed % NUM_AGENTS;
        address agent = agents[agentIdx];

        (uint256 bond,,,, uint256 pending, uint256 timestamp, bool isSlashed) = vault.vaults(agent);
        if (bond == 0 || isSlashed || pending == 0) return;
        if (block.timestamp < timestamp + vault.EMERGENCY_DISPUTE_PERIOD()) {
            vm.warp(timestamp + vault.EMERGENCY_DISPUTE_PERIOD() + 1);
        }
        if (block.number <= vault.disputeLocks(agent)) return;

        uint256 amountToTransfer = pending > bond ? bond : pending;

        vm.prank(agent);
        vault.finalizeEmergencyWithdrawal();

        ghost_totalWithdrawn += amountToTransfer;
    }

    function cancelEmergencyWithdrawal(uint256 agentIdxSeed) public {
        uint256 agentIdx = agentIdxSeed % NUM_AGENTS;
        address agent = agents[agentIdx];

        (uint256 bond,,,, uint256 pending,, bool isSlashed) = vault.vaults(agent);
        if (isSlashed || pending == 0) return;

        vm.prank(agent);
        vault.cancelEmergencyWithdrawal();
    }

    function slashAgent(uint256 agentIdxSeed) public {
        uint256 agentIdx = agentIdxSeed % NUM_AGENTS;
        address agent = agents[agentIdx];

        (uint256 bond,, address signer,,,, bool isSlashed) = vault.vaults(agent);
        if (bond == 0 || isSlashed || signer == address(0)) return;
        if (block.number <= vault.disputeLocks(agent)) return;

        bytes32 salt = keccak256(abi.encodePacked("salt", agent, block.number));
        bytes32 commitHash = keccak256(abi.encodePacked(agentPks[agentIdx], finder, salt));

        // Commit fraud proof (1 USDC anti-spam bond)
        vm.prank(finder);
        vault.commitFraudProof(agent, commitHash);
        ghost_totalCommitBondsDeposited += 1e6;

        // Roll blocks forward to satisfy MIN_COMMIT_DELAY
        vm.roll(block.number + 2);

        PerformanceCollateralVault.SlashArgs memory args = PerformanceCollateralVault.SlashArgs({
            maliciousAgent: agent,
            extractedSk: agentPks[agentIdx],
            salt: salt
        });

        uint256 totalBond = bond;
        uint256 bounty = (totalBond * 15) / 100;
        uint256 remaining = totalBond - bounty;
        uint256 totalReserved = vault.totalAllocatedExposure(agent);
        uint256 restitutionAllocation = remaining > totalReserved ? totalReserved : remaining;
        remaining -= restitutionAllocation;
        uint256 insuranceAmount = (remaining * 60) / 100;
        uint256 treasuryAmount = remaining - insuranceAmount;

        vm.prank(finder);
        vault.revealAndSlash(args);

        // Finder receives 1 USDC bond back
        ghost_totalCommitBondsRefunded += 1e6;

        ghost_totalFinderBounties += bounty;
        ghost_totalInsurancePaid += insuranceAmount;
        ghost_totalTreasuryPaid += treasuryAmount;
        ghost_initialRestitutionPool[agent] = restitutionAllocation;
    }

    function claimRestitution(uint256 agentIdxSeed, uint256 vendorIdxSeed) public {
        uint256 agentIdx = agentIdxSeed % NUM_AGENTS;
        uint256 vendorIdx = vendorIdxSeed % NUM_VENDORS;
        address agent = agents[agentIdx];
        address vendor = vendors[vendorIdx];

        uint256 pool = vault.slashedRestitutionPool(agent);
        if (pool == 0) return;

        uint256 activeQuota = vault.vendorExposure(agent, vendor);
        if (activeQuota == 0) return;

        uint256 prevCumulative = ghost_cumulativeSettled[agent][vendor];
        uint256 delta = activeQuota > pool ? pool : activeQuota;
        if (delta == 0) return;

        uint256 newCumulative = prevCumulative + delta;
        uint64 newHeight = ghost_channelHeights[agent][vendor] + 1;
        uint256 sessionNonce = uint256(newHeight);
        uint256 deadline = block.timestamp + 1000;

        bytes32 chequeHash = keccak256(
            abi.encode(CHEQUE_TYPEHASH, agent, vendor, newCumulative, sessionNonce, deadline)
        );
        bytes32 digest = vault.hashTypedDataV4(chequeHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPks[agentIdx], digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(vendor);
        vault.claimSlashedRestitution(agent, newCumulative, sessionNonce, deadline, sig);

        ghost_channelHeights[agent][vendor] = newHeight;
        ghost_cumulativeSettled[agent][vendor] = newCumulative;
        ghost_totalRestitutionClaimed += delta;
        ghost_agentRestitutionClaimed[agent] += delta;
    }

    function sweepRestitution(uint256 agentIdxSeed) public {
        uint256 agentIdx = agentIdxSeed % NUM_AGENTS;
        address agent = agents[agentIdx];

        (,,,,,, bool isSlashed) = vault.vaults(agent);
        if (!isSlashed) return;

        uint256 pool = vault.slashedRestitutionPool(agent);
        if (pool == 0) return;

        uint256 slashTime = vault.slashTimestamps(agent);
        if (block.timestamp < slashTime + vault.EMERGENCY_DISPUTE_PERIOD()) {
            vm.warp(slashTime + vault.EMERGENCY_DISPUTE_PERIOD() + 1);
        }

        uint256 insuranceAmount = (pool * 60) / 100;
        uint256 treasuryAmount = pool - insuranceAmount;

        vault.sweepUnclaimedRestitution(agent);

        ghost_totalInsurancePaid += insuranceAmount;
        ghost_totalTreasuryPaid += treasuryAmount;
        ghost_agentRestitutionSwept[agent] += pool;
    }
}
