pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2; // solium-disable-line no-experimental

import "@openzeppelin/contracts/math/SafeMath.sol";
import "@openzeppelin/contracts/ownership/Ownable.sol";
import "./INearBridge.sol";
import "./NearDecoder.sol";
import "./Ed25519.sol";


contract NearBridge is INearBridge {
    using SafeMath for uint256;
    using Borsh for Borsh.Data;
    using NearDecoder for Borsh.Data;

    struct BlockProducer {
        NearDecoder.PublicKey publicKey;
        uint128 stake;
    }

    // Information about the block producers of a certain epoch.
    struct BlockProducerInfo {
        uint256 bpsLength;
        uint256 totalStake;
        mapping(uint256 => BlockProducer) bps;
    }

    // Minimal information about the submitted block.
    struct BlockInfo {
        uint64 height;
        uint256 timestamp;
        bytes32 epochId;
        bytes32 nextEpochId;
        bytes32 hash;
        bytes32 merkleRoot;
        bytes32 next_hash;
        uint256 approvals_after_next_length;
        mapping(uint256 => NearDecoder.OptionalSignature) approvals_after_next;
    }

    // Whether the contract was initialized.
    bool public initialized;
    // The `0` address where we are going to send half of the bond when challenge is successful.
    address payable burner;
    uint256 public lockEthAmount;
    uint256 public lockDuration;
    uint256 public replaceDuration;
    Ed25519 edwards;

    // Block producers of the current epoch.
    BlockProducerInfo public currentBlockProducers;
    // Block producers of the next epoch.
    BlockProducerInfo public nextBlockProducers;

    // The most recent head that is guaranteed to be valid.
    BlockInfo public head;

    // The most recently added block. May still be in its challenge period, so should not be trusted.
    BlockInfo untrustedHead;
    // True if untrustedHead is from the following epoch of currentHead.
    // False if it is from the same epoch.
    bool untrustedHeadIsFromNextEpoch;
    // Next block producers from untrustedHead, if any.
    BlockProducerInfo untrustedNextBlockProducers;
    // Address of the account which submitted the last block.
    address lastSubmitter;
    // End of challenge period, or zero if there is no block to be challenged.
    uint lastValidAt;

    mapping(uint64 => bytes32) blockHashes_;
    mapping(uint64 => bytes32) blockMerkleRoots_;
    mapping(address => uint256) public balanceOf;

    event BlockHashAdded(
        uint64 indexed height,
        bytes32 blockHash
    );

    event BlockHashReverted(
        uint64 indexed height,
        bytes32 blockHash
    );

    constructor(Ed25519 ed, uint256 _lockEthAmount, uint256 _lockDuration, uint256 _replaceDuration) public {
        edwards = ed;
        lockEthAmount = _lockEthAmount;
        lockDuration = _lockDuration;
        replaceDuration = _replaceDuration;
        burner = address(0);
    }

    function deposit() public payable {
        require(msg.value == lockEthAmount && balanceOf[msg.sender] == 0);
        balanceOf[msg.sender] = balanceOf[msg.sender].add(msg.value);
    }

    function withdraw() public {
        require(msg.sender != lastSubmitter || block.timestamp >= lastValidAt);
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(lockEthAmount);
        msg.sender.transfer(lockEthAmount);
    }

    function challenge(address payable receiver, uint256 signatureIndex) public {
        require(block.timestamp < lastValidAt, "No block can be challenged at this time");

        require(
            !checkBlockProducerSignatureInHead(signatureIndex),
            "Can't challenge valid signature"
        );

        _payRewardAndRollBack(receiver);
    }

    function checkBlockProducerSignatureInHead(uint256 signatureIndex) public view returns(bool) {
        if (untrustedHead.approvals_after_next[signatureIndex].none) {
            return true;
        }
        BlockProducerInfo storage untrustedBlockProducers
            = untrustedHeadIsFromNextEpoch
            ? nextBlockProducers : currentBlockProducers;
        return _checkValidatorSignature(
            untrustedHead.height,
            untrustedHead.next_hash,
            untrustedHead.approvals_after_next[signatureIndex].signature,
            untrustedBlockProducers.bps[signatureIndex].publicKey
        );
    }

    function _payRewardAndRollBack(address payable receiver) internal {
        // Pay reward
        balanceOf[lastSubmitter] = balanceOf[lastSubmitter].sub(lockEthAmount);
        receiver.transfer(lockEthAmount / 2);
        burner.transfer(lockEthAmount - lockEthAmount / 2);

        emit BlockHashReverted(
            untrustedHead.height,
            untrustedHead.hash
        );

        lastValidAt = 0;
    }

    // The first part of initialization -- setting the validators of the current epoch.
    function initWithValidators(bytes memory _initialValidators) public {
        require(!initialized, "NearBridge: already initialized");
        Borsh.Data memory initialValidatorsBorsh = Borsh.from(_initialValidators);
        NearDecoder.InitialValidators memory initialValidators = initialValidatorsBorsh.decodeInitialValidators();
        require(initialValidatorsBorsh.finished(), "NearBridge: only initial validators should be passed as second argument");

        // Set current block producers.
        currentBlockProducers.bpsLength = initialValidators.validator_stakes.length;
        uint256 totalStake = 0;
        for (uint i = 0; i < initialValidators.validator_stakes.length; i++) {
            currentBlockProducers.bps[i] = BlockProducer({
                publicKey: initialValidators.validator_stakes[i].public_key,
                stake: initialValidators.validator_stakes[i].stake
                });
            // Compute total stake
            totalStake = totalStake.add(initialValidators.validator_stakes[i].stake);
        }
        currentBlockProducers.totalStake = totalStake;
    }

    // The second part of the initialization -- setting the current head.
    function initWithBlock(bytes memory data) public {
        require(currentBlockProducers.totalStake > 0, "NearBridge: validators need to be initialized first");
        require(!initialized, "NearBridge: already initialized");
        initialized = true;

        Borsh.Data memory borsh = Borsh.from(data);
        NearDecoder.LightClientBlock memory nearBlock = borsh.decodeLightClientBlock();
        require(borsh.finished(), "NearBridge: only light client block should be passed as first argument");

        require(!nearBlock.next_bps.none, "NearBridge: The first block of the epoch should contain next_bps.");
        setBlockInfo(nearBlock, head, nextBlockProducers);
        blockHashes_[head.height] = head.hash;
        blockMerkleRoots_[head.height] = head.merkleRoot;
    }

    function _checkBp(NearDecoder.LightClientBlock memory nearBlock, BlockProducerInfo storage bpInfo) internal {
        require(nearBlock.approvals_after_next.length >= bpInfo.bpsLength, "NearBridge: number of approvals should be at least as large as number of BPs");

        uint256 votedFor = 0;
        for (uint i = 0; i < bpInfo.bpsLength; i++) {
            if (!nearBlock.approvals_after_next[i].none) {
                // Assume presented signatures are valid, but this could be challenged
                votedFor = votedFor.add(bpInfo.bps[i].stake);
            }
        }
        // Last block in the epoch might contain extra approvals that light client can ignore.

        require(votedFor > bpInfo.totalStake.mul(2).div(3), "NearBridge: Less than 2/3 voted by the block after next");
    }

    function addLightClientBlock(bytes memory data) public {
        require(initialized, "NearBridge: Contract is not initialized.");
        require(balanceOf[msg.sender] >= lockEthAmount, "Balance is not enough");

        Borsh.Data memory borsh = Borsh.from(data);
        NearDecoder.LightClientBlock memory nearBlock = borsh.decodeLightClientBlock();
        require(borsh.finished(), "NearBridge: only light client block should be passed");

        if (block.timestamp >= lastValidAt) {
            if (lastValidAt != 0) {
                commitBlock();
            }
        } else {
            require(nearBlock.inner_lite.timestamp >= untrustedHead.timestamp.add(replaceDuration), "NearBridge: can only replace with a sufficiently newer block");
        }

        // 1. The height of the block is higher than the height of the current head
        require(
            nearBlock.inner_lite.height > head.height,
            "NearBridge: Height of the block is not valid"
        );

        // 2. The epoch of the block is equal to the epoch_id or next_epoch_id known for the current head
        require(
            nearBlock.inner_lite.epoch_id == head.epochId || nearBlock.inner_lite.epoch_id == head.nextEpochId,
            "NearBridge: Epoch id of the block is not valid"
        );

        // 3. If the epoch of the block is equal to the next_epoch_id of the head, then next_bps is not None
        if (nearBlock.inner_lite.epoch_id == head.nextEpochId) {
            require(
                !nearBlock.next_bps.none,
                "NearBridge: Next next_bps should no be None"
            );
        }

        // 4. approvals_after_next contain signatures that check out against the block producers for the epoch of the block
        // 5. The signatures present in approvals_after_next correspond to more than 2/3 of the total stake
        if (nearBlock.inner_lite.epoch_id == head.epochId) {
            // The new block is from the current epoch.
            _checkBp(nearBlock, currentBlockProducers);
        } else {
            // The new block is from the next epoch.
            _checkBp(nearBlock, nextBlockProducers);
        }

        // 6. If next_bps is not none, sha256(borsh(next_bps)) corresponds to the next_bp_hash in inner_lite.
        if (!nearBlock.next_bps.none) {
            require(
                nearBlock.next_bps.hash == nearBlock.inner_lite.next_bp_hash,
                "NearBridge: Hash of block producers do not match"
            );
        }

        setBlockInfo(nearBlock, untrustedHead, untrustedNextBlockProducers);
        untrustedHeadIsFromNextEpoch = nearBlock.inner_lite.epoch_id == head.nextEpochId;
        lastSubmitter = msg.sender;
        lastValidAt = block.timestamp.add(lockDuration);
    }

    function setBlockInfo(
        NearDecoder.LightClientBlock memory src,
        BlockInfo storage destBlock,
        BlockProducerInfo storage destBPs
    )
        internal
    {
        destBlock.height = src.inner_lite.height;
        destBlock.timestamp = src.inner_lite.timestamp;
        destBlock.epochId = src.inner_lite.epoch_id;
        destBlock.nextEpochId = src.inner_lite.next_epoch_id;
        destBlock.hash = src.hash;
        destBlock.merkleRoot = src.inner_lite.block_merkle_root;
        destBlock.next_hash = src.next_hash;
        destBlock.approvals_after_next_length = src.approvals_after_next.length;
        for (uint i = 0; i < src.approvals_after_next.length; i++) {
            destBlock.approvals_after_next[i] = src.approvals_after_next[i];
        }

        if (src.next_bps.none) {
            destBPs.bpsLength = 0;
            destBPs.totalStake = 0;
        } else {
            destBPs.bpsLength = src.next_bps.validatorStakes.length;
            uint256 totalStake = 0;
            for (uint i = 0; i < src.next_bps.validatorStakes.length; i++) {
                destBPs.bps[i] = BlockProducer({
                    publicKey: src.next_bps.validatorStakes[i].public_key,
                    stake: src.next_bps.validatorStakes[i].stake
                });
                totalStake = totalStake.add(src.next_bps.validatorStakes[i].stake);
            }
            destBPs.totalStake = totalStake;
        }

        emit BlockHashAdded(
            src.inner_lite.height,
            src.hash
        );
    }

    function commitBlock() internal {
        require(lastValidAt != 0 && block.timestamp >= lastValidAt, "Nothing to commit");

        head = untrustedHead;
        if (untrustedHeadIsFromNextEpoch) {
            copyBlockProducers(nextBlockProducers, currentBlockProducers);
            copyBlockProducers(untrustedNextBlockProducers, nextBlockProducers);
        }
        lastValidAt = 0;

        blockHashes_[head.height] = head.hash;
        blockMerkleRoots_[head.height] = head.merkleRoot;
    }

    function copyBlockProducers(BlockProducerInfo storage src, BlockProducerInfo storage dest) internal {
        dest.bpsLength = src.bpsLength;
        dest.totalStake = src.totalStake;
        for (uint i = 0; i < src.bpsLength; i++) {
            dest.bps[i] = src.bps[i];
        }
    }

    function _checkValidatorSignature(
        uint64 height,
        bytes32 next_block_hash,
        NearDecoder.Signature memory signature,
        NearDecoder.PublicKey storage publicKey
    ) internal view returns(bool) {
        bytes memory message = abi.encodePacked(uint8(0), next_block_hash, _reversedUint64(height + 2), bytes23(0));

        if (signature.enumIndex == 0) {
            (bytes32 arg1, bytes9 arg2) = abi.decode(message, (bytes32, bytes9));
            return publicKey.ed25519.xy != bytes32(0) && edwards.check(
                publicKey.ed25519.xy,
                signature.ed25519.rs[0],
                signature.ed25519.rs[1],
                arg1,
                arg2
            );
        }
        else {
            return ecrecover(
                keccak256(message),
                signature.secp256k1.v + (signature.secp256k1.v < 27 ? 27 : 0),
                signature.secp256k1.r,
                signature.secp256k1.s
                ) == address(uint256(keccak256(abi.encodePacked(
                publicKey.secp256k1.x,
                publicKey.secp256k1.y
            ))));
        }
    }

    function _reversedUint64(uint64 data) private pure returns(uint64 r) {
        r = data;
        r = ((r & 0x00000000FFFFFFFF) << 32) |
            ((r & 0xFFFFFFFF00000000) >> 32);
        r = ((r & 0x0000FFFF0000FFFF) << 16) |
            ((r & 0xFFFF0000FFFF0000) >> 16);
        r = ((r & 0x00FF00FF00FF00FF) << 8) |
            ((r & 0xFF00FF00FF00FF00) >> 8);
    }

    function blockHashes(uint64 height) public view returns (bytes32 res) {
        res = blockHashes_[height];
        if (res == 0 && block.timestamp >= lastValidAt && lastValidAt != 0 && height == untrustedHead.height) {
            res = untrustedHead.hash;
        }
    }

    function blockMerkleRoots(uint64 height) public view returns (bytes32 res) {
        res = blockMerkleRoots_[height];
        if (res == 0 && block.timestamp >= lastValidAt && lastValidAt != 0 && height == untrustedHead.height) {
            res = untrustedHead.merkleRoot;
        }
    }
}
