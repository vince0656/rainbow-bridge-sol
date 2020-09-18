pragma solidity ^0.5.0;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "../../nearprover/contracts/INearProver.sol";
import "../../nearprover/contracts/ProofDecoder.sol";
import "../../nearbridge/contracts/NearDecoder.sol";
import "../../nearbridge/contracts/Borsh.sol";

// ERC721Locker is linked to a non-fungible token on Ethereum side and mintable non-fungible
// token on NEAR side, it also links to the prover that it uses to unlock the tokens.
contract ERC721TokenLocker {

    using Borsh for Borsh.Data;
    using ProofDecoder for Borsh.Data;
    using NearDecoder for Borsh.Data;

    IERC721 public ethToken;
    bytes public nearToken;
    INearProver public prover;

    // OutcomeReciptId -> Used
    mapping(bytes32 => bool) public usedEvents_;  // when an event from the NEAR side has been used to unlock a token

    event Locked(
        address indexed token,
        address indexed sender,
        uint256 amount, // leaving the name of the event field [amount] unchanged FOR NOW. It will be used as the tokenId
        string accountId
    );

    event Unlocked(
        uint128 amount, // leaving the name of the event field [amount] unchanged FOR NOW. It will be used as the tokenId
        address recipient
    );

    // Function output from burning fungible token on Near side.
    struct BurnResult {
        uint128 tokenId; // this could limit which projects are able to use this contract if their token Id requires a bigger int
        address recipient;
    }

    constructor(IERC721 _ethToken, bytes memory _nearToken, INearProver _prover) public {
        ethToken = _ethToken;
        nearToken = _nearToken;
        prover = _prover;
    }

    function lockToken(uint256 tokenId, string calldata accountId) external {
        ethToken.transferFrom(msg.sender, address(this), tokenId);

        emit Locked(address(ethToken), msg.sender, tokenId, accountId);
    }

    function unlockToken(bytes calldata proofData, uint64 proofBlockHeight) external {
        require(prover.proveOutcome(proofData, proofBlockHeight), "Proof should be valid");

        // Unpack the proof and extract the execution outcome.
        Borsh.Data memory borshData = Borsh.from(proofData);
        ProofDecoder.FullOutcomeProof memory fullOutcomeProof = borshData.decodeFullOutcomeProof();
        require(borshData.finished(), "Argument should be exact borsh serialization");

        bytes32 receiptId = fullOutcomeProof.outcome_proof.outcome_with_id.outcome.receipt_ids[0];
        require(!usedEvents_[receiptId], "The burn event cannot be reused");
        usedEvents_[receiptId] = true;

        require(keccak256(fullOutcomeProof.outcome_proof.outcome_with_id.outcome.executor_id) == keccak256(nearToken),
        "Can only unlock tokens from the linked mintable fungible token on Near blockchain.");

        ProofDecoder.ExecutionStatus memory status = fullOutcomeProof.outcome_proof.outcome_with_id.outcome.status;
        require(!status.failed, "Cannot use failed execution outcome for unlocking the tokens.");
        require(!status.unknown, "Cannot use unknown execution outcome for unlocking the tokens.");

        BurnResult memory result = _decodeBurnResult(status.successValue);
        ethToken.transferFrom(address(this), result.recipient, result.tokenId);

        emit Unlocked(result.tokenId, result.recipient);
    }

    function _decodeBurnResult(bytes memory data) internal pure returns(BurnResult memory result) {
        Borsh.Data memory borshData = Borsh.from(data);
        result.tokenId = borshData.decodeU128();
        bytes20 recipient = borshData.decodeBytes20();
        result.recipient = address(uint160(recipient));
    }
}
