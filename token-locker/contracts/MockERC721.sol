pragma solidity ^0.5.0;

import "@openzeppelin/contracts/token/ERC721/ERC721Full.sol";

contract MockERC721 is ERC721Full("NonFungible","NFT") {
    constructor() public {
        _mint(msg.sender, 1000);
    }

    function mint(address _beneficiary, uint256 _tokenId) public {
        _mint(_beneficiary, _tokenId);
    }
}
