// FIXTURE: intentionally vulnerable contract (for x402guard tests)
pragma solidity ^0.8.20;

contract Vuln {
    address public owner;
    address public usdc;

    // privileged setter with NO access modifier + value move with NO nonReentrant guard
    function withdrawFunds(address to) external {
        IERC20(usdc).safeTransfer(to, address(this).balance);
    }

    // sets owner to the EOA that started the call (unsafe)
    function setOwnerFromOrigin() public {
        owner = tx.origin;
    }
}
