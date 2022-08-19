pragma solidity >=0.8.0;

contract Counter {
    uint256 private value;
    address private last_caller;

    constructor() {
        value = 1;
        last_caller = msg.sender;
    }

    fallback() external payable { value = 5; }

    function inc() public {
        value += 1;
        last_caller = msg.sender;
    }

    function add(uint delta) public {
        value += delta;
        last_caller = msg.sender;
    }

    function get_value() view public returns (uint) {
        return value;
    }

    function get_last_caller() view public returns (address) {
        return last_caller;
    }
}