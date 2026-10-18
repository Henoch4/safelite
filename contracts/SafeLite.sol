// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SafeLite — minimal multisig. Owners + threshold set once at setup;
/// execution needs >= threshold owner signatures (EIP-191 personal_sign)
/// over (chainid, safe, to, value, dataHash, nonce), sorted ascending.
/// Nonce bumps per execution: no replays. The infra every ecosystem needs.
contract SafeLite is ReentrancyGuard {
    address[] private _owners;
    mapping(address => bool) public isOwner;
    uint256 public threshold;
    uint256 public nonce;
    bool private _setup;

    event Setup(address[] owners, uint256 threshold);
    event Executed(address indexed to, uint256 value, uint256 nonce);
    event Deposit(address indexed from, uint256 amount);

    function setup(address[] calldata owners, uint256 _threshold) external {
        require(!_setup, "Setup done");
        require(owners.length > 0 && _threshold > 0 && _threshold <= owners.length, "Bad config");
        for (uint256 i = 0; i < owners.length; i++) {
            require(owners[i] != address(0), "Zero owner");
            require(!isOwner[owners[i]], "Duplicate owner");
            isOwner[owners[i]] = true;
            _owners.push(owners[i]);
        }
        threshold = _threshold;
        _setup = true;
        emit Setup(owners, _threshold);
    }

    function domainHash(address to, uint256 value, bytes32 dataHash, uint256 n) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), to, value, dataHash, n));
    }

    function exec(address to, uint256 value, bytes calldata data, bytes[] calldata sigs) external nonReentrant {
        require(_setup, "No setup");
        require(sigs.length >= threshold, "Not enough sigs");
        bytes32 h = MessageHashUtils.toEthSignedMessageHash(domainHash(to, value, keccak256(data), nonce));
        address prev = address(0);
        for (uint256 i = 0; i < sigs.length; i++) {
            address r = ECDSA.recover(h, sigs[i]);
            require(isOwner[r], "Not owner");
            require(r > prev, "Dup/order");
            prev = r;
        }
        nonce++;
        (bool ok, ) = to.call{value: value}(data);
        require(ok, "Exec failed");
        emit Executed(to, value, nonce - 1);
    }

    function getOwners() external view returns (address[] memory) {
        return _owners;
    }

    receive() external payable {
        emit Deposit(msg.sender, msg.value);
    }
}

/// @title SafeLiteFactory — deploy tracked minimal multisigs in one call.
contract SafeLiteFactory {
    address[] private _safes;

    event SafeCreated(address indexed safe, address indexed creator);

    function create(address[] calldata owners, uint256 threshold) external returns (address) {
        SafeLite s = new SafeLite();
        s.setup(owners, threshold);
        _safes.push(address(s));
        emit SafeCreated(address(s), msg.sender);
        return address(s);
    }

    function totalSafes() external view returns (uint256) {
        return _safes.length;
    }

    function safeAt(uint256 i) external view returns (address) {
        return _safes[i];
    }
}
