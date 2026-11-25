// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

contract CredentialRegistry is AccessControl, Pausable {

    // ===== Part 1: Roles =====

    // role for universities
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    event IssuerAdded(address issuer);
    event IssuerRemoved(address issuer);

    // deployer becomes the admin
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function addIssuer(address issuer) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(issuer != address(0), "Invalid address");
        require(!hasRole(ISSUER_ROLE, issuer), "Already an issuer");

        _grantRole(ISSUER_ROLE, issuer);
        emit IssuerAdded(issuer);
    }

    function removeIssuer(address issuer) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(hasRole(ISSUER_ROLE, issuer), "Not an issuer");

        _revokeRole(ISSUER_ROLE, issuer);
        emit IssuerRemoved(issuer);
    }

    // emergency stop
    function pause() public onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ===== Part 2: Issuing =====


    // ===== Part 3: Revoke & Verify =====

}