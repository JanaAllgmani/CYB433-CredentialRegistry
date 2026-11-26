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

    
    /// @notice Lifecycle of a credential.
    /// None    = the hash was never issued (default value of an empty slot)
    /// Active  = issued and valid
    /// Revoked = withdrawn by the university that issued it
    /// Expired = never stored; returned by verify when expiresAt has passed
    enum Status {
        None,
        Active,
        Revoked,
        Expired
    }

    /// @notice One credential. Packed into ONE storage slot (32 bytes):
    /// address (20) + uint40 (5) + uint40 (5) + Status (1) = 31 bytes.
    /// No personal data here: the key of the mapping is the hash of the degree.
    struct Credential {
        address issuer;    // university that issued it (only it may revoke)
        uint40 issuedAt;   // block.timestamp when issued
        uint40 expiresAt;  // 0 = never expires
        Status status;     // current state
    }

    /// @notice credentialHash => Credential. Direct lookup, no loops.
    mapping(bytes32 => Credential) internal _credentials;

    /// @notice How many credentials each university has issued (for statistics).
    mapping(address => uint256) public issuedCount;

    // ---- Custom errors (cheaper than require strings) ----
    error ZeroHash();
    error CredentialAlreadyExists(bytes32 credentialHash);
    error InvalidExpiry(uint256 expiresAt);
    error CredentialNotFound(bytes32 credentialHash);

    // ---- Events (one for every state change) ----
    event CredentialIssued(
        bytes32 indexed credentialHash,
        address indexed issuer,
        uint40 issuedAt,
        uint40 expiresAt
    );
    event CredentialRevoked(
        bytes32 indexed credentialHash,
        address indexed issuer,
        bytes32 reasonHash
    );


    /// @notice A trusted university issues a new credential.
    /// @param credentialHash keccak256 of the degree data + a secret salt, computed off-chain
    /// @param expiresAt      Unix time when it expires, or 0 if it never expires
    function issueCredential(bytes32 credentialHash, uint40 expiresAt)
        external
        onlyRole(ISSUER_ROLE)
        whenNotPaused
    {
        // 1) the hash must not be empty
        if (credentialHash == bytes32(0)) revert ZeroHash();

        // 2) no duplicates: the hash must never have been used before
        //    (this also blocks re-issuing a revoked credential)
        if (_credentials[credentialHash].status != Status.None) {
            revert CredentialAlreadyExists(credentialHash);
        }

        // 3) the expiry date (if any) must be in the future
        if (expiresAt != 0 && expiresAt <= block.timestamp) {
            revert InvalidExpiry(expiresAt);
        }

        uint40 nowTs = uint40(block.timestamp);

        // 4) save it (one storage write, because the struct is packed)
        _credentials[credentialHash] = Credential({
            issuer: msg.sender,
            issuedAt: nowTs,
            expiresAt: expiresAt,
            status: Status.Active
        });

        unchecked {
            ++issuedCount[msg.sender]; // cannot realistically overflow
        }

        // 5) record the change
        emit CredentialIssued(credentialHash, msg.sender, nowTs, expiresAt);
    }

    /// @notice Read the raw stored record (helper for verify and for tests).
    function getCredential(bytes32 credentialHash)
        external
        view
        returns (Credential memory)
    {
        Credential memory c = _credentials[credentialHash];
        if (c.status == Status.None) revert CredentialNotFound(credentialHash);
        return c;
    }

    // ===== Part 3: Revoke & Verify =====
    error NotOriginalIssuer(bytes32 credentialHash, address caller);
    error CredentialNotActive(bytes32 credentialHash);
        /// @notice The university that issued a credential withdraws it.
    /// @param reasonHash Hash of the reason (kept off-chain for privacy).
    function revokeCredential(bytes32 credentialHash, bytes32 reasonHash)
        external
        onlyRole(ISSUER_ROLE)
        whenNotPaused
    {
        Credential storage c = _credentials[credentialHash];

        // 1) The credential must exist
        if (c.status == Status.None) revert CredentialNotFound(credentialHash);

        // 2) Only the original issuer can revoke it
        if (c.issuer != msg.sender) revert NotOriginalIssuer(credentialHash, msg.sender);

        // 3) It must still be active
        if (c.status != Status.Active) revert CredentialNotActive(credentialHash);

        // 4) Change the state and record it
        c.status = Status.Revoked;
        emit CredentialRevoked(credentialHash, msg.sender, reasonHash);
    }
        /// @notice Anyone can check a credential. Expired is calculated here, never stored.
    function verifyCredential(bytes32 credentialHash)
        external
        view
        returns (bool isValid, Status status, address issuer, uint40 expiresAt)
    {
        Credential memory c = _credentials[credentialHash];
        status = c.status;

        // Check whether an active credential has expired
        if (status == Status.Active && c.expiresAt != 0 && block.timestamp >= c.expiresAt) {
            status = Status.Expired;
        }

        return (status == Status.Active, status, c.issuer, c.expiresAt);
    }
}
