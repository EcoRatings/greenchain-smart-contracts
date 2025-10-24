// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/common/ERC2981.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

/// @title CarbonCreditSBT
/// @notice Single-NFT (no fractionalization), non-transferable (soulbound) carbon credit certificate.
///         Keeps slim attributes: expiry, registry serial uniqueness, tokenURI + metadataHash, vintageYear, optional royalties.
///         1 NFT represents one carbon credit certificate (not divisible, not transferable).
contract CarbonCreditSBT is ERC721, ERC2981, AccessControl {
    using Strings for uint256;

    // -------------------- Roles --------------------
    bytes32 public constant MINTER_ROLE      = keccak256("MINTER_ROLE");
    bytes32 public constant RETIRER_ROLE     = keccak256("RETIRER_ROLE");
    bytes32 public constant URI_MANAGER_ROLE = keccak256("URI_MANAGER_ROLE");

    // -------------------- Collection metadata --------------------
    string public baseURI; // optional prefix for tokenURI if you want; tokenURI can also be full URL
    uint256 private _idCounter;

    // -------------------- Per-token minimal state --------------------
    mapping(uint256 => string)  private _tokenURIs;          // off-chain JSON pointer (IPFS/Arweave/etc.)
    mapping(uint256 => bytes32) public  metadataHash;        // keccak256 of the canonical JSON
    mapping(uint256 => bool)    public  metadataFrozen;      // freeze URI/editing
    mapping(bytes32 => bool)    public  registrySerialUsed;  // uniqueness (hash of lowercased serial)

    mapping(uint256 => uint64)  public  validUntil;          // unix timestamp; 0 = no expiry
    mapping(uint256 => uint16)  public  vintageYear;         // tiny on-chain tag
    mapping(uint256 => bool)    public  retired;             // persists even after burn
    mapping(uint256 => bool)    private _minted;             // track existence for views after burn

    // -------------------- Soulbound (EIP-5192) --------------------
    // interfaceId: 0xb45a3c0e
    event Locked(uint256 indexed tokenId);

    // -------------------- Events --------------------
    event CarbonCertificateMinted(
        uint256 indexed id,
        address indexed to,
        uint16 vintageYear,
        bytes32 registrySerialHash,
        string tokenURI,
        bytes32 contentHash
    );
    event CarbonCertificateURISet(uint256 indexed id, string uri);
    event MetadataFrozen(uint256 indexed id, bytes32 contentHash);
    event ValiditySet(uint256 indexed id, uint64 validUntil);
    event CarbonRetired(address indexed from, uint256 indexed id);

    // Multisig/timelock & migration events
    event MultisigMigrationInitiated(address indexed newMultisig, uint256 timestamp);
    event MultisigMigrationCompleted(address indexed oldAdmin, address indexed newMultisig);
    event RolesBatchGranted(address indexed account, bytes32[] roles);
    event DefaultAdminTransferInitiated(address indexed oldAdmin, address indexed newAdmin);
    event DefaultAdminTransferCompleted(address indexed oldAdmin, address indexed newAdmin);

    // -------------------- Constructor --------------------
    constructor(
        string memory collectionName,
        string memory collectionSymbol,
        string memory baseURI_,
        address defaultRoyaltyReceiver,
        uint96 defaultRoyaltyBps
    ) ERC721(collectionName, collectionSymbol) {
        baseURI = baseURI_;
        _idCounter = 1;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(RETIRER_ROLE, msg.sender);
        _grantRole(URI_MANAGER_ROLE, msg.sender);

        if (defaultRoyaltyReceiver != address(0) && defaultRoyaltyBps > 0) {
            require(defaultRoyaltyBps <= _feeDenominator(), "royalty too high");
            _setDefaultRoyalty(defaultRoyaltyReceiver, defaultRoyaltyBps);
        }
    }

    // -------------------- Helpers --------------------
    function _serialKey(string memory s) internal pure returns (bytes32) {
        // basic ASCII lowercasing; ensure any unicode normalization is done off-chain
        bytes memory b = bytes(s);
        for (uint256 i; i < b.length; ++i) {
            uint8 c = uint8(b[i]);
            if (c >= 65 && c <= 90) { // 'A'..'Z'
                b[i] = bytes1(c + 32);
            }
        }
        return keccak256(b);
    }

    // -------------------- Minting --------------------
    /// @param to Recipient (owner) of the soulbound NFT
    /// @param _vintageYear Vintage year (e.g., 2023)
    /// @param registrySerialNumber Human-readable serial (only hash stored for uniqueness)
    /// @param tokenURI_ Off-chain JSON pointer
    /// @param royaltyReceiver Optional per-token royalty receiver (override default)
    /// @param royaltyBps Optional bps (1% = 100)
    /// @param validUntil_ Expiry unix timestamp; 0 = no expiry
    function mintCertificate(
        address to,
        uint16 _vintageYear,
        string calldata registrySerialNumber,
        string calldata tokenURI_,
        bytes32 contentHash,
        address royaltyReceiver,
        uint96 royaltyBps,
        uint64 validUntil_
    ) external onlyRole(MINTER_ROLE) returns (uint256 tokenId) {
        require(to != address(0), "zero address");
        require(_vintageYear > 2000 && _vintageYear <= 2100, "Invalid vintage year");
        require(bytes(registrySerialNumber).length > 0, "Empty registry serial");
        require(royaltyBps <= _feeDenominator(), "royalty too high");

        // Prevent minting immediately expired certificates
        if (validUntil_ != 0) {
            require(validUntil_ > block.timestamp, "validUntil must be in the future");
        }

        bytes32 sk = _serialKey(registrySerialNumber);
        require(!registrySerialUsed[sk], "Registry serial already used");
        registrySerialUsed[sk] = true;

        tokenId = _idCounter++;
        _safeMint(to, tokenId);
        _minted[tokenId] = true;

        vintageYear[tokenId] = _vintageYear;
        validUntil[tokenId]  = validUntil_;
        emit ValiditySet(tokenId, validUntil_);

        if (bytes(tokenURI_).length > 0) {
            require(contentHash != bytes32(0), "content hash required");
            _tokenURIs[tokenId] = tokenURI_;
            metadataHash[tokenId] = contentHash;
            emit CarbonCertificateURISet(tokenId, tokenURI_);
        }

        if (royaltyReceiver != address(0) && royaltyBps > 0) {
            _setTokenRoyalty(tokenId, royaltyReceiver, royaltyBps);
        }

        // Soulbound: emit EIP-5192 Locked on mint
        emit Locked(tokenId);

        emit CarbonCertificateMinted(tokenId, to, _vintageYear, sk, tokenURI_, metadataHash[tokenId]);
    }

    // -------------------- Metadata controls --------------------
    function setURI(uint256 tokenId, string calldata newuri, bytes32 contentHash) external onlyRole(URI_MANAGER_ROLE) {
        _requireOwned(tokenId);
        require(!metadataFrozen[tokenId], "Metadata frozen");
        require(bytes(newuri).length > 0, "Empty URI");
        require(contentHash != bytes32(0), "content hash required");
        _tokenURIs[tokenId] = newuri;
        metadataHash[tokenId] = contentHash;
        emit CarbonCertificateURISet(tokenId, newuri);
    }

    function freezeMetadata(uint256 tokenId) external onlyRole(URI_MANAGER_ROLE) {
        _requireOwned(tokenId);
        metadataFrozen[tokenId] = true;
        emit MetadataFrozen(tokenId, metadataHash[tokenId]);
    }

    // -------------------- Validity admin --------------------
    /// @notice Extend validity (cannot shorten). Governance-controlled.
    function extendValidity(uint256 tokenId, uint64 newValidUntil) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _requireOwned(tokenId);
        // Allow setting to 0 to indicate "no expiry" per audit recommendation (ECA-02).
        // Rules:
        //  - If newValidUntil == 0 -> always allowed (removes expiry, increases flexibility)
        //  - Else must be in the future
        //  - Cannot reduce a non-zero validity to a smaller non-zero timestamp (monotonic unless clearing)
        if (newValidUntil != 0) {
            require(newValidUntil > block.timestamp, "newValidUntil must be future");
            require(newValidUntil >= validUntil[tokenId], "Cannot shorten validity");
        } else {
            // If clearing expiry (setting to 0) ensure we are not making an already expired token active retroactively.
            // This is permitted; governance explicitly chooses to lift the expiry constraint.
            // No additional checks required.
        }
        validUntil[tokenId] = newValidUntil;
        emit ValiditySet(tokenId, newValidUntil);
    }

    // -------------------- Retirement (Burn) --------------------
    /// @notice Burn (retire) the certificate. Blocked after expiry by default.
    ///         Remove the expiry check if you want to allow post-expiry retirement.
    function retire(uint256 tokenId) external {
        _requireOwned(tokenId);
        uint64 vu = validUntil[tokenId];
        require(vu == 0 || block.timestamp <= vu, "Token expired");

        address owner = ownerOf(tokenId);
        require(
            msg.sender == owner ||
            hasRole(RETIRER_ROLE, msg.sender) ||
            isApprovedForAll(owner, msg.sender) || // approvals are disabled, but kept for completeness
            getApproved(tokenId) == msg.sender,    // approvals are disabled, but kept for completeness
            "Not owner/retirer"
        );

        retired[tokenId] = true;
        _burn(tokenId);
        emit CarbonRetired(owner, tokenId);
    }

    // -------------------- Views --------------------
    function isExpired(uint256 tokenId) public view returns (bool) {
        require(_minted[tokenId], "Nonexistent id");
        uint64 vu = validUntil[tokenId];
        return vu != 0 && block.timestamp > vu && !retired[tokenId];
    }

    /// @notice On-chain status: "Active" | "Expired" | "Retired"
    function statusOf(uint256 tokenId) external view returns (string memory) {
        require(_minted[tokenId], "Nonexistent id");
        if (retired[tokenId]) return "Retired";
        if (isExpired(tokenId)) return "Expired";
        return "Active";
    }

    /// EIP-5192: always locked while it exists (non-transferable).
    function locked(uint256 tokenId) external view returns (bool) {
        require(_minted[tokenId], "Nonexistent id");
        return !retired[tokenId];
    }

    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        // Permit lookup after burn using _minted flag instead of _requireOwned.
        require(_minted[tokenId], "Nonexistent id");
        string memory custom = _tokenURIs[tokenId];
        if (bytes(custom).length > 0) return custom;
        if (bytes(baseURI).length > 0) return string(abi.encodePacked(baseURI, tokenId.toString()));
        return "";
    }

    /// Convenience for indexers
    function getInfo(uint256 tokenId)
        external
        view
        returns (uint16 _vintageYear, uint64 _validUntil, bytes32 _metadataHash, string memory _uri, bool _retired)
    {
        require(_minted[tokenId], "Nonexistent id");
        string memory custom = _tokenURIs[tokenId];
        string memory resolved = custom;
        if (bytes(resolved).length == 0 && bytes(baseURI).length > 0) {
            resolved = string(abi.encodePacked(baseURI, tokenId.toString()));
        }
        return (vintageYear[tokenId], validUntil[tokenId], metadataHash[tokenId], resolved, retired[tokenId]);
    }

    // -------------------- Non-transferable enforcement --------------------
    // Block all transfers except mint (from==0) and burn (to==0).
    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = _ownerOf(tokenId);
        if (from != address(0) && to != address(0)) {
            revert("Soulbound: non-transferable");
        }
        return super._update(to, tokenId, auth);
    }

    // Block approvals to keep things tidy.
    function approve(address, uint256) public pure override {
        revert("Soulbound: approvals disabled");
    }
    function setApprovalForAll(address, bool) public pure override {
        revert("Soulbound: approvals disabled");
    }

    // -------------------- Overrides --------------------
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC2981, AccessControl)
        returns (bool)
    {
        // EIP-5192 interface id = 0xb45a3c0e
        return interfaceId == 0xb45a3c0e || super.supportsInterface(interfaceId);
    }

    function _baseURI() internal view override returns (string memory) {
        return baseURI;
    }

    // -------------------- Multisig / Timelock Governance Helpers --------------------
    /// @notice Grant multiple roles to a multisig wallet in preparation for migration
    /// @dev Only callable by DEFAULT_ADMIN_ROLE.
    function batchGrantRolesToMultisig(address multisig, bytes32[] calldata roles)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(multisig != address(0), "Invalid multisig address");
        require(multisig != msg.sender, "Multisig cannot be deployer EOA");
        for (uint256 i = 0; i < roles.length; i++) {
            grantRole(roles[i], multisig);
        }
        emit MultisigMigrationInitiated(multisig, block.timestamp);
        emit RolesBatchGranted(multisig, roles);
    }

    /// @notice Revoke multiple roles from the deployer EOA after migration completes.
    function batchRevokeRolesFromDeployer(address deployerEOA, bytes32[] calldata roles)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(deployerEOA != address(0), "Invalid deployer address");
        for (uint256 i = 0; i < roles.length; i++) {
            revokeRole(roles[i], deployerEOA);
        }
        emit MultisigMigrationCompleted(deployerEOA, msg.sender);
    }

    /// @notice Transfer DEFAULT_ADMIN to a timelock/multisig admin (grant then revoke old admin).
    function transferDefaultAdminTo(address newAdmin) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newAdmin != address(0), "Invalid new admin");
        address oldAdmin = msg.sender;
        emit DefaultAdminTransferInitiated(oldAdmin, newAdmin);
        grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
        revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin);
        emit DefaultAdminTransferCompleted(oldAdmin, newAdmin);
    }

    /// @notice Helper to get all standard role identifiers for this contract (excluding DEFAULT_ADMIN_ROLE)
    function getStandardRoles() external pure returns (bytes32[] memory) {
        bytes32[] memory roles = new bytes32[](3);
        roles[0] = MINTER_ROLE;
        roles[1] = RETIRER_ROLE;
        roles[2] = URI_MANAGER_ROLE;
        return roles;
    }
}
