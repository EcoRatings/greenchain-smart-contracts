// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";
import "@openzeppelin/contracts/token/common/ERC2981.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/// @title CarbonCredit1155
/// @notice Gas-optimized ERC-1155 carbon credits.
///         1 token = 1 tCO2e. Expiry-enforced transfers. Optional royalties.
///         Rich metadata is kept off-chain (IPFS/Arweave) and anchored by metadataHash.
///         Uniqueness enforced via hashed registry serial.
contract CarbonCredit1155 is ERC1155, ERC1155Supply, ERC2981, AccessControl {
    // -------------------- Roles --------------------
    bytes32 public constant MINTER_ROLE       = keccak256("MINTER_ROLE");
    bytes32 public constant RETIRER_ROLE      = keccak256("RETIRER_ROLE");
    bytes32 public constant URI_MANAGER_ROLE  = keccak256("URI_MANAGER_ROLE");

    // -------------------- Collection metadata --------------------
    string public name;
    string public symbol;

    // Incremental id for new batches
    uint256 private _idCounter;

    // -------------------- Per-token minimal state --------------------
    // Per-tokenId off-chain metadata URI (e.g., IPFS)
    mapping(uint256 => string) private _tokenURIs;

    // Optional immutability for per-token metadata
    mapping(uint256 => bool) public metadataFrozen;

    // Content hash of the metadata payload (e.g., keccak256(JSON))
    mapping(uint256 => bytes32) public metadataHash;

    // Enforce uniqueness of registry serial numbers (hashed, lowercase ASCII)
    mapping(bytes32 => bool) public registrySerialUsed;

    // Supply accounting (lifetime issued / retired)
    mapping(uint256 => uint256) public issuedSupply;
    mapping(uint256 => uint256) public retiredSupply;

    // Per-token validity (unix timestamp). 0 = no expiry.
    mapping(uint256 => uint64) public validUntil;

    // Small on-chain tag for discovery/filters (keep tiny!)
    mapping(uint256 => uint16) public vintageYear; // e.g., 2023

    // -------------------- Events --------------------
    event CarbonBatchMinted(
        uint256 indexed id,
        address indexed to,
        uint256 amount,
        uint16 vintageYear,
        bytes32 registrySerialHash,
        string tokenURI,
        bytes32 contentHash
    );

    event CarbonBatchURISet(uint256 indexed id, string uri);
    event MetadataFrozen(uint256 indexed id, bytes32 contentHash);
    event ValiditySet(uint256 indexed id, uint64 validUntil);
    event CarbonRetired(address indexed from, uint256 indexed id, uint256 amount);

    // -------------------- Constructor --------------------
    constructor(
        string memory collectionName,
        string memory collectionSymbol,
        string memory baseURI,
        address defaultRoyaltyReceiver,
        uint96 defaultRoyaltyBps
    ) ERC1155(baseURI) {
        name = collectionName;
        symbol = collectionSymbol;
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

    /// @dev Returns true if this id has ever been issued (minted at least once).
    function _everIssued(uint256 id) internal view returns (bool) {
        return issuedSupply[id] > 0;
    }

    // -------------------- Minting --------------------
    /// @dev 1 token = 1 tCO2e. Use `amount` as tonnes minted.
    /// @param to Receiver of the minted credits
    /// @param amount Tonnes of CO2e (must be > 0)
    /// @param _vintageYear Vintage year (e.g., 2023)
    /// @param registrySerialNumber Human-readable serial; stored only as keccak256(lowercase ASCII) for uniqueness
    /// @param tokenURI_ Pointer to off-chain JSON (IPFS/Arweave/etc.)
    /// @param royaltyReceiver Per-token royalty receiver (optional override)
    /// @param royaltyBps Per-token royalty bps (1% = 100)
    /// @param validUntil_ Unix timestamp for expiry; 0 = no expiry
    /// @param data Arbitrary data for ERC1155
    function mintCarbonBatch(
        address to,
        uint256 amount,
        uint16 _vintageYear,
        string calldata registrySerialNumber,
        string calldata tokenURI_,
        bytes32 contentHash,
        address royaltyReceiver,
        uint96 royaltyBps,
        uint64 validUntil_,
        bytes calldata data
    ) external onlyRole(MINTER_ROLE) returns (uint256 id) {
        require(amount > 0, "Amount must be > 0");
        require(_vintageYear > 2000 && _vintageYear <= 2100, "Invalid vintage year");
        require(bytes(registrySerialNumber).length > 0, "Empty registry serial");
        require(royaltyBps <= _feeDenominator(), "royalty too high");

        if (validUntil_ != 0) {
            require(validUntil_ > block.timestamp, "validUntil_ must be in the future");
        }

        bytes32 sk = _serialKey(registrySerialNumber);
        require(!registrySerialUsed[sk], "Registry serial already used");
        registrySerialUsed[sk] = true;

        id = _idCounter++;
        vintageYear[id] = _vintageYear;

        // Optional per-token URI and content hash (content hash of full JSON recommended)
        if (bytes(tokenURI_).length > 0) {
            require(contentHash != bytes32(0), "content hash required");
            _tokenURIs[id] = tokenURI_;
            metadataHash[id] = contentHash;
            emit CarbonBatchURISet(id, tokenURI_);
        }

        // Set per-token royalty if provided
        if (royaltyReceiver != address(0) && royaltyBps > 0) {
            _setTokenRoyalty(id, royaltyReceiver, royaltyBps);
        }

        // Set validity (expiry)
        validUntil[id] = validUntil_;
        emit ValiditySet(id, validUntil_);

        issuedSupply[id] += amount;
        _mint(to, id, amount, data);

        emit CarbonBatchMinted(id, to, amount, _vintageYear, sk, tokenURI_, metadataHash[id]);
    }

    // -------------------- Metadata controls --------------------
    function setURI(uint256 id, string calldata newuri, bytes32 contentHash) external onlyRole(URI_MANAGER_ROLE) {
        require(exists(id), "Nonexistent id");
        require(!metadataFrozen[id], "Metadata frozen");
        require(bytes(newuri).length > 0, "Empty URI");
        require(contentHash != bytes32(0), "content hash required");
        _tokenURIs[id] = newuri;
        metadataHash[id] = contentHash;
        emit CarbonBatchURISet(id, newuri);
    }

    function freezeMetadata(uint256 id) external onlyRole(URI_MANAGER_ROLE) {
        require(exists(id), "Nonexistent id");
        metadataFrozen[id] = true;
        emit MetadataFrozen(id, metadataHash[id]);
    }

    // -------------------- Validity admin --------------------
    /// @notice Extend validity (cannot shorten). Governance-controlled.
    function extendValidity(uint256 id, uint64 newValidUntil) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(exists(id), "Nonexistent id");
        // Optional extra safety: do not allow setting a past timestamp
        if (newValidUntil != 0) {
            require(newValidUntil > block.timestamp, "newValidUntil must be in the future");
        }
        require(newValidUntil >= validUntil[id], "Cannot shorten validity");
        validUntil[id] = newValidUntil;
        emit ValiditySet(id, newValidUntil);
    }

    // -------------------- Retirement (Burn) --------------------
    /// @notice Retire (burn) a specific amount from `from` for `id`.
    /// @dev Retirement is blocked after expiry. Remove the check to allow post-expiry retire.
    function retire(address from, uint256 id, uint256 amount) public {
        uint64 vu = validUntil[id];
        require(vu == 0 || block.timestamp <= vu, "Token expired");
        require(
            _msgSender() == from ||
            isApprovedForAll(from, _msgSender()) ||
            hasRole(RETIRER_ROLE, _msgSender()),
            "Not owner/approved/retirer"
        );
        _burn(from, id, amount);
        retiredSupply[id] += amount;
        emit CarbonRetired(from, id, amount);
    }

    function retireAllOfId(address from, uint256 id) external {
        uint256 bal = balanceOf(from, id);
        require(bal > 0, "No balance to retire");
        retire(from, id, bal);
    }

    function retireAllFor(address from, uint256[] calldata ids) external {
        for (uint256 i = 0; i < ids.length; ++i) {
            uint256 bal = balanceOf(from, ids[i]);
            if (bal > 0) retire(from, ids[i], bal);
        }
    }

    function retireAllMyCredits(uint256[] calldata ids) external {
        for (uint256 i = 0; i < ids.length; ++i) {
            uint256 bal = balanceOf(_msgSender(), ids[i]);
            if (bal > 0) retire(_msgSender(), ids[i], bal);
        }
    }

    // -------------------- Views --------------------
    function uri(uint256 id) public view override returns (string memory) {
        string memory custom = _tokenURIs[id];
        if (bytes(custom).length > 0) return custom;
        return super.uri(id);
    }

    /// @notice Returns true if the credit has an expiry and the current time is past it.
    /// @dev Uses _everIssued so fully retired (totalSupply==0) ids are still queryable.
    function isExpired(uint256 id) public view returns (bool) {
        require(_everIssued(id), "Unknown id");
        uint64 vu = validUntil[id];
        return vu != 0 && block.timestamp > vu;
    }

    /// @notice On-chain status derived from supply and expiry.
    /// "Expired" takes precedence over supply-based statuses.
    /// @dev Uses _everIssued so FullyRetired status is available when totalSupply==0.
    function statusOf(uint256 id) external view returns (string memory) {
        require(_everIssued(id), "Unknown id");
        if (isExpired(id)) return "Expired";
        uint256 issued = issuedSupply[id];
        uint256 retired_ = retiredSupply[id];
        if (retired_ == 0) return "Active";
        if (retired_ < issued) return "PartiallyRetired";
        return "FullyRetired";
    }

    /// @notice Minimal info helper for indexers/clients (gas-cheap).
    function getInfo(uint256 id)
        external
        view
        returns (uint16 _vintageYear, uint64 _validUntil, bytes32 _metadataHash, string memory _uri)
    {
        require(_everIssued(id), "Unknown id");
        return (vintageYear[id], validUntil[id], metadataHash[id], uri(id));
    }

    // -------------------- Overrides --------------------
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC1155, ERC2981, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    /// @dev Block transfers after expiry; allow mint (from==0) and burn (to==0).
    function _update(address from, address to, uint256[] memory ids, uint256[] memory amounts)
        internal
        override(ERC1155, ERC1155Supply)
    {
        if (from != address(0) && to != address(0)) {
            for (uint256 i = 0; i < ids.length; ++i) {
                uint64 vu = validUntil[ids[i]];
                require(vu == 0 || block.timestamp <= vu, "Token expired");
            }
        }
        super._update(from, to, ids, amounts);
    }
}
