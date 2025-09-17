# GreenChain Smart Contracts

<p align="center">
  <img src="https://docs.optimism.io/_next/image?url=%2Fimg%2Fbuilders%2Fchain-operators%2Fsequencer-diagram.png&w=828&q=75" alt="Optimism Sequencer Diagram">
</p>

## 1. High-Level Overview
GreenChain is an Optimism SDK (OP Stack) based L2 Ethereum chain focused on transparent tokenization and retirement of carbon credits. Two on-chain token standards are provided:

1. `CarbonCredit1155` (multi-batch fungible credits; 1 unit = 1 tCO2e) with expiry and retirement (burn) tracking.
2. `CarbonCreditSBT` (soulbound ERC721 certificate) — a non-transferable single certificate representation for specific carbon credit lots.

Both contracts emphasize:
- Minimal on-chain state; rich metadata stored off-chain (IPFS/Arweave/etc.) and integrity anchored via content hash.
- Enforced uniqueness of registry serial numbers (normalized & hashed).
- Optional per-token or default royalties using ERC2981 (secondary sales context if wrapped or bridged to marketplaces that honor royalties).
- Explicit roles (AccessControl) for minting, retiring, metadata updates.
- Expiry semantics that restrict transfers (1155) or retirement after expiration unless extended.

Out of scope (currently not in repo): bridging contracts, rollup system contracts, sequencer/proposer infra, fraud/fault-proof components. Those remain part of the OP Stack base layer or infra configuration.

---
## 2. Layer 2 Architecture (OP Stack)
**Implementation Status:** Deployment uses an unmodified (vanilla) OP Stack configuration. No custom system contracts, predeploy additions, gas schedule changes, opcode patches, or protocol-level parameter overrides (beyond standard configuration fields) have been introduced. All differences from Ethereum mainnet execution semantics are those inherent to the canonical OP Stack release in use.

| Component | Description | Customization | Audit Notes |
|-----------|-------------|---------------|-------------|
| Execution (EVM) | Standard OP Stack EVM | None | Focus only on application contracts here |
| Sequencer | Batches L2 txs, posts to L1 | Single centralized EOA (project operator) – to be migrated to multisig | Short-term censorship / ordering risk window |
| Batch Submitter | Posts calldata batches to L1 | None | Capacity sizing relevant for burst minting |
| Proposer / Output Root Publisher | Publishes state roots to L1 | None | Standard OP Stack finalization delay applies |
| Fault/Fraud Proofs | Dispute invalid roots | Standard OP Stack fault proof pipeline (no custom mods) | Trust reduced as proofs mature (current industry baseline) |
| Data Availability | L1 calldata | None | Economic cost only |

### Key Chain Parameters
- Chain ID: 42069 (testnet; final production chain ID not yet assigned)  
- Block time target: ~2 seconds (standard OP Stack)  
- Finalization window (challenge period): 7 days (standard)  
- Gas token: Native ETH on L2 (derivative of L1 ETH)  
- System contracts: Canonical OP Stack set (no additions or replacements)  
- Network status: TESTNET ONLY (ephemeral; state may be reset without notice)  

### 2.1 Testnet Status & Disclaimers
This OP Stack chain is currently operated as a testnet environment:
- Not production / no real economic value assumed.
- Carbon credit tokens minted here DO NOT represent legally recognized / retired offsets.
- State resets, contract redeployments, and parameter changes may occur without migration tooling.
- Security review focuses on code correctness; operational security (key custody, monitoring) is minimal in testnet.
- Auditors should treat any addresses provided as provisional and subject to change at production launch.

Transition Plan to Production (Outline):
1. Freeze feature set; tag audit commit.
2. Complete external audit & address findings.
3. Deploy production chain (new chain ID) & contracts with multisig governance.
4. Publish final documentation
5. Public announcement & begin monitored issuance.

### Trust & Assumption Boundary
Until fault proofs are fully permissionless and live, users must trust: (a) Sequencer honesty for short-term execution ordering, (b) Proposer not publishing invalid state roots (backed by social / governance guarantees), (c) L1 security for final settlement. No extra trust assumptions are added by custom code because there is none at the protocol layer.

---
## 3. Repository Scope
Currently only application-layer carbon credit token contracts are in scope:
- `CarbonCredit1155.sol` (contract name: `CarbonCredit1155`)
- `CarbonCreditSBT.sol` (contract name: `CarbonCreditSBT`)

No upgrade proxies, factories, bridges, or governance modules exist in this repository (at time of writing). If future additions occur, update this section.

---
## 4. External Dependencies
- OpenZeppelin Contracts v5.x (exact tag to be pinned before production deploy; no local modifications).  
- Solidity ^0.8.20 compiler (no custom build).  
- Assumed toolchain: Hardhat (build & deploy) – Foundry may be added for fuzz/invariant tests.

Security expectation: Use a pinned, reviewed OpenZeppelin release (e.g., v5.0.x). Avoid floating ranges in production deployment.

---
## 5. Contract Summaries
### 5.1 CarbonCredit1155
Purpose: Multi-batch fungible carbon credit units (1 token = 1 metric tonne CO2e). Each minted batch receives a new incremental `id`.
Key Features:
- Roles: `DEFAULT_ADMIN_ROLE`, `MINTER_ROLE`, `RETIRER_ROLE`, `URI_MANAGER_ROLE`.
- Mint enforces: unique registry serial (lowercased + keccak256), valid vintage year, non-zero amount.
- Expiry: `validUntil[id]` (0 = perpetual). Transfers blocked after expiry; mint/burn still allowed except retirement enforces non-expired constraint.
- Retirement: Burns supply from holder (or authorized retire role) increasing `retiredSupply[id]`.
- Metadata: mutable until frozen. `metadataHash` is keccak256 of current URI string (recommend using keccak256 of full JSON payload for stronger anchoring — see Section 9).
- Royalties: Default collection-level (optional in constructor) + per-token override (ERC2981).
- Status helper: Active / PartiallyRetired / FullyRetired / Expired.

Invariants / Expectations:
- `retiredSupply[id] <= issuedSupply[id]` (implicit by burn path).
- Serial uniqueness: once a serial hash used, cannot be reused.
- Expired tokens cannot be transferred (prevents after-market movement) but can still be identified via view functions.

### 5.2 CarbonCreditSBT
Purpose: Non-transferable 1-of-1 carbon credit certificate (soulbound). Cannot be transferred; can be burned (retired).
Key Features:
- Roles: `DEFAULT_ADMIN_ROLE`, `MINTER_ROLE`, `RETIRER_ROLE`, `URI_MANAGER_ROLE`.
- Mint: uniqueness via normalized registry serial; sets vintage, optional expiry, optional per-token royalty.
- Soulbound: Overrides `_update` to revert on any non-mint/non-burn transfer. Approvals disabled.
- Retirement: Burn marks `retired[tokenId] = true`; status becomes Retired.
- Expiry: Disallows retirement after expiry unless extended.
- Metadata: mutable until frozen; on freeze, hash emitted.
- EIP-5192 compliance: `locked(tokenId)` returns true while token exists and not retired.

Invariants / Expectations:
- A token is never transferable after mint.
- `retired[tokenId]` true implies the token is burned and cannot reappear.
- Metadata immutability after freeze.

---
## 6. Access Control & Governance Model
| Role | Granted To (Initial) | Powers | Risk if Compromised | Mitigation |
|------|----------------------|--------|---------------------|------------|
| DEFAULT_ADMIN_ROLE | Deployer EOA (upgrade to multisig planned) | Grant/revoke roles, extend validity | Total control escalation | Multisig + off-chain monitoring |
| MINTER_ROLE | Deployer EOA (same as admin) | Mint new credits/certificates | Unauthorized inflation | Serial audits, issuance monitoring |
| RETIRER_ROLE | Deployer EOA (may remove later) | Burn (retire) user holdings (with checks) | Forced retirement / grief | Limit or drop role if not required |
| URI_MANAGER_ROLE | Deployer EOA | Set/freeze metadata URIs | Metadata tampering / misrepresentation | Early freeze, hash verification |

Governance Changes: Initially centralized (single EOA). Migration path: deploy multisig (e.g., 2-of-3) then transfer all roles and revoke EOA.

---
## 7. Token Lifecycle (Text Sequence)
Fungible (1155):
1. Mint: MINTER_ROLE mints batch id=N with `amount`, sets metadata, expiry, optional royalty.
2. Transfer: Allowed until `validUntil` (if set and not passed). Standard ERC1155 semantics.
3. Retirement: Holder (or RETIRER_ROLE) burns a portion/all; increases `retiredSupply`.
4. Expiry: After `validUntil`, transfers blocked; remaining supply can remain unretired (status: Expired) unless governance extends validity.

Soulbound (SBT):
1. Mint: MINTER_ROLE mints non-transferable tokenId.
2. Locked: Always locked; no transfers.
3. Retirement: Burn sets retired=true.
4. Expiry: If reached prior to retirement, cannot retire unless extended.

---
## 8. Royalty Mechanism
Implements ERC2981. Default royalty set in constructor; per-token override on mint. `royaltyBps <= 10000` enforced. Royalty data is advisory; marketplace compliance not guaranteed. No on-chain fee enforcement.

---
## 9. Metadata & Integrity
- `_tokenURIs` store an IPFS/Arweave (or HTTPS) pointer.
- `metadataHash` currently = keccak256(URI string). RECOMMENDATION: Instead store keccak256 of raw JSON bytes to remain stable if gateway / URI format changes. To adopt: include raw JSON hash off-chain, pass in as parameter, store separately.
- `freezeMetadata` irreversibly flags immutability.
- Auditors should confirm no code path modifies URI after freeze.

Content Verification Flow (Suggested Off-Chain):
1. Retrieve `tokenURI`.
2. Fetch JSON, compute keccak256(bytes(JSON)).
3. Compare with separately published list (or future on-chain field) for stronger guarantee.

---
## 10. Registry Serial Uniqueness
Normalization: ASCII lowercase loop, keccak256 hashed. Prevents duplicate serials differing only by case. Off-chain MUST normalize & validate Unicode / whitespace to avoid homograph issues. Potential improvement: enforce regex on-chain (cost tradeoff) or emit original normalized form.

---
## 11. Expiry Semantics
- 1155: Expired tokens: transfers blocked; retirement still blocked (see code) because retire() requires not expired. Governance may call `extendValidity` to move forward in time (monotonic, cannot shorten).
- SBT: Expired tokens: cannot retire; governance can extend.
- Rationale: Prevent post-expiry market movement and ensure retirement claims are timely.

Risk: If expiry is accidentally set too short, requires admin intervention. Provide monitoring alert for soon-to-expire active batches.

---
## 12. Retirement (Burn) Semantics
- 1155: Partial retire allowed; supply accounting via `issuedSupply` and `retiredSupply`.
- SBT: Single retire via burn toggles `retired[tokenId]`.
- Events: `CarbonRetired` emitted for both.
- Off-chain indexers aggregate retired volume for ESG reporting.

---
## 13. Events & Indexing Guidance
Key Events:
- `CarbonBatchMinted(id,to,amount,vintageYear,serialHash,tokenURI)`
- `CarbonRetired(from,id,amount)` (1155)
- `CarbonCertificateMinted(id,to,vintageYear,serialHash,tokenURI)`
- `CarbonRetired(owner,id)` (SBT)
- Metadata events: `CarbonBatchURISet`, `CarbonCertificateURISet`, `MetadataFrozen`, `ValiditySet`.

Recommended Indexer Derived Data:
- Outstanding (non-retired & non-expired) supply per vintage.
- Retirement leaderboard (addresses, volumes).
- Expiring soon (cutoff window).
- Serial-to-id mapping (store original serial off-chain).

---
## 14. Security / Threat Model
| Threat | Vector | Mitigation | Residual Risk |
|--------|--------|-----------|---------------|
| Unauthorized mint | Compromised MINTER_ROLE | Multisig, key rotation | Limited by detection speed |
| Metadata tampering | URI_MANAGER_ROLE misuse before freeze | Early freeze policy | Delay before freeze |
| Forced retirement | RETIRER_ROLE abuse | Restrict / remove role | Still possible if compromised |
| Replay or duplication | Serial uniqueness bypass | Case normalization + hash | Unicode / formatting edge cases |
| Expiry griefing | Setting too short expiry | Admin review / monitoring | Human error |
| Royalty griefing | High per-token royalty | Limit policy off-chain | Marketplace ignoring royalties |
| Censorship (L2) | Sequencer ordering | L1 escape hatch via withdrawals (OP Stack) | Short-term ordering risk |
| State root invalid | Proposer malicious (if no proofs) | Roadmap to permissionless proofs | Trust in governance |

Out of Scope for This Audit (unless added later): bridging, oracles, stablecoin custody, liquidation logic.

---
## 15. Upgrade & Governance
Current contracts are NOT upgradeable (no proxy). Governance actions limited to role grants/revokes and extending validity. No upgrade hooks exist; storage layout is compact and final.

If future upgradeability is needed:
- Introduce transparent or UUPS proxy pattern with explicit gap storage.
- Add upgrade timelock & on-chain proposal flow.

---
## 16. Known Limitations / Potential Improvements
- Metadata hash currently of URI string (see Section 9 improvement path).
- No pausable emergency stop; consider if operationally required.
- No supply cap enforcement (policy-driven off-chain); can add max supply per vintage.
- No on-chain registry serial storage (only hash) – cannot recover original serial on-chain.

---
## 17. Recommended Invariant Tests (Pre-Audit)
| Category | Invariant / Property |
|----------|---------------------|
| Supply | `retiredSupply[id] <= issuedSupply[id]` always |
| Serial | Re-mint with same serial (case variants) reverts |
| Expiry | Transfer after expiry reverts (1155), retire after expiry reverts both |
| Metadata | After freeze, further `setURI` reverts |
| Roles | Non-role accounts cannot call role-restricted functions |
| SBT Soulbound | Any transfer (other than mint/burn) reverts |
| Royalty | `royaltyInfo` returns expected receiver & amount within bounds |
| Validity Extension | `extendValidity` only accepts >= current validity |

Consider property-based fuzzing (Foundry `invariant` tests or Echidna) for edge conditions (expiry boundaries, serial normalization, batch operations).

---
## 18. Deployment & Environment
Current (pre-production / testnet) parameters:
- Solidity compiler version: 0.8.20 (standard release build)  
- Optimization: enabled, runs=200  
- Deployment tool: Hardhat (scripts forthcoming)  
- Deployer address (L2 testnet): 0xA5aa6a59A1Ab05C1c72cCA71794C95d527827916  
- Admin multisig address: 0xA5aa6a59A1Ab05C1c72cCA71794C95d527827916  
- Contract addresses (L2 testnet): deployed  / ephemeral  
  - CarbonCredit1155: 0x49bbdbe77497db1614d8ad0F2468390DCaaB1128  
  - CarbonCreditSBT: 0x8BEf48dA1ddca5550E1d7C8d2Df111Fd1dA252Ea  
- Default royalty receiver & bps: None (0) – per-token optional override only  
- Initial roles & grantees snapshot: Will be captured at first stable testnet deployment block  
- Environment classification: Testnet (data may be purged prior to production)  

Production Deployment Differences (Planned):
- Distinct chain ID (permanent).
- Multisig governance (roles transferred, EOA revoked).
- Public security contact & bug bounty live prior to first production mint.
- Immutable metadata policy (freeze earlier) and documented issuance controls.

---
## 19. Operational Runbook (Suggested)
| Scenario | Action |
|----------|--------|
| Compromised MINTER_ROLE | Revoke role via admin, redeploy if necessary, publish incident report |
| Incorrect metadata URI | If not frozen: update & freeze; if frozen: redeploy batch with new id & mark old expired (extend validity prohibited) |
| Imminent Expiry (legitimate) | Admin extends validity (monotonic) after off-chain registry confirmation |
| Royalty change required | Adjust via per-token overrides for new mints; cannot mutate frozen tokens |

---
## 20. Future Extensions (Roadmap – Informational Only)
- On-chain registry anchor contract for original serial + signature attestation.
- Cross-chain bridge representation (ERC5164 / canonical bridge) for credits.
- Merkle-based batch retirement proofs aggregated off-chain.
- Verifiable metadata hashing (content-addressed JSON) with multi-hash standard.

---
## 21. Repository Structure
```
./CarbonCredit1155.sol   (ERC1155 multi-batch carbon credits)
./CarbonCreditSBT.sol    (Soulbound ERC721 carbon certificate)
./README.md              (This documentation)
```
(Add test, scripts, and deployment directories before formal audit.)

---
## 22. Contact & Disclosure
Primary technical contact: ajay@ecoratings.ai  

---
## 23. License
All contracts: MIT (see SPDX identifiers in source headers). Ensure third-party dependencies comply.

