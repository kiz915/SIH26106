// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EvidenceRegistry
 * @dev Blockchain-based Digital Evidence Integrity System for Email Forensics
 * @notice Stores cryptographic hashes of forensic evidence for tamper-proof verification
 */
contract EvidenceRegistry {
    
    /**
     * @dev Evidence structure containing forensic metadata
     * @param evidenceHash SHA-256 hash of the evidence (bytes32)
     * @param timestamp Registration timestamp
     * @param stage Processing stage (e.g., EMAIL_RECEIVED, FORENSIC_ANALYSIS, REPORT_GENERATED)
     * @param submitter Address that registered the evidence
     * @param exists Flag indicating if evidence record exists
     */
    struct Evidence {
        bytes32 evidenceHash;
        uint256 timestamp;
        string stage;
        address submitter;
        bool exists;
    }
    
    /**
     * @dev Mapping from evidence ID to Evidence struct
     */
    mapping(string => Evidence) private evidenceRecords;
    
    /**
     * @dev Array of all evidence IDs for enumeration
     */
    string[] private evidenceIds;
    
    /**
     * @dev Events for important blockchain actions
     */
    event EvidenceRegistered(
        string indexed evidenceId,
        bytes32 indexed evidenceHash,
        address indexed submitter,
        string stage,
        uint256 timestamp
    );
    
    event EvidenceVerified(
        string indexed evidenceId,
        bytes32 indexed evidenceHash,
        bool verified,
        uint256 timestamp
    );
    
    /**
     * @dev Modifier to check if evidence exists
     */
    modifier evidenceExists(string memory evidenceId) {
        require(evidenceRecords[evidenceId].exists, "Evidence does not exist");
        _;
    }
    
    /**
     * @dev Register new forensic evidence on blockchain
     * @param evidenceId Unique identifier for the evidence
     * @param evidenceHash SHA-256 hash of the evidence (must be 32 bytes)
     * @param stage Processing stage of the evidence
     * @return timestamp Registration timestamp
     */
    function registerEvidence(
        string memory evidenceId,
        bytes32 evidenceHash,
        string memory stage
    ) public returns (uint256 timestamp) {
        require(bytes(evidenceId).length > 0, "Evidence ID cannot be empty");
        require(evidenceHash != bytes32(0), "Evidence hash cannot be zero");
        require(!evidenceRecords[evidenceId].exists, "Evidence already registered");
        
        timestamp = block.timestamp;
        
        evidenceRecords[evidenceId] = Evidence({
            evidenceHash: evidenceHash,
            timestamp: timestamp,
            stage: stage,
            submitter: msg.sender,
            exists: true
        });
        
        evidenceIds.push(evidenceId);
        
        emit EvidenceRegistered(evidenceId, evidenceHash, msg.sender, stage, timestamp);
    }
    
    /**
     * @dev Get evidence record by ID
     * @param evidenceId Unique identifier for the evidence
     * @return evidenceHash SHA-256 hash of the evidence
     * @return timestamp Registration timestamp
     * @return stage Processing stage
     * @return submitter Address that registered the evidence
     */
    function getEvidence(string memory evidenceId) 
        public 
        view 
        evidenceExists(evidenceId) 
        returns (
            bytes32 evidenceHash,
            uint256 timestamp,
            string memory stage,
            address submitter
        ) 
    {
        Evidence memory evidence = evidenceRecords[evidenceId];
        return (
            evidence.evidenceHash,
            evidence.timestamp,
            evidence.stage,
            evidence.submitter
        );
    }
    
    /**
     * @dev Verify evidence integrity by comparing current hash with blockchain hash
     * @param evidenceId Unique identifier for the evidence
     * @param currentHash Current SHA-256 hash of the evidence
     * @return verified True if hashes match, false otherwise
     * @return blockchainHash Hash stored on blockchain
     */
    function verifyEvidence(
        string memory evidenceId,
        bytes32 currentHash
    ) public evidenceExists(evidenceId) returns (bool verified, bytes32 blockchainHash) {
        Evidence memory evidence = evidenceRecords[evidenceId];
        blockchainHash = evidence.evidenceHash;
        verified = (currentHash == blockchainHash);
        
        emit EvidenceVerified(evidenceId, currentHash, verified, block.timestamp);
        
        return (verified, blockchainHash);
    }
    
    /**
     * @dev Check if evidence exists
     * @param evidenceId Unique identifier for the evidence
     * @return exists True if evidence is registered, false otherwise
     */
    function evidenceRecordExists(string memory evidenceId) public view returns (bool exists) {
        return evidenceRecords[evidenceId].exists;
    }
    
    /**
     * @dev Get total number of registered evidence records
     * @return count Total evidence count
     */
    function getEvidenceCount() public view returns (uint256 count) {
        return evidenceIds.length;
    }
    
    /**
     * @dev Get evidence ID by index
     * @param index Index in the evidence array
     * @return evidenceId Evidence ID at the given index
     */
    function getEvidenceIdByIndex(uint256 index) public view returns (string memory evidenceId) {
        require(index < evidenceIds.length, "Index out of bounds");
        return evidenceIds[index];
    }
    
    /**
     * @dev Get all evidence IDs (useful for frontend enumeration)
     * @return allEvidenceIds Array of all evidence IDs
     */
    function getAllEvidenceIds() public view returns (string[] memory allEvidenceIds) {
        return evidenceIds;
    }
    
    /**
     * @dev Update evidence stage (for chain-of-custody tracking)
     * @param evidenceId Unique identifier for the evidence
     * @param newStage New processing stage
     */
    function updateEvidenceStage(string memory evidenceId, string memory newStage) 
        public 
        evidenceExists(evidenceId) 
    {
        require(bytes(newStage).length > 0, "Stage cannot be empty");
        require(msg.sender == evidenceRecords[evidenceId].submitter, "Only submitter can update stage");
        evidenceRecords[evidenceId].stage = newStage;
    }
    
    /**
     * @dev Get evidence hash only (for quick verification)
     * @param evidenceId Unique identifier for the evidence
     * @return evidenceHash SHA-256 hash stored on blockchain
     */
    function getEvidenceHash(string memory evidenceId) 
        public 
        view 
        evidenceExists(evidenceId) 
        returns (bytes32 evidenceHash) 
    {
        return evidenceRecords[evidenceId].evidenceHash;
    }
}