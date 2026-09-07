# Blockchain Digital Evidence Integrity System

A blockchain-based Digital Evidence Integrity system for the SIH26106 Email Forensics platform. This module provides tamper-proof evidence verification using smart contracts on Polygon Amoy testnet and local Hardhat networks.

## 🎯 Overview

The blockchain module implements a secure, cryptographic evidence registry that ensures the integrity of forensic email analysis reports. By storing only cryptographic hashes on-chain, the system provides:

- **Tamper Detection**: Immediate detection of evidence modification
- **Chain of Custody**: Track evidence through processing stages
- **Immutable Records**: Blockchain-stored evidence hashes cannot be altered
- **Privacy Protection**: Only hashes stored, not actual email content

## 🏗️ Architecture

### System Flow

```
Forensic Email
    ↓
Forensic Analysis
    ↓
Forensic Report
    ↓
SHA-256 Hash
    ↓
Smart Contract
    ↓
Blockchain
    ↓
Transaction Hash
    ↓
Evidence Verification
    ↓
VERIFIED / TAMPERED
```

### Components

1. **Smart Contract** (`EvidenceRegistry.sol`)
   - Stores evidence hashes and metadata
   - Provides verification functions
   - Emits events for audit trail

2. **Backend Service** (`blockchain_service.py`)
   - Python web3 integration
   - SHA-256 hash conversion
   - Transaction management

3. **Hardhat Development Environment**
   - Local blockchain testing
   - Contract compilation
   - Deployment scripts

## 🔧 Technology Stack

- **Smart Contract**: Solidity 0.8.20
- **Development Framework**: Hardhat
- **Blockchain Networks**: 
  - Local Hardhat Network (development)
  - Polygon Amoy Testnet (production)
- **Backend Integration**: Python web3.py
- **Hashing**: SHA-256 (via Python hashlib + Node.js crypto)

## 📁 Project Structure

```
blockchain/
├── contracts/
│   └── EvidenceRegistry.sol          # Main smart contract
├── scripts/
│   ├── deploy.js                     # Deployment script
│   └── demo.js                       # Demo script for testing
├── test/
│   └── EvidenceRegistry.test.js      # Comprehensive test suite
├── hardhat.config.js                 # Hardhat configuration
├── package.json                      # Node.js dependencies
├── .env.example                      # Environment variables template
└── README.md                         # This file
```

## 🚀 Quick Start

### Prerequisites

- Node.js (v16+)
- Python 3.8+
- Git

### Installation

1. **Install Node.js dependencies**:
```bash
cd blockchain
npm install
```

2. **Install Python dependencies** (for backend integration):
```bash
cd ../backend
pip install -r requirements.txt
```

3. **Configure environment variables**:
```bash
cd blockchain
cp .env.example .env
# Edit .env with your configuration
```

### Local Development

1. **Start local Hardhat network**:
```bash
cd blockchain
npx hardhat node
```

2. **Compile contracts**:
```bash
npx hardhat compile
```

3. **Run tests**:
```bash
npx hardhat test
```

4. **Run demo**:
```bash
npx hardhat run scripts/demo.js
```

5. **Deploy to local network**:
```bash
npx hardhat run scripts/deploy.js --network localhost
```

## 🔐 Smart Contract Details

### EvidenceRegistry Contract

The `EvidenceRegistry` contract provides the following functions:

#### Core Functions

- **`registerEvidence(evidenceId, evidenceHash, stage)`**
  - Registers new evidence on blockchain
  - Returns registration timestamp
  - Emits `EvidenceRegistered` event

- **`getEvidence(evidenceId)`**
  - Retrieves complete evidence record
  - Returns: hash, timestamp, stage, submitter

- **`verifyEvidence(evidenceId, currentHash)`**
  - Verifies evidence integrity
  - Returns: (verified: bool, blockchainHash: bytes32)
  - Emits `EvidenceVerified` event

- **`evidenceRecordExists(evidenceId)`**
  - Checks if evidence exists
  - Returns: boolean

#### Chain of Custody Functions

- **`updateEvidenceStage(evidenceId, newStage)`**
  - Updates processing stage
  - Tracks evidence through workflow

#### Utility Functions

- **`getEvidenceCount()`**
  - Returns total evidence count

- **`getEvidenceIdByIndex(index)`**
  - Retrieves evidence ID by index

- **`getAllEvidenceIds()`**
  - Returns all evidence IDs

### Data Structures

```solidity
struct Evidence {
    bytes32 evidenceHash;      // SHA-256 hash of evidence
    uint256 timestamp;         // Registration timestamp
    string stage;              // Processing stage
    address submitter;        // Address that registered evidence
    bool exists;               // Existence flag
}
```

### Events

```solidity
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
```

## 🔒 Security Considerations

### What's Stored On-Chain

✅ **Stored**:
- SHA-256 hashes (bytes32)
- Timestamps
- Processing stages
- Submitter addresses
- Evidence IDs

❌ **NOT Stored**:
- Email content
- Attachments
- Forensic report PDFs
- Personal information
- Passwords
- Any sensitive data

### Security Best Practices

1. **Private Key Management**
   - Never commit private keys to Git
   - Use environment variables
   - Rotate keys regularly

2. **Hash Integrity**
   - SHA-256 provides cryptographic security
   - Same evidence always produces same hash
   - Single bit change produces completely different hash

3. **Access Control**
   - Any address can register evidence (public registry)
   - Verification is public (read-only)
   - Stage updates restricted to original submitter only

4. **Gas Optimization**
   - Efficient storage patterns
   - Event emission for audit trail
   - Optimized contract bytecode

## 🧪 Testing

### Test Coverage

The test suite includes 34 comprehensive tests covering:

- Contract deployment
- Evidence registration
- Evidence retrieval
- Hash verification
- Tamper detection
- Timestamp recording
- Stage updates
- Submitter tracking
- Multiple evidence records
- Invalid operations
- Edge cases

### Running Tests

```bash
# Run all tests
npx hardhat test

# Run specific test file
npx hardhat test test/EvidenceRegistry.test.js

# Run with coverage
npx hardhat coverage
```

### Test Results

```
✓ 34 passing (963ms)
✓ 0 failing
```

## 🌐 Network Configuration

### Local Hardhat Network

- **URL**: http://127.0.0.1:8545
- **Chain ID**: 31337
- **Gas Price**: 0 gwei (free)
- **Purpose**: Development and testing

### Polygon Amoy Testnet

- **RPC URL**: https://rpc-amoy.polygon.technology
- **Chain ID**: 80002
- **Explorer**: https://amoy.polygonscan.com
- **Purpose**: Production testing

### Environment Variables

```bash
# Polygon Amoy Configuration
POLYGON_AMOY_RPC_URL=https://rpc-amoy.polygon.technology
PRIVATE_KEY=your_private_key_here
CONTRACT_ADDRESS=your_deployed_contract_address
POLYGONSCAN_API_KEY=your_polygonscan_api_key

# Local Development
BLOCKCHAIN_RPC_URL=http://127.0.0.1:8545
BLOCKCHAIN_PRIVATE_KEY=your_local_hardhat_private_key_here
BLOCKCHAIN_CONTRACT_ADDRESS=
```

## 🔗 Backend Integration

### Python Blockchain Service

The backend includes a comprehensive blockchain service (`backend/blockchain_service.py`):

```python
from backend.blockchain_service import get_blockchain_service

# Get blockchain service instance
blockchain_service = get_blockchain_service()

# Register evidence
result = blockchain_service.register_evidence(
    evidence_id="EVID-20260907-ABC123",
    sha256_hash="0x1234...",
    stage="FORENSIC_ANALYSIS"
)

# Verify evidence
verification = blockchain_service.verify_evidence(
    evidence_id="EVID-20260907-ABC123",
    current_sha256_hash="0x1234..."
)
```

### API Endpoints

The backend provides the following blockchain endpoints:

- **GET `/blockchain/status`**
  - Get blockchain service status
  - Returns network information

- **POST `/blockchain/register`**
  - Register evidence on blockchain
  - Parameters: evidence_id, case_id, stage

- **GET `/blockchain/verify/{evidence_id}`**
  - Verify evidence integrity
  - Returns VERIFIED or EVIDENCE_TAMPERED

- **GET `/blockchain/evidence/{evidence_id}`**
  - Get blockchain evidence record
  - Returns complete evidence details

### API Response Examples

#### Registration Response

```json
{
  "success": true,
  "evidence_id": "EVID-20260907-ABC123",
  "blockchain_hash": "0x1234...",
  "stage": "FORENSIC_ANALYSIS",
  "transaction_hash": "0xabcd...",
  "block_number": 12345,
  "gas_used": 45000,
  "timestamp": "2026-09-07T04:46:04.000Z"
}
```

#### Verification Response (VERIFIED)

```json
{
  "verified": true,
  "status": "EVIDENCE_VERIFIED",
  "evidence_id": "EVID-20260907-ABC123",
  "blockchain_hash": "0x1234...",
  "current_hash": "0x1234...",
  "message": "Evidence integrity verified - no tampering detected"
}
```

#### Verification Response (TAMPERED)

```json
{
  "verified": false,
  "status": "EVIDENCE_TAMPERED",
  "evidence_id": "EVID-20260907-ABC123",
  "blockchain_hash": "0x1234...",
  "current_hash": "0x5678...",
  "message": "Evidence tampering detected - hash mismatch"
}
```

## 📊 SHA-256 Hashing Process

### Hash Generation

The system uses SHA-256 for cryptographic hashing consistently across all components:

**Python Backend:**
```python
import hashlib

def calculate_sha256(data: bytes) -> str:
    """Computes SHA-256 hex digest from raw bytes."""
    return hashlib.sha256(data).hexdigest()
```

**JavaScript/Node.js:**
```javascript
const crypto = require('crypto');

function sha256Hash(data) {
  return "0x" + crypto.createHash('sha256').update(data).digest('hex');
}
```

**Smart Contract:**
- Accepts bytes32 (32-byte hash)
- Stores as-is on blockchain
- Does not perform hashing (hashing done off-chain)

### Hash Properties

- **Deterministic**: Same input always produces same hash
- **Collision-resistant**: Extremely unlikely to find two inputs with same hash
- **Avalanche effect**: Single bit change produces completely different hash
- **Fixed output**: Always 64-character hexadecimal string

### Example

```python
# Original evidence
original = b"FORENSIC_REPORT_20260907"
original_hash = hashlib.sha256(original).hexdigest()
# Output: "a571f1a55d8ca8bb1ab4447f0877fe3963d5cd95ece8faefaf1a6cd651a08297"

# Tampered evidence (one character changed)
tampered = b"FORENSIC_REPORT_20260907_TAMPERED"
tampered_hash = hashlib.sha256(tampered).hexdigest()
# Output: "f7686e36476a23723a093108b3068d91ee3db64f48a22525c551e323443bf683"

# Hashes are completely different (these are example hashes for illustration)
```

## 🔍 Chain of Custody

### Processing Stages

The blockchain tracks evidence through these stages:

1. **EMAIL_RECEIVED** - Initial email receipt
2. **FORENSIC_ANALYSIS** - Analysis in progress
3. **REPORT_GENERATED** - Forensic report created
4. **REPORT_HASHED** - SHA-256 hash calculated
5. **BLOCKCHAIN_REGISTERED** - Hash stored on blockchain
6. **VERIFIED** - Evidence integrity verified

### Stage Updates

```python
# Update evidence stage (only by original submitter)
blockchain_service.contract.functions.updateEvidenceStage(
    evidence_id="EVID-20260907-ABC123",
    newStage="VERIFIED"
).transact()
```

**Note**: Stage updates are restricted to the original submitter address for security.

## 🎯 Demo Walkthrough

### Running the Demo

```bash
cd blockchain
npx hardhat run scripts/demo.js
```

### Demo Steps

1. **Deploy Contract**: Deploys EvidenceRegistry to local network
2. **Generate Report**: Creates test forensic report
3. **Calculate Hash**: Computes SHA-256 hash of report
4. **Register Evidence**: Stores hash on blockchain
5. **Retrieve Record**: Gets blockchain evidence record
6. **Verify Original**: Confirms original report integrity (✓ VERIFIED)
7. **Tamper Evidence**: Modifies report content
8. **Calculate New Hash**: Computes hash of tampered report
9. **Verify Tampered**: Detects tampering (🚨 TAMPERED)
10. **Chain of Custody**: Demonstrates restricted stage updates

### Expected Output

```
=== BLOCKCHAIN EVIDENCE INTEGRITY DEMO ===

✓ Contract deployed successfully
✓ Evidence registered on blockchain
✓ Original report verified: EVIDENCE VERIFIED
✓ Tampered report detected: EVIDENCE TAMPERED
✓ Chain of custody tracked through stages
```

## 🚢 Deployment to Polygon Amoy

### Prerequisites

1. Get testnet MATIC tokens from [Polygon Faucet](https://faucet.polygon.technology/)
2. Configure environment variables
3. Ensure sufficient gas fees

### Deployment Steps

1. **Configure .env**:
```bash
cd blockchain
cp .env.example .env
# Edit with your Polygon Amoy credentials
```

2. **Deploy to Amoy**:
```bash
npx hardhat run scripts/deploy.js --network amoy
```

3. **Verify on Explorer**:
   - Copy contract address from deployment output
   - View on [Polygon Amoy Explorer](https://amoy.polygonscan.com)

4. **Update backend configuration**:
```bash
cd ../backend
cp .env.example .env
# Set BLOCKCHAIN_CONTRACT_ADDRESS to deployed address
```

### Deployment Commands

```bash
# Compile contracts
npx hardhat compile

# Deploy to Polygon Amoy
npx hardhat run scripts/deploy.js --network amoy

# Verify contract (optional)
npx hardhat verify --network amoy CONTRACT_ADDRESS CONSTRUCTOR_ARGS
```

## 🛠️ Troubleshooting

### Common Issues

**Issue**: "hardhat not recognized"
- **Solution**: Use `npx hardhat` instead of `hardhat`

**Issue**: "Private key not found"
- **Solution**: Check .env file configuration

**Issue**: "Insufficient funds"
- **Solution**: Get testnet tokens from faucet

**Issue**: "Contract verification failed"
- **Solution**: Check constructor arguments match deployment

**Issue**: "Backend can't connect to blockchain"
- **Solution**: Ensure RPC URL is correct and network is accessible

## 📝 Frontend Integration

### Data for Frontend Display

The blockchain service provides data for frontend display:

```json
{
  "available": true,
  "connected": true,
  "network_id": 80002,
  "latest_block": 12345678,
  "contract_address": "0x1234...",
  "account_address": "0x5678..."
}
```

### Evidence Display Format

```
Blockchain Evidence

Status: ✓ VERIFIED
Network: Polygon Amoy
Evidence ID: EVID-20260907-ABC123
Evidence Hash: 0x1234...
Transaction Hash: 0xabcd...
Timestamp: 2026-09-07T04:46:04.000Z
Stage: FORENSIC_REPORT
```

### Tampered Evidence Display

```
🚨 EVIDENCE TAMPERED

Original Blockchain Hash: 0x1234...
Current Hash: 0x5678...
Evidence ID: EVID-20260907-ABC123
Network: Polygon Amoy
```

## 🔗 Additional Resources

- [Polygon Documentation](https://docs.polygon.technology/)
- [Hardhat Documentation](https://hardhat.org/docs)
- [Solidity Documentation](https://docs.soliditylang.org/)
- [Web3.py Documentation](https://web3py.readthedocs.io/)
- [Ethereum Smart Contract Security](https://consensys.github.io/smart-contract-best-practices/)

## 📄 License

This project is part of SIH26106 Email Threat Intelligence Platform by Team Dino Coders.

## 👥 Team

- **Blockchain Module**: Gogulraj A
- **Project**: SIH 2026 | PS 261016 | Team Dino Coders

---

**Note**: This blockchain module is designed for forensic evidence integrity verification. Always follow proper forensic procedures and legal requirements when handling digital evidence.