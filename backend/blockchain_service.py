"""
Blockchain Service for Digital Evidence Integrity.
Integrates with EvidenceRegistry smart contract for tamper-proof evidence verification.
"""

import os
import json
from typing import Optional, Dict, Any
from datetime import datetime, timezone

try:
    from web3 import Web3
    from web3.contract import Contract
    from eth_account import Account
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False
    Web3 = None
    Contract = None
    Account = None


class BlockchainService:
    """
    Service for interacting with the EvidenceRegistry smart contract.
    Handles evidence registration, verification, and blockchain data retrieval.
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        private_key: Optional[str] = None,
        contract_address: Optional[str] = None,
        contract_abi_path: Optional[str] = None
    ):
        """
        Initialize blockchain service with connection parameters.
        
        Args:
            rpc_url: Blockchain RPC URL (defaults to environment variable or localhost)
            private_key: Private key for signing transactions (defaults to environment variable)
            contract_address: Deployed contract address (defaults to environment variable)
            contract_abi_path: Path to contract ABI JSON file
        """
        if not WEB3_AVAILABLE:
            raise ImportError(
                "web3.py is not installed. Install it with: pip install web3"
            )

        self.rpc_url = rpc_url or os.environ.get(
            "BLOCKCHAIN_RPC_URL",
            "http://127.0.0.1:8545"  # Default to local Hardhat node
        )
        self.private_key = private_key or os.environ.get("BLOCKCHAIN_PRIVATE_KEY")
        self.contract_address = contract_address or os.environ.get("BLOCKCHAIN_CONTRACT_ADDRESS")
        
        # Initialize Web3 connection
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        
        # Check connection
        if not self.w3.is_connected():
            raise ConnectionError(f"Failed to connect to blockchain at {self.rpc_url}")
        
        # Load contract ABI
        self.contract_abi = self._load_contract_abi(contract_abi_path)
        
        # Initialize contract if address is provided
        self.contract = None
        if self.contract_address:
            self.contract = self.w3.eth.contract(
                address=self.contract_address,
                abi=self.contract_abi
            )
        
        # Set up account if private key is provided
        self.account = None
        if self.private_key:
            self.account = Account.from_key(self.private_key)
            self.w3.eth.default_account = self.account.address

    def _load_contract_abi(self, abi_path: Optional[str] = None) -> list:
        """
        Load contract ABI from file or use default compiled ABI.
        
        Args:
            abi_path: Path to ABI JSON file
            
        Returns:
            Contract ABI as list
        """
        if abi_path and os.path.exists(abi_path):
            with open(abi_path, 'r') as f:
                return json.load(f)
        
        # Try to load from blockchain directory
        default_abi_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "blockchain",
            "artifacts",
            "contracts",
            "EvidenceRegistry.sol",
            "EvidenceRegistry.json"
        )
        
        if os.path.exists(default_abi_path):
            with open(default_abi_path, 'r') as f:
                contract_data = json.load(f)
                return contract_data.get("abi", [])
        
        # Fallback: return minimal ABI for EvidenceRegistry
        return self._get_minimal_abi()

    def _get_minimal_abi(self) -> list:
        """
        Return minimal ABI for EvidenceRegistry contract.
        Used as fallback when compiled ABI is not available.
        """
        return [
            {
                "inputs": [
                    {"internalType": "string", "name": "evidenceId", "type": "string"},
                    {"internalType": "bytes32", "name": "evidenceHash", "type": "bytes32"},
                    {"internalType": "string", "name": "stage", "type": "string"}
                ],
                "name": "registerEvidence",
                "outputs": [{"internalType": "uint256", "name": "timestamp", "type": "uint256"}],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "string", "name": "evidenceId", "type": "string"}],
                "name": "getEvidence",
                "outputs": [
                    {"internalType": "bytes32", "name": "evidenceHash", "type": "bytes32"},
                    {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
                    {"internalType": "string", "name": "stage", "type": "string"},
                    {"internalType": "address", "name": "submitter", "type": "address"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "string", "name": "evidenceId", "type": "string"},
                    {"internalType": "bytes32", "name": "currentHash", "type": "bytes32"}
                ],
                "name": "verifyEvidence",
                "outputs": [
                    {"internalType": "bool", "name": "verified", "type": "bool"},
                    {"internalType": "bytes32", "name": "blockchainHash", "type": "bytes32"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "string", "name": "evidenceId", "type": "string"}],
                "name": "evidenceRecordExists",
                "outputs": [{"internalType": "bool", "name": "exists", "type": "bool"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "getEvidenceCount",
                "outputs": [{"internalType": "uint256", "name": "count", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"internalType": "string", "name": "evidenceId", "type": "string"}],
                "name": "getEvidenceHash",
                "outputs": [{"internalType": "bytes32", "name": "evidenceHash", "type": "bytes32"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]

    def sha256_to_bytes32(self, sha256_hex: str) -> str:
        """
        Convert SHA-256 hex string to bytes32 format for smart contract.
        
        Args:
            sha256_hex: 64-character hexadecimal SHA-256 hash
            
        Returns:
            bytes32 formatted hash with 0x prefix
        """
        if not sha256_hex.startswith("0x"):
            sha256_hex = "0x" + sha256_hex
        
        # Ensure it's exactly 64 hex characters (32 bytes)
        if len(sha256_hex) != 66:  # 0x + 64 hex chars
            raise ValueError(f"Invalid SHA-256 hash length: {len(sha256_hex)}")
        
        return sha256_hex

    def register_evidence(
        self,
        evidence_id: str,
        sha256_hash: str,
        stage: str = "FORENSIC_ANALYSIS"
    ) -> Dict[str, Any]:
        """
        Register forensic evidence on blockchain.
        
        Args:
            evidence_id: Unique evidence identifier
            sha256_hash: SHA-256 hash of the evidence
            stage: Processing stage (e.g., FORENSIC_ANALYSIS, REPORT_GENERATED)
            
        Returns:
            Dictionary with registration result and transaction details
        """
        if not self.contract:
            raise ValueError("Contract not initialized. Provide contract_address.")
        
        if not self.account:
            raise ValueError("Account not initialized. Provide private_key.")
        
        # Convert hash to bytes32
        bytes32_hash = self.sha256_to_bytes32(sha256_hash)
        
        # Build transaction
        transaction = self.contract.functions.registerEvidence(
            evidence_id,
            bytes32_hash,
            stage
        ).build_transaction({
            'from': self.account.address,
            'gas': 200000,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(self.account.address),
        })
        
        # Sign and send transaction
        signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        
        # Wait for transaction receipt
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        return {
            "success": receipt.status == 1,
            "evidence_id": evidence_id,
            "blockchain_hash": sha256_hash,
            "stage": stage,
            "transaction_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def verify_evidence(
        self,
        evidence_id: str,
        current_sha256_hash: str
    ) -> Dict[str, Any]:
        """
        Verify evidence integrity against blockchain record.
        
        Args:
            evidence_id: Unique evidence identifier
            current_sha256_hash: Current SHA-256 hash of the evidence
            
        Returns:
            Dictionary with verification result and details
        """
        if not self.contract:
            raise ValueError("Contract not initialized. Provide contract_address.")
        
        # Convert current hash to bytes32
        bytes32_hash = self.sha256_to_bytes32(current_sha256_hash)
        
        # Check if evidence exists
        exists = self.contract.functions.evidenceRecordExists(evidence_id).call()
        if not exists:
            return {
                "verified": False,
                "status": "EVIDENCE_NOT_FOUND",
                "evidence_id": evidence_id,
                "reason": "Evidence ID not found on blockchain"
            }
        
        # Verify evidence
        verified, blockchain_hash = self.contract.functions.verifyEvidence(
            evidence_id,
            bytes32_hash
        ).call()
        
        # Convert blockchain hash back to hex format
        blockchain_hash_hex = blockchain_hash.hex()
        
        if verified:
            return {
                "verified": True,
                "status": "EVIDENCE_VERIFIED",
                "evidence_id": evidence_id,
                "blockchain_hash": blockchain_hash_hex,
                "current_hash": current_sha256_hash,
                "message": "Evidence integrity verified - no tampering detected"
            }
        else:
            return {
                "verified": False,
                "status": "EVIDENCE_TAMPERED",
                "evidence_id": evidence_id,
                "blockchain_hash": blockchain_hash_hex,
                "current_hash": current_sha256_hash,
                "message": "Evidence tampering detected - hash mismatch"
            }

    def get_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve evidence record from blockchain.
        
        Args:
            evidence_id: Unique evidence identifier
            
        Returns:
            Dictionary with evidence details or None if not found
        """
        if not self.contract:
            raise ValueError("Contract not initialized. Provide contract_address.")
        
        try:
            evidence_hash, timestamp, stage, submitter = self.contract.functions.getEvidence(
                evidence_id
            ).call()
            
            return {
                "evidence_id": evidence_id,
                "evidence_hash": evidence_hash.hex(),
                "timestamp": timestamp,
                "stage": stage,
                "submitter": submitter,
                "exists": True
            }
        except Exception as e:
            return None

    def get_blockchain_info(self) -> Dict[str, Any]:
        """
        Get blockchain network information.
        
        Returns:
            Dictionary with network details
        """
        return {
            "connected": self.w3.is_connected(),
            "network_id": self.w3.eth.chain_id,
            "latest_block": self.w3.eth.block_number,
            "gas_price": self.w3.eth.gas_price,
            "contract_address": self.contract_address,
            "account_address": self.account.address if self.account else None
        }

    def is_available(self) -> bool:
        """
        Check if blockchain service is available and configured.
        
        Returns:
            True if service is available, False otherwise
        """
        return WEB3_AVAILABLE and self.w3.is_connected()


# Singleton instance for application-wide use
_blockchain_service: Optional[BlockchainService] = None


def get_blockchain_service() -> Optional[BlockchainService]:
    """
    Get or create blockchain service singleton instance.
    
    Returns:
        BlockchainService instance or None if not available
    """
    global _blockchain_service
    
    if _blockchain_service is None:
        try:
            _blockchain_service = BlockchainService()
        except Exception:
            # Service not available (missing dependencies or configuration)
            return None
    
    return _blockchain_service


def convert_sha256_to_blockchain_format(sha256_hex: str) -> str:
    """
    Convert SHA-256 hex string to blockchain-compatible format.
    
    Args:
        sha256_hex: 64-character hexadecimal SHA-256 hash
        
    Returns:
        Blockchain-compatible hash with 0x prefix
    """
    if not sha256_hex.startswith("0x"):
        sha256_hex = "0x" + sha256_hex
    
    if len(sha256_hex) != 66:
        raise ValueError(f"Invalid SHA-256 hash: expected 64 hex characters, got {len(sha256_hex) - 2}")
    
    return sha256_hex