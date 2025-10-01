"""
Blockchain service for file access logging using Sepolia testnet
"""

import os
import json
import hashlib
from datetime import datetime
from web3 import Web3
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class BlockchainService:
    def __init__(self):
        """Initialize blockchain connection"""
        self.rpc_url = os.getenv('RPC_URL')
        self.private_key = os.getenv('PRIVATE_KEY')
        self.account_address = os.getenv('ACCOUNT_ADDRESS')
        self.chain_id = int(os.getenv('CHAIN_ID', 11155111))
        
        if not all([self.rpc_url, self.private_key, self.account_address]):
            raise ValueError("Missing required blockchain environment variables")
        
        # Initialize Web3
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        
        if not self.w3.is_connected():
            raise ConnectionError("Failed to connect to Sepolia network")
        
        # Contract details (will be set after deployment)
        self.contract_address = None
        self.contract_abi = None
        self.contract = None
        
        print(f"✅ Connected to Sepolia network")
        print(f"📡 RPC URL: {self.rpc_url}")
        print(f"👤 Account: {self.account_address}")
        print(f"⛓️  Chain ID: {self.chain_id}")
    
    def deploy_contract(self, contract_bytecode, contract_abi):
        """Deploy the smart contract to Sepolia"""
        try:
            # Create contract instance
            contract = self.w3.eth.contract(bytecode=contract_bytecode, abi=contract_abi)
            
            # Build transaction
            transaction = contract.constructor().build_transaction({
                'from': self.account_address,
                'gas': 2000000,  # Adjust gas limit as needed
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account_address),
                'chainId': self.chain_id
            })
            
            # Sign transaction
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
            
            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                self.contract_address = receipt.contractAddress
                self.contract_abi = contract_abi
                self.contract = self.w3.eth.contract(
                    address=self.contract_address,
                    abi=self.contract_abi
                )
                
                print(f"✅ Contract deployed successfully!")
                print(f"📍 Contract Address: {self.contract_address}")
                print(f"🔗 Transaction Hash: {tx_hash.hex()}")
                
                return self.contract_address
            else:
                raise Exception("Contract deployment failed")
                
        except Exception as e:
            print(f"❌ Contract deployment failed: {e}")
            raise
    
    def load_contract(self, contract_address, contract_abi):
        """Load an existing deployed contract"""
        self.contract_address = contract_address
        self.contract_abi = contract_abi
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=self.contract_abi
        )
        print(f"✅ Contract loaded: {contract_address}")
    
    def register_file_upload(self, filename, file_content_hash, description="", uploader_id=""):
        """Register a file upload on the blockchain"""
        if not self.contract:
            raise Exception("Contract not deployed or loaded")
        
        try:
            # Generate file ID using keccak256 hash
            file_id = self.w3.keccak(text=f"{filename}_{file_content_hash}_{self.account_address}")
            
            # Build transaction
            transaction = self.contract.functions.uploadFile(
                file_id,
                filename,
                description,
                uploader_id,
                file_content_hash
            ).build_transaction({
                'from': self.account_address,
                'gas': 500000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account_address),
                'chainId': self.chain_id
            })
            
            # Sign and send transaction
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                print(f"✅ File upload registered on blockchain")
                print(f"📄 File ID: {file_id.hex()}")
                print(f"🔗 Transaction Hash: {tx_hash.hex()}")
                return {'file_id': file_id.hex(), 'tx_hash': tx_hash.hex()}
            else:
                raise Exception("Transaction failed")
                
        except Exception as e:
            print(f"❌ Failed to register file upload: {e}")
            raise
    
    def request_file_access(self, file_id, requester_address, permission):
        """Request access to a file on the blockchain"""
        if not self.contract:
            raise Exception("Contract not deployed or loaded")
        
        try:
            # Build transaction
            transaction = self.contract.functions.requestFileAccess(
                file_id,
                permission
            ).build_transaction({
                'from': requester_address,
                'gas': 150000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(requester_address),
                'chainId': self.chain_id
            })
            
            # Sign and send transaction
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                print(f"✅ Access request submitted to blockchain")
                print(f"🔗 Transaction Hash: {tx_hash.hex()}")
                return tx_hash.hex()
            else:
                raise Exception("Transaction failed")
                
        except Exception as e:
            print(f"❌ Failed to request file access: {e}")
            raise
    
    def approve_access_request(self, file_id, requester_address, approved=True):
        """Approve or deny an access request on the blockchain"""
        if not self.contract:
            raise Exception("Contract not deployed or loaded")
        
        try:
            # Build transaction
            transaction = self.contract.functions.approveAccessRequest(
                file_id,
                requester_address,
                approved
            ).build_transaction({
                'from': self.account_address,
                'gas': 150000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account_address),
                'chainId': self.chain_id
            })
            
            # Sign and send transaction
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                action = "approved" if approved else "denied"
                print(f"✅ Access request {action} on blockchain")
                print(f"🔗 Transaction Hash: {tx_hash.hex()}")
                return tx_hash.hex()
            else:
                raise Exception("Transaction failed")
                
        except Exception as e:
            print(f"❌ Failed to approve access request: {e}")
            raise
    
    def revoke_access(self, file_id, user_address):
        """Revoke access to a file on the blockchain"""
        if not self.contract:
            raise Exception("Contract not deployed or loaded")
        
        try:
            # Build transaction
            transaction = self.contract.functions.revokeAccess(
                file_id,
                user_address
            ).build_transaction({
                'from': self.account_address,
                'gas': 100000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account_address),
                'chainId': self.chain_id
            })
            
            # Sign and send transaction
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status == 1:
                print(f"✅ Access revoked on blockchain")
                print(f"🔗 Transaction Hash: {tx_hash.hex()}")
                return tx_hash.hex()
            else:
                raise Exception("Transaction failed")
                
        except Exception as e:
            print(f"❌ Failed to revoke access: {e}")
            raise
    
    def get_file_metadata(self, file_id):
        """Get file metadata from the blockchain"""
        if not self.contract:
            raise Exception("Contract not deployed or loaded")
        
        try:
            metadata = self.contract.functions.getFileMetadata(file_id).call()
            return {
                'fileId': metadata[0],
                'filename': metadata[1],
                'uploader': metadata[2],
                'uploadTimestamp': metadata[3],
                'fileHash': metadata[4],
                'exists': metadata[5]
            }
        except Exception as e:
            print(f"❌ Failed to get file metadata: {e}")
            return None
    
    def check_access(self, file_id, user_address):
        """Check if a user has access to a file"""
        if not self.contract:
            raise Exception("Contract not deployed or loaded")
        
        try:
            has_access = self.contract.functions.checkAccess(file_id, user_address).call()
            return has_access
        except Exception as e:
            print(f"❌ Failed to check access: {e}")
            return False
    
    def get_balance(self):
        """Get the account balance"""
        try:
            balance_wei = self.w3.eth.get_balance(self.account_address)
            balance_eth = self.w3.from_wei(balance_wei, 'ether')
            return balance_eth
        except Exception as e:
            print(f"❌ Failed to get balance: {e}")
            return 0

def calculate_file_hash(file_content):
    """Calculate SHA-256 hash of file content"""
    return hashlib.sha256(file_content).hexdigest()

# Contract ABI (this would be generated after compilation)
CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "string", "name": "_filename", "type": "string"},
            {"internalType": "string", "name": "_fileHash", "type": "string"}
        ],
        "name": "registerFileUpload",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "_fileId", "type": "uint256"},
            {"internalType": "string", "name": "_permission", "type": "string"}
        ],
        "name": "requestFileAccess",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "_fileId", "type": "uint256"},
            {"internalType": "address", "name": "_requester", "type": "address"},
            {"internalType": "bool", "name": "_approved", "type": "bool"}
        ],
        "name": "approveAccessRequest",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "_fileId", "type": "uint256"},
            {"internalType": "address", "name": "_user", "type": "address"}
        ],
        "name": "revokeAccess",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "_fileId", "type": "uint256"},
            {"internalType": "address", "name": "_user", "type": "address"}
        ],
        "name": "checkAccess",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "_fileId", "type": "uint256"}],
        "name": "getFileMetadata",
        "outputs": [
            {
                "components": [
                    {"internalType": "uint256", "name": "fileId", "type": "uint256"},
                    {"internalType": "string", "name": "filename", "type": "string"},
                    {"internalType": "address", "name": "uploader", "type": "address"},
                    {"internalType": "uint256", "name": "uploadTimestamp", "type": "uint256"},
                    {"internalType": "string", "name": "fileHash", "type": "string"},
                    {"internalType": "bool", "name": "exists", "type": "bool"}
                ],
                "internalType": "struct FileAccessRegistry.FileMetadata",
                "name": "",
                "type": "tuple"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "fileId", "type": "uint256"},
            {"indexed": False, "internalType": "string", "name": "filename", "type": "string"},
            {"indexed": True, "internalType": "address", "name": "uploader", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"indexed": False, "internalType": "string", "name": "fileHash", "type": "string"}
        ],
        "name": "FileUploaded",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "fileId", "type": "uint256"},
            {"indexed": True, "internalType": "address", "name": "requester", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "owner", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"indexed": False, "internalType": "string", "name": "permission", "type": "string"}
        ],
        "name": "AccessRequested",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "fileId", "type": "uint256"},
            {"indexed": True, "internalType": "address", "name": "requester", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "owner", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"indexed": False, "internalType": "string", "name": "permission", "type": "string"},
            {"indexed": False, "internalType": "bool", "name": "approved", "type": "bool"}
        ],
        "name": "AccessGranted",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "fileId", "type": "uint256"},
            {"indexed": True, "internalType": "address", "name": "user", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "owner", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "name": "AccessRevoked",
        "type": "event"
    }
]
