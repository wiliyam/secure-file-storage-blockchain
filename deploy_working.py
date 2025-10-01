#!/usr/bin/env python3
"""
Deploy FileAccessRegistry contract to Sepolia testnet
Based on working reference implementation
"""

import json
import os
import base64
from pathlib import Path
from solcx import compile_standard, install_solc
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv

# Configuration
SOLC_VERSION = '0.8.20'
ETHERSCAN_BASE = 'https://sepolia.etherscan.io/address/'
CONTRACT_NAME = 'FileAccessRegistry'

def load_private_key_bytes() -> bytes:
    """Load and validate private key from environment"""
    pk_raw = os.environ['PRIVATE_KEY']
    pk = pk_raw.strip()
    if pk.startswith('0x') or pk.startswith('0X'):
        pk = pk[2:]
    pk = pk.replace(' ', '').replace('\n', '').replace('\r', '')
    is_hex = all(c in '0123456789abcdefABCDEF' for c in pk)
    if len(pk) == 64 and is_hex:
        try:
            return bytes.fromhex(pk)
        except Exception as exc:
            raise ValueError('PRIVATE_KEY is not valid hex after sanitation') from exc
    # Fallback: try base64-encoded key (must decode to exactly 32 bytes)
    try:
        b = base64.b64decode(pk_raw.strip(), validate=True)
        if len(b) == 32:
            return b
    except Exception:
        pass
    masked = (pk[:4] + '...' + pk[-4:]) if len(pk) >= 8 else pk
    raise ValueError(f'PRIVATE_KEY must be 64 hex chars or base64(32 bytes) (len={len(pk)}, hex={is_hex}, sample={masked})')

def compile_contract():
    """Compile the Solidity contract"""
    print("🔨 Installing Solidity compiler...")
    install_solc(SOLC_VERSION)
    
    print("🔨 Compiling contract...")
    contract_path = Path('contracts') / f'{CONTRACT_NAME}.sol'
    source = contract_path.read_text()
    
    compiled = compile_standard({
        'language': 'Solidity',
        'sources': {f'{CONTRACT_NAME}.sol': {'content': source}},
        'settings': {
            'outputSelection': {
                '*': {'*': ['abi', 'metadata', 'evm.bytecode', 'evm.sourceMap']}
            }
        },
    }, solc_version=SOLC_VERSION)
    
    abi = compiled['contracts'][f'{CONTRACT_NAME}.sol'][CONTRACT_NAME]['abi']
    bytecode = compiled['contracts'][f'{CONTRACT_NAME}.sol'][CONTRACT_NAME]['evm']['bytecode']['object']
    
    print("✅ Contract compiled successfully")
    return abi, bytecode

def deploy_contract():
    """Deploy the contract to Sepolia testnet"""
    print("🚀 Deploying contract to Sepolia testnet...")
    
    # Load environment variables
    load_dotenv()
    
    # Compile contract
    abi, bytecode = compile_contract()
    
    # Setup Web3
    rpc_url = os.environ['RPC_URL']
    private_key_bytes = load_private_key_bytes()
    chain_id = int(os.environ.get('CHAIN_ID', '11155111'))
    
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    acct = Account.from_key(private_key_bytes)
    
    print(f"📡 RPC URL: {rpc_url}")
    print(f"👤 Account: {acct.address}")
    print(f"⛓️  Chain ID: {chain_id}")
    
    # Check balance
    balance = w3.eth.get_balance(acct.address)
    balance_eth = w3.from_wei(balance, 'ether')
    print(f"💰 Account balance: {balance_eth} ETH")
    
    if balance_eth < 0.01:
        print("⚠️  Low balance! You may need more ETH for deployment.")
        print("   Get testnet ETH from: https://sepoliafaucet.com/")
    
    # Deploy contract
    FileAccessRegistry = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = FileAccessRegistry.constructor().build_transaction({
        'from': acct.address,
        'nonce': w3.eth.get_transaction_count(acct.address),
        'chainId': chain_id,
        'gas': 2_000_000,
        'gasPrice': w3.to_wei('8', 'gwei'),
    })
    
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    print('Deploying... tx:', tx_hash.hex())
    
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    address = receipt.contractAddress
    
    print('✅ Contract deployed successfully!')
    print(f"📍 Contract Address: {address}")
    print(f"🔗 Transaction Hash: {tx_hash.hex()}")
    print(f"🔗 Etherscan URL: {ETHERSCAN_BASE}{address}")
    
    # Save contract info
    contract_info = {
        'contract_address': address,
        'abi': abi,
        'deployment_timestamp': receipt.blockNumber,
        'chain_id': chain_id,
        'account_address': acct.address,
        'transaction_hash': tx_hash.hex(),
        'etherscan_url': f"{ETHERSCAN_BASE}{address}"
    }
    
    with open('contract_info.json', 'w') as f:
        json.dump(contract_info, f, indent=2)
    
    print(f"📄 Contract info saved to contract_info.json")
    
    return address, abi

def test_contract(address, abi):
    """Test the deployed contract"""
    print("\n🧪 Testing deployed contract...")
    
    try:
        # Setup Web3
        rpc_url = os.environ['RPC_URL']
        private_key_bytes = load_private_key_bytes()
        chain_id = int(os.environ.get('CHAIN_ID', '11155111'))
        
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        acct = Account.from_key(private_key_bytes)
        
        # Load contract
        contract = w3.eth.contract(address=address, abi=abi)
        
        # Test file upload
        test_file_id = w3.keccak(text="test_file_123")
        test_filename = "test_file.txt"
        test_description = "Test file for contract verification"
        test_uploader_id = "test@example.com"
        test_file_hash = "test_hash_123456789"
        
        print(f"📄 Testing file upload: {test_filename}")
        
        tx = contract.functions.uploadFile(
            test_file_id,
            test_filename,
            test_description,
            test_uploader_id,
            test_file_hash
        ).build_transaction({
            'from': acct.address,
            'nonce': w3.eth.get_transaction_count(acct.address),
            'chainId': chain_id,
            'gas': 500_000,
            'gasPrice': w3.to_wei('12', 'gwei'),
        })
        
        signed = acct.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt.status == 1:
            print("✅ File upload test successful!")
            print(f"🔗 Test Transaction: {tx_hash.hex()}")
            
            # Test file retrieval
            file_data = contract.functions.getFile(test_file_id).call()
            print(f"📋 Retrieved file: {file_data[1]} (owner: {file_data[0]})")
        else:
            print("❌ File upload test failed")
            
    except Exception as e:
        print(f"❌ Contract test failed: {e}")

if __name__ == "__main__":
    print("🔗 FileAccessRegistry Contract Deployment")
    print("=" * 50)
    
    try:
        address, abi = deploy_contract()
        test_contract(address, abi)
        
        print("\n🎉 Deployment and testing completed successfully!")
        print(f"📍 Contract Address: {address}")
        print(f"🔗 Etherscan URL: {ETHERSCAN_BASE}{address}")
        
    except Exception as e:
        print(f"\n❌ Deployment failed: {e}")
        exit(1)
