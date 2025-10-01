# 🔐 Secure File Storage with Blockchain Integration

A comprehensive web application that provides encrypted file storage with digital signatures and blockchain-based access logging using Sepolia testnet.

## 🌟 Features

### Core Security Features
- **AES-256 Encryption**: All files are encrypted before storage
- **ECDSA Digital Signatures**: Files are digitally signed for authenticity verification
- **User Authentication**: Secure login with password hashing
- **Access Control**: Role-based permissions (read, write, admin)

### Blockchain Integration
- **Smart Contract Logging**: File uploads and access changes logged on Sepolia blockchain
- **Immutable Audit Trail**: All file operations recorded on blockchain
- **Public Verification**: Anyone can verify file operations via Etherscan
- **Decentralized Access Control**: Access permissions managed on blockchain

### File Management
- **Encrypted Upload**: Files encrypted with user-specific keys
- **Secure Download**: Automatic decryption and signature verification
- **File Sharing**: Grant access to other users with time-based expiration
- **Access Logging**: Complete audit trail of file access attempts
- **Transaction History**: View all blockchain transactions for each file

## 🏗️ Architecture

### Technology Stack
- **Backend**: Flask (Python)
- **Database**: SQLite with SQLAlchemy ORM
- **Encryption**: AES-256 (Fernet) + ECDSA digital signatures
- **Blockchain**: Ethereum Sepolia testnet
- **Smart Contract**: Solidity (FileAccessRegistry.sol)

### Security Model
```
User Upload → AES Encryption → ECDSA Signing → Blockchain Logging → Secure Storage
User Download → Access Check → Decryption → Signature Verification → File Delivery
```

## 📋 Prerequisites

- **Python 3.8+** (recommended: Python 3.11+)
- **Sepolia testnet ETH** (for gas fees) - Get from [Sepolia Faucet](https://sepoliafaucet.com/)
- **Infura Account** (for blockchain access) - Sign up at [Infura](https://infura.io/)

## 🚀 Complete Setup Guide

### Step 1: Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### Step 2: Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Set Up Blockchain Environment

#### 3.1 Get Sepolia Testnet ETH
1. Visit [Sepolia Faucet](https://sepoliafaucet.com/)
2. Enter your wallet address
3. Request test ETH (you'll need ~0.1 ETH for deployment and transactions)

#### 3.2 Create Infura Account
1. Go to [Infura](https://infura.io/)
2. Sign up for a free account
3. Create a new project
4. Copy your project ID

#### 3.3 Generate Wallet (if needed)
If you don't have a wallet, you can generate one:
```bash
# Install web3 if not already installed
pip install web3

# Generate a new wallet
python3 -c "
from web3 import Web3
from eth_account import Account
import secrets

# Generate private key
private_key = '0x' + secrets.token_hex(32)
account = Account.from_key(private_key)

print(f'Private Key: {private_key}')
print(f'Address: {account.address}')
print(f'Please fund this address with Sepolia ETH from the faucet')
"
```

### Step 4: Configure Environment Variables

Create a `.env` file in the project root:
```bash
# Copy the example environment file
cp env.example .env

# Edit the .env file with your actual values
nano .env  # or use your preferred editor
```

**Required Variables:**
- `RPC_URL` - Your Infura project URL
- `PRIVATE_KEY` - Your wallet private key (without 0x prefix)
- `ACCOUNT_ADDRESS` - Your wallet address
- `CHAIN_ID` - Always 11155111 for Sepolia

**Example .env file:**
```env
# Blockchain Configuration
RPC_URL=https://sepolia.infura.io/v3/YOUR_INFURA_PROJECT_ID
PRIVATE_KEY=your_private_key_here_without_0x_prefix
ACCOUNT_ADDRESS=your_account_address_here
CHAIN_ID=11155111

# Application Configuration (Optional)
SECRET_KEY=your-secret-key-here-for-flask-sessions
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=16777216
```

**Important Notes:**
- Replace `YOUR_INFURA_PROJECT_ID` with your actual Infura project ID
- Replace `your_private_key_here_without_0x_prefix` with your private key (without 0x prefix)
- Replace `your_account_address_here` with your wallet address
- The `SECRET_KEY` can be any random string for Flask sessions

### Step 5: Deploy Smart Contract

#### 5.1 Install Solidity Compiler
```bash
# Option 1: Using pip (recommended)
pip install py-solc-x

# Option 2: Using npm
npm install -g solc

# Option 3: Using system package manager
# macOS:
brew install solidity

# Ubuntu/Debian:
sudo apt-get install solc
```

#### 5.2 Deploy Contract
```bash
python deploy_working.py
```

This will:
- Compile the smart contract
- Deploy it to Sepolia testnet
- Save contract address and ABI to `contract_info.json`
- Display Etherscan URL for verification

### Step 6: Initialize Database
```bash
python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('Database initialized successfully!')
"
```

### Step 7: Run Application
```bash
# Option 1: Using the start script
./start.sh

# Option 2: Direct Python execution
python app.py
```

The application will be available at: **http://localhost:5001**

## 🐛 Debugging Guide

### Enable Debug Mode
```bash
# Set debug environment variable
export FLASK_DEBUG=1

# Run application with debug mode
python app.py
```

### Common Debug Commands

#### Check Blockchain Connection
```bash
python -c "
from blockchain_service import BlockchainService
try:
    bs = BlockchainService()
    print('✅ Blockchain connection successful')
    print(f'Account: {bs.account_address}')
    print(f'Balance: {bs.get_balance()} ETH')
except Exception as e:
    print(f'❌ Connection failed: {e}')
"
```

#### Check Database Status
```bash
python -c "
from app import app, db
with app.app_context():
    from app import User, File
    user_count = User.query.count()
    file_count = File.query.count()
    print(f'Users: {user_count}')
    print(f'Files: {file_count}')
"
```

#### Verify Environment Variables
```bash
python -c "
import os
from dotenv import load_dotenv
load_dotenv()

required_vars = ['RPC_URL', 'PRIVATE_KEY', 'ACCOUNT_ADDRESS', 'CHAIN_ID']
for var in required_vars:
    value = os.getenv(var)
    if value:
        print(f'✅ {var}: Set')
    else:
        print(f'❌ {var}: Missing')
"
```

#### Test Smart Contract Deployment
```bash
python -c "
import json
try:
    with open('contract_info.json', 'r') as f:
        contract_info = json.load(f)
    print('✅ Contract deployed successfully')
    print(f'Address: {contract_info.get(\"contract_address\", \"Not found\")}')
except FileNotFoundError:
    print('❌ Contract not deployed - run: python deploy_working.py')
except Exception as e:
    print(f'❌ Error reading contract info: {e}')
"
```

### Debug Logs
When debug mode is enabled, you'll see detailed logs including:
- Blockchain transaction details
- Database operations
- File encryption/decryption status
- Access control decisions
- Error stack traces

### Reset Application State
```bash
# Reset database (WARNING: This will delete all data)
rm instance/users.db
python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('Database reset successfully!')
"

# Clear uploaded files
rm -rf uploads/encrypted/*

# Redeploy contract (if needed)
python deploy_working.py
```

## 🔧 Environment Configuration Details

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `RPC_URL` | Infura RPC endpoint for Sepolia | `https://sepolia.infura.io/v3/abc123...` |
| `PRIVATE_KEY` | Wallet private key (64 hex chars) | `9c2fc743b22d7cb164bec27d080b71e36a2f576a4fdfef45efa9800cfeb30a78` |
| `ACCOUNT_ADDRESS` | Wallet address | `0xB218C72DaDcD02d0B99586371f37F47Dcf6Ba593` |
| `CHAIN_ID` | Sepolia chain ID | `11155111` |

### Optional Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask session secret | Auto-generated |
| `UPLOAD_FOLDER` | File upload directory | `uploads` |
| `MAX_CONTENT_LENGTH` | Max file size (bytes) | `16777216` (16MB) |

## 🔗 Smart Contract Documentation

### Contract Address
**Contract Name**: FileAccessRegistry  
**Network**: Sepolia Testnet  
**Contract Address**: `0x93D3b1b10d2a52a493729788dfd7705b85FBd4Fb`  
**Etherscan URL**: https://sepolia.etherscan.io/address/0x93D3b1b10d2a52a493729788dfd7705b85FBd4Fb

### Contract Functions

#### File Management
- `uploadFile(bytes32 fileId, string filename, string description, string uploaderId, string fileHash)` - Register new file upload
- `getFile(bytes32 fileId)` - Get file metadata
- `checkAccess(bytes32 fileId, address requester)` - Check user access

#### Access Control
- `requestAccess(bytes32 fileId, string requesterId)` - Request file access
- `approveAccess(bytes32 fileId, uint256 index, string encryptedKey)` - Approve access request
- `revokeAccess(bytes32 fileId, address user)` - Revoke user access

### Contract Events

#### FileUploaded
```solidity
event FileUploaded(
    bytes32 indexed fileId,
    address indexed owner,
    string filename,
    string uploaderId,
    uint256 timestamp,
    string fileHash
);
```

#### AccessRequested
```solidity
event AccessRequested(
    bytes32 indexed fileId,
    address indexed requester,
    string requesterId,
    uint256 timestamp
);
```

#### AccessApproved
```solidity
event AccessApproved(
    bytes32 indexed fileId,
    address indexed requester,
    string encryptedKey,
    uint256 timestamp
);
```

#### AccessRevoked
```solidity
event AccessRevoked(
    bytes32 indexed fileId,
    address indexed user,
    uint256 timestamp
);
```

## 🎯 Usage Guide

### 1. User Registration
1. Navigate to the application
2. Click "Register" to create a new account
3. Enter email and password
4. Login with your credentials

### 2. File Upload
1. Go to Dashboard
2. Click "Upload File"
3. Select file and add description
4. File will be:
   - Encrypted with AES-256
   - Digitally signed with ECDSA
   - Uploaded to blockchain
   - Stored securely

### 3. File Sharing
1. Go to "My Files"
2. Click "Share" on any file
3. Enter user email and permission level
4. Set expiration date (optional)
5. Access will be logged on blockchain

### 4. View Transaction History
1. Go to "My Files"
2. Click "🔗 Transactions" on any file
3. View all blockchain transactions
4. Click Etherscan links to verify on blockchain

### 5. Access Logs
1. Go to "My Files"
2. Click "📊 Logs" on any file
3. View complete access audit trail
4. See IP addresses and user agents

## 🔍 Verification

### Blockchain Verification
1. Visit the [Etherscan contract page](https://sepolia.etherscan.io/address/0x93D3b1b10d2a52a493729788dfd7705b85FBd4Fb)
2. Check "Transactions" tab for all operations
3. Verify file uploads and access changes
4. Confirm gas usage and timestamps

### Digital Signature Verification
1. Download any file
2. The application automatically verifies the digital signature
3. Check the signature display in file information
4. Verify authenticity and integrity

## 🛠️ Troubleshooting

### Common Issues

#### 1. "Insufficient funds" Error
**Solution**: Get more Sepolia ETH from the faucet
```bash
# Check balance
python -c "
from blockchain_service import BlockchainService
bs = BlockchainService()
print(f'Balance: {bs.get_balance()} ETH')
"
```

#### 2. "Contract not deployed" Error
**Solution**: Deploy the contract
```bash
python deploy_working.py
```

#### 3. "Template not found" Error
**Solution**: Ensure all template files are present
```bash
ls templates/
# Should show all .html files
```

#### 4. Database Errors
**Solution**: Recreate database
```bash
rm instance/users.db
python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('Database recreated!')
"
```

#### 5. Blockchain Connection Issues
**Solution**: Check environment variables
```bash
# Verify .env file
cat .env

# Test connection
python -c "
from blockchain_service import BlockchainService
try:
    bs = BlockchainService()
    print('✅ Blockchain connection successful')
except Exception as e:
    print(f'❌ Connection failed: {e}')
"
```

### Debug Mode
Enable debug mode for detailed error messages:
```bash
export FLASK_DEBUG=1
python app.py
```

## 📁 Project Structure

```
proj2/
├── app.py                          # Main Flask application
├── blockchain_service.py           # Blockchain interaction service
├── deploy_working.py              # Smart contract deployment script
├── requirements.txt               # Python dependencies
├── .env                          # Environment variables
├── contract_info.json            # Deployed contract information
├── contracts/
│   └── FileAccessRegistry.sol    # Smart contract source
├── templates/                     # HTML templates
│   ├── dashboard.html
│   ├── files.html
│   ├── transaction_history.html
│   ├── access_logs.html
│   ├── share_file.html
│   ├── blockchain_status.html
│   └── ...
├── uploads/                       # Encrypted file storage
│   └── encrypted/
├── instance/                      # Database files
│   └── users.db
└── venv/                         # Virtual environment
```

## 🔒 Security Considerations

### Production Deployment
- Use HTTPS for all communications
- Store private keys securely (not in .env files)
- Use production database (PostgreSQL/MySQL)
- Implement rate limiting
- Add input validation and sanitization
- Use environment-specific configurations

### Key Management
- Never commit private keys to version control
- Use hardware wallets for production
- Implement key rotation policies
- Monitor for unauthorized access

## 📞 Support

For issues and questions:
1. Check the troubleshooting section above
2. Verify all environment variables are correct
3. Ensure sufficient Sepolia ETH balance
4. Check blockchain connection status

## 📄 License

This project is for educational and demonstration purposes. Please ensure compliance with local regulations when using blockchain technology.

---

**Built with ❤️ using Flask, Solidity, and Web3.py**