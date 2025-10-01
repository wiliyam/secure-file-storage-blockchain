#!/bin/bash

# Simple Web App with Encrypted File Upload and Digital Signatures
# Startup script for virtual environment

echo "🚀 Starting Simple Web App with Encrypted File Upload and Digital Signatures..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Creating..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "📦 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Install Solidity compiler if not present
if ! command -v solc &> /dev/null; then
    echo "Installing Solidity compiler..."
    brew install solidity
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p uploads/encrypted

# Migrate database if needed
echo "🔄 Checking database migration..."
python migrate_db.py

# Start the application
echo "🌟 Starting Flask application..."
echo "   - Application will be available at: http://localhost:5001"
echo "   - Press Ctrl+C to stop the server"
echo ""

python app.py


