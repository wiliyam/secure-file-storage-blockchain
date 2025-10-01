from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
import ecdsa
import os
import base64
import hashlib
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import blockchain service
try:
    from blockchain_service import BlockchainService, calculate_file_hash
    BLOCKCHAIN_AVAILABLE = True
except ImportError:
    print("⚠️ Blockchain service not available. Install web3.py to enable blockchain features.")
    BLOCKCHAIN_AVAILABLE = False

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads/encrypted'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize blockchain service
blockchain_service = None
if BLOCKCHAIN_AVAILABLE:
    try:
        blockchain_service = BlockchainService()
        # Try to load existing contract if available
        if os.path.exists('contract_info.json'):
            with open('contract_info.json', 'r') as f:
                contract_info = json.load(f)
            blockchain_service.load_contract(contract_info['contract_address'], contract_info['abi'])
            print("✅ Blockchain service initialized with existing contract")
        else:
            print("⚠️ No contract deployed yet. Run deploy_contract.py to deploy the smart contract.")
    except Exception as e:
        print(f"❌ Failed to initialize blockchain service: {e}")
        blockchain_service = None

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=True)  # ECDSA public key
    private_key_encrypted = db.Column(db.Text, nullable=True)  # Encrypted private key
    role = db.Column(db.String(20), default='user')  # user, admin, super_admin
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_key_pair(self):
        """Generate ECDSA key pair for the user"""
        # Generate private key
        private_key = ec.generate_private_key(ec.SECP256R1())
        
        # Get public key
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Encrypt private key with user's password hash
        encryption_key = hashlib.sha256(self.password_hash.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(encryption_key)
        fernet = Fernet(fernet_key)
        encrypted_private_key = fernet.encrypt(private_pem)
        
        # Store keys
        self.private_key_encrypted = base64.b64encode(encrypted_private_key).decode()
        self.public_key = base64.b64encode(public_pem).decode()
        
        return private_key, public_key
    
    def get_private_key(self, password):
        """Retrieve and decrypt private key"""
        if not self.private_key_encrypted:
            # Generate keys if they don't exist
            self.generate_key_pair()
            db.session.commit()
        
        try:
            # Decrypt private key
            encryption_key = hashlib.sha256(self.password_hash.encode()).digest()
            fernet_key = base64.urlsafe_b64encode(encryption_key)
            fernet = Fernet(fernet_key)
            
            encrypted_key = base64.b64decode(self.private_key_encrypted)
            private_pem = fernet.decrypt(encrypted_key)
            
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_pem,
                password=None
            )
            return private_key
        except Exception as e:
            print(f"Error decrypting private key: {e}")
            return None
    
    def get_public_key(self):
        """Retrieve public key"""
        if not self.public_key:
            return None
        
        try:
            public_pem = base64.b64decode(self.public_key)
            public_key = serialization.load_pem_public_key(public_pem)
            return public_key
        except Exception:
            return None

# File model
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encryption_key_hash = db.Column(db.String(128), nullable=False)
    digital_signature = db.Column(db.Text, nullable=True)  # ECDSA signature
    signature_hash = db.Column(db.String(128), nullable=True)  # Hash of signed content
    is_public = db.Column(db.Boolean, default=False)  # Public file sharing
    access_level = db.Column(db.String(20), default='private')  # private, shared, public
    blockchain_file_id = db.Column(db.Integer, nullable=True)  # Blockchain file ID
    blockchain_tx_hash = db.Column(db.String(66), nullable=True)  # Blockchain transaction hash
    
    # Relationships
    user = db.relationship('User', backref='files')

# File Access Control model
class FileAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    permission = db.Column(db.String(20), nullable=False)  # read, write, admin
    granted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)  # Optional expiration
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='file_accesses')
    granted_by_user = db.relationship('User', foreign_keys=[granted_by], backref='granted_accesses')
    file = db.relationship('File', backref='access_grants')

# File Sharing Invitation model
class FileInvitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    invited_email = db.Column(db.String(120), nullable=False)
    permission = db.Column(db.String(20), nullable=False)  # read, write, admin
    invited_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invitation_token = db.Column(db.String(128), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    is_accepted = db.Column(db.Boolean, default=False)
    accepted_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    file = db.relationship('File', backref='invitations')
    invited_by_user = db.relationship('User', foreign_keys=[invited_by], backref='sent_invitations')

# Access Log model for audit trail
class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # download, view, share, etc.
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)
    
    # Relationships
    file = db.relationship('File', backref='access_logs')
    user = db.relationship('User', backref='access_logs')

# Blockchain Transaction Log model
class BlockchainTransaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_hash = db.Column(db.String(66), nullable=False, unique=True)
    transaction_type = db.Column(db.String(50), nullable=False)  # upload, access_grant, access_revoke
    blockchain_file_id = db.Column(db.String(66), nullable=True)  # File ID on blockchain
    block_number = db.Column(db.Integer, nullable=True)
    gas_used = db.Column(db.Integer, nullable=True)
    gas_price = db.Column(db.String(20), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    etherscan_url = db.Column(db.String(200), nullable=True)
    
    # Relationships
    user = db.relationship('User', backref='blockchain_transactions')
    file = db.relationship('File', backref='blockchain_transactions')

# Encryption functions
def generate_encryption_key():
    """Generate a new encryption key"""
    return Fernet.generate_key()

def encrypt_file(file_data, key):
    """Encrypt file data using AES encryption"""
    fernet = Fernet(key)
    return fernet.encrypt(file_data)

def decrypt_file(encrypted_data, key):
    """Decrypt file data using AES encryption"""
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)

def get_user_encryption_key(user_id):
    """Get or generate encryption key for user"""
    # In a real application, you'd store this securely
    # For demo purposes, we'll derive it from user ID
    key_material = f"user_{user_id}_encryption_key"
    key_hash = hashlib.sha256(key_material.encode()).digest()
    return base64.urlsafe_b64encode(key_hash)

# Digital signature functions
def sign_file_content(file_data, private_key):
    """Sign file content with ECDSA"""
    # Create hash of file content
    file_hash = hashlib.sha256(file_data).digest()
    
    # Sign the hash
    signature = private_key.sign(file_hash, ec.ECDSA(hashes.SHA256()))
    
    # Encode signature for storage
    signature_b64 = base64.b64encode(signature).decode()
    
    return signature_b64, file_hash

def verify_file_signature(file_data, signature_b64, public_key):
    """Verify file signature with ECDSA"""
    try:
        # Decode signature
        signature = base64.b64decode(signature_b64)
        
        # Create hash of file content
        file_hash = hashlib.sha256(file_data).digest()
        
        # Verify signature
        public_key.verify(signature, file_hash, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def create_signature_metadata(file_data, signature, user_email):
    """Create metadata for signature verification"""
    metadata = {
        'signer': user_email,
        'timestamp': datetime.utcnow().isoformat(),
        'algorithm': 'ECDSA-SHA256',
        'file_hash': hashlib.sha256(file_data).hexdigest()
    }
    return json.dumps(metadata)

# Access Control Functions
def has_file_access(user_id, file_id, required_permission='read'):
    """Check if user has required permission for file"""
    file_record = File.query.get(file_id)
    if not file_record:
        return False
    
    # Owner has all permissions
    if file_record.user_id == user_id:
        return True
    
    # Check if file is public
    if file_record.is_public and required_permission == 'read':
        return True
    
    # Check specific access permissions
    access = FileAccess.query.filter_by(
        file_id=file_id, 
        user_id=user_id, 
        is_active=True
    ).first()
    
    if not access:
        return False
    
    # Check expiration
    if access.expires_at and access.expires_at < datetime.utcnow():
        return False
    
    # Check permission level
    permission_levels = {'read': 1, 'write': 2, 'admin': 3}
    user_level = permission_levels.get(access.permission, 0)
    required_level = permission_levels.get(required_permission, 1)
    
    return user_level >= required_level

def grant_file_access(file_id, user_id, permission, granted_by, expires_at=None):
    """Grant access to a file for a user"""
    # Check if access already exists
    existing = FileAccess.query.filter_by(
        file_id=file_id, 
        user_id=user_id
    ).first()
    
    if existing:
        existing.permission = permission
        existing.granted_by = granted_by
        existing.granted_at = datetime.utcnow()
        existing.expires_at = expires_at
        existing.is_active = True
    else:
        access = FileAccess(
            file_id=file_id,
            user_id=user_id,
            permission=permission,
            granted_by=granted_by,
            expires_at=expires_at
        )
        db.session.add(access)
    
    db.session.commit()

def revoke_file_access(file_id, user_id):
    """Revoke access to a file for a user"""
    access = FileAccess.query.filter_by(
        file_id=file_id, 
        user_id=user_id
    ).first()
    
    if access:
        access.is_active = False
        db.session.commit()

def log_file_access(file_id, user_id, action, ip_address=None, user_agent=None, success=True):
    """Log file access for audit trail"""
    log_entry = AccessLog(
        file_id=file_id,
        user_id=user_id,
        action=action,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success
    )
    db.session.add(log_entry)
    db.session.commit()

def log_blockchain_transaction(file_id, user_id, transaction_hash, transaction_type, blockchain_file_id=None, block_number=None, gas_used=None, gas_price=None):
    """Log blockchain transaction for audit trail"""
    etherscan_url = f"https://sepolia.etherscan.io/tx/{transaction_hash}"
    
    tx_log = BlockchainTransaction(
        file_id=file_id,
        user_id=user_id,
        transaction_hash=transaction_hash,
        transaction_type=transaction_type,
        blockchain_file_id=blockchain_file_id,
        block_number=block_number,
        gas_used=gas_used,
        gas_price=gas_price,
        etherscan_url=etherscan_url
    )
    db.session.add(tx_log)
    db.session.commit()

def generate_invitation_token():
    """Generate secure invitation token"""
    return base64.urlsafe_b64encode(os.urandom(32)).decode()

def create_file_invitation(file_id, invited_email, permission, invited_by, expires_at=None):
    """Create file sharing invitation"""
    token = generate_invitation_token()
    
    invitation = FileInvitation(
        file_id=file_id,
        invited_email=invited_email,
        permission=permission,
        invited_by=invited_by,
        invitation_token=token,
        expires_at=expires_at
    )
    
    db.session.add(invitation)
    db.session.commit()
    
    return token

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        files = File.query.filter_by(user_id=current_user.id).order_by(File.upload_date.desc()).limit(5).all()
        return render_template('dashboard.html', user=current_user, files=files)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(email=email)
        user.set_password(password)
        
        # Generate ECDSA key pair for digital signatures
        try:
            user.generate_key_pair()
            db.session.add(user)
            db.session.commit()
            
            # Check for pending invitations for this email
            pending_invitations = FileInvitation.query.filter_by(
                invited_email=email,
                is_accepted=False
            ).all()
            
            for invitation in pending_invitations:
                # Check if invitation is still valid
                if not invitation.expires_at or invitation.expires_at > datetime.utcnow():
                    # Grant access
                    grant_file_access(invitation.file_id, user.id, 
                                     invitation.permission, invitation.invited_by, invitation.expires_at)
                    
                    # Mark invitation as accepted
                    invitation.is_accepted = True
                    invitation.accepted_at = datetime.utcnow()
            
            if pending_invitations:
                db.session.commit()
                flash(f'Registration successful! ECDSA keys generated. {len(pending_invitations)} file invitations automatically accepted.', 'success')
            else:
                flash('Registration successful! ECDSA keys generated for digital signatures. Please login.', 'success')
                
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'error')
            return render_template('register.html')
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('index'))
    
    if file:
        try:
            # Secure the filename
            filename = secure_filename(file.filename)
            
            # Generate unique encrypted filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            encrypted_filename = f"{current_user.id}_{timestamp}_{filename}.enc"
            
            # Get user's encryption key
            encryption_key = get_user_encryption_key(current_user.id)
            
            # Read file data
            file_data = file.read()
            
            # Create digital signature
            password = request.form.get('password', '')
            if not password:
                flash('Password is required for digital signing.', 'error')
                return redirect(url_for('index'))
            
            private_key = current_user.get_private_key(password)
            if not private_key:
                flash('Unable to access private key for signing. Please check your password.', 'error')
                return redirect(url_for('index'))
            
            signature, file_hash = sign_file_content(file_data, private_key)
            
            # Encrypt the file
            encrypted_data = encrypt_file(file_data, encryption_key)
            
            # Save encrypted file
            encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Store file info in database
            file_record = File(
                filename=filename,
                encrypted_filename=encrypted_filename,
                file_size=len(file_data),
                user_id=current_user.id,
                encryption_key_hash=hashlib.sha256(encryption_key).hexdigest(),
                digital_signature=signature,
                signature_hash=base64.b64encode(file_hash).decode()
            )
            
            db.session.add(file_record)
            db.session.commit()
            
            # Register file upload on blockchain
            blockchain_file_id = None
            blockchain_tx_hash = None
            if blockchain_service:
                try:
                    file_content_hash = calculate_file_hash(file_data)
                    blockchain_result = blockchain_service.register_file_upload(
                        filename, 
                        file_content_hash, 
                        description=f"Encrypted file uploaded by {current_user.email}",
                        uploader_id=current_user.email
                    )
                    
                    # Handle new return format
                    if isinstance(blockchain_result, dict):
                        blockchain_file_id = blockchain_result['file_id']
                        blockchain_tx_hash = blockchain_result['tx_hash']
                    else:
                        # Legacy format
                        blockchain_file_id = blockchain_result
                        blockchain_tx_hash = "pending"
                    
                    # Update file record with blockchain info
                    file_record.blockchain_file_id = blockchain_file_id
                    file_record.blockchain_tx_hash = blockchain_tx_hash
                    db.session.commit()
                    
                    # Log blockchain transaction
                    log_blockchain_transaction(
                        file_id=file_record.id,
                        user_id=current_user.id,
                        transaction_hash=blockchain_tx_hash,
                        transaction_type='upload',
                        blockchain_file_id=blockchain_file_id
                    )
                    
                    etherscan_url = f"https://sepolia.etherscan.io/tx/{blockchain_tx_hash}"
                    flash(f'File "{filename}" uploaded, encrypted, digitally signed, and registered on blockchain! <a href="{etherscan_url}" target="_blank">View Transaction</a>', 'success')
                except Exception as e:
                    print(f"❌ Blockchain registration failed: {e}")
                    flash(f'File "{filename}" uploaded and encrypted, but blockchain registration failed: {str(e)}', 'warning')
            else:
                flash(f'File "{filename}" uploaded, encrypted, and digitally signed successfully!', 'success')
            
        except Exception as e:
            flash(f'Upload failed: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = File.query.get(file_id)
    
    if not file_record:
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    # Check access permissions
    if not has_file_access(current_user.id, file_id, 'read'):
        log_file_access(file_id, current_user.id, 'download_denied', 
                       request.remote_addr, request.headers.get('User-Agent'), False)
        flash('Access denied. You do not have permission to download this file.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Log successful access
        log_file_access(file_id, current_user.id, 'download', 
                       request.remote_addr, request.headers.get('User-Agent'), True)
        
        # Get encryption key - use file owner's key for shared files
        if file_record.user_id == current_user.id:
            # User owns the file, use their encryption key
            encryption_key = get_user_encryption_key(current_user.id)
        else:
            # Shared file, use file owner's encryption key
            encryption_key = get_user_encryption_key(file_record.user_id)
        
        # Read encrypted file
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.encrypted_filename)
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt the file
        decrypted_data = decrypt_file(encrypted_data, encryption_key)
        
        # Verify digital signature if present
        signature_verified = False
        if file_record.digital_signature:
            # Get public key - use file owner's key for signature verification
            if file_record.user_id == current_user.id:
                # User owns the file, use their public key
                public_key = current_user.get_public_key()
            else:
                # Shared file, get file owner's public key
                file_owner = User.query.get(file_record.user_id)
                if file_owner:
                    public_key = file_owner.get_public_key()
                else:
                    public_key = None
            
            if public_key:
                signature_verified = verify_file_signature(decrypted_data, file_record.digital_signature, public_key)
                if signature_verified:
                    flash('✅ Digital signature verified - file is authentic and untampered', 'success')
                else:
                    flash('⚠️ Digital signature verification failed - file may have been tampered with', 'error')
        
        # Create temporary file for download
        temp_path = f"/tmp/{file_record.filename}"
        with open(temp_path, 'wb') as f:
            f.write(decrypted_data)
        
        return send_file(temp_path, as_attachment=True, download_name=file_record.filename)
    
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    file_record = File.query.filter_by(id=file_id, user_id=current_user.id).first()
    
    if not file_record:
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    try:
        # Delete encrypted file from filesystem
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record.encrypted_filename)
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        
        # Delete record from database
        db.session.delete(file_record)
        db.session.commit()
        
        flash(f'File "{file_record.filename}" deleted successfully!', 'success')
    
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'error')
    
    return redirect(url_for('index'))

@app.route('/files')
@login_required
def list_files():
    files = File.query.filter_by(user_id=current_user.id).order_by(File.upload_date.desc()).all()
    return render_template('files.html', files=files)

@app.route('/public-key')
@login_required
def get_public_key():
    """Get user's public key for signature verification"""
    public_key = current_user.get_public_key()
    if not public_key:
        flash('No public key found', 'error')
        return redirect(url_for('index'))
    
    # Return public key in PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return render_template('public_key.html', public_key=public_pem.decode(), user_email=current_user.email)

# File Sharing Routes
@app.route('/share/<int:file_id>', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    """Share file with other users"""
    file_record = File.query.get(file_id)
    
    if not file_record:
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    # Check if user owns the file or has admin access
    if not has_file_access(current_user.id, file_id, 'admin'):
        flash('Access denied. You do not have permission to share this file.', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        invited_email = request.form['email']
        permission = request.form['permission']
        expires_days = request.form.get('expires_days', '')
        
        # Validate permission
        if permission not in ['read', 'write', 'admin']:
            flash('Invalid permission level', 'error')
            return redirect(url_for('share_file', file_id=file_id))
        
        # Check if user exists
        invited_user = User.query.filter_by(email=invited_email).first()
        
        if invited_user:
            # User exists, grant direct access
            expires_at = None
            if expires_days:
                expires_at = datetime.utcnow() + timedelta(days=int(expires_days))
            
            grant_file_access(file_id, invited_user.id, permission, current_user.id, expires_at)
            
            # Remove any pending invitations for this user
            pending_invitation = FileInvitation.query.filter_by(
                file_id=file_id,
                invited_email=invited_email,
                is_accepted=False
            ).first()
            if pending_invitation:
                db.session.delete(pending_invitation)
                db.session.commit()
            
            # Log access grant on blockchain
            if blockchain_service and file_record.blockchain_file_id:
                try:
                    tx_hash = blockchain_service.approve_access_request(
                        file_record.blockchain_file_id, 
                        invited_user.email,  # Using email as identifier
                        True
                    )
                    
                    # Log blockchain transaction
                    log_blockchain_transaction(
                        file_id=file_id,
                        user_id=current_user.id,
                        transaction_hash=tx_hash,
                        transaction_type='access_grant',
                        blockchain_file_id=file_record.blockchain_file_id
                    )
                    
                    etherscan_url = f"https://sepolia.etherscan.io/tx/{tx_hash}"
                    flash(f'Access granted to {invited_email} with {permission} permission and logged on blockchain! <a href="{etherscan_url}" target="_blank">View Transaction</a>', 'success')
                except Exception as e:
                    print(f"❌ Blockchain access logging failed: {e}")
                    flash(f'Access granted to {invited_email} with {permission} permission (blockchain logging failed)', 'warning')
            else:
                flash(f'Access granted to {invited_email} with {permission} permission', 'success')
        else:
            # User doesn't exist, create invitation
            expires_at = None
            if expires_days:
                expires_at = datetime.utcnow() + timedelta(days=int(expires_days))
            
            token = create_file_invitation(file_id, invited_email, permission, current_user.id, expires_at)
            flash(f'Invitation sent to {invited_email}. They will receive access when they register.', 'success')
        
        return redirect(url_for('list_files'))
    
    # Get current access list
    current_access = FileAccess.query.filter_by(file_id=file_id, is_active=True).all()
    invitations = FileInvitation.query.filter_by(file_id=file_id, is_accepted=False).all()
    
    return render_template('share_file.html', file=file_record, 
                         current_access=current_access, invitations=invitations)

@app.route('/revoke-access/<int:file_id>/<int:user_id>')
@login_required
def revoke_access(file_id, user_id):
    """Revoke access to a file"""
    file_record = File.query.get(file_id)
    
    if not file_record:
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    # Check if user owns the file or has admin access
    if not has_file_access(current_user.id, file_id, 'admin'):
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    revoke_file_access(file_id, user_id)
    
    # Log access revocation on blockchain
    if blockchain_service and file_record.blockchain_file_id:
        try:
            user_to_revoke = User.query.get(user_id)
            if user_to_revoke:
                tx_hash = blockchain_service.revoke_access(file_record.blockchain_file_id, user_to_revoke.email)
                
                # Log blockchain transaction
                log_blockchain_transaction(
                    file_id=file_id,
                    user_id=current_user.id,
                    transaction_hash=tx_hash,
                    transaction_type='access_revoke',
                    blockchain_file_id=file_record.blockchain_file_id
                )
                
                etherscan_url = f"https://sepolia.etherscan.io/tx/{tx_hash}"
                flash(f'Access revoked successfully and logged on blockchain! <a href="{etherscan_url}" target="_blank">View Transaction</a>', 'success')
            else:
                flash('Access revoked successfully (blockchain logging failed - user not found)', 'warning')
        except Exception as e:
            print(f"❌ Blockchain revocation logging failed: {e}")
            flash('Access revoked successfully (blockchain logging failed)', 'warning')
    else:
        flash('Access revoked successfully', 'success')
    
    return redirect(url_for('share_file', file_id=file_id))

@app.route('/accept-invitation/<token>')
@login_required
def accept_invitation(token):
    """Accept file sharing invitation"""
    invitation = FileInvitation.query.filter_by(
        invitation_token=token, 
        is_accepted=False
    ).first()
    
    if not invitation:
        flash('Invalid or expired invitation', 'error')
        return redirect(url_for('index'))
    
    # Check if invitation is for current user
    if invitation.invited_email != current_user.email:
        flash('This invitation is not for you', 'error')
        return redirect(url_for('index'))
    
    # Check expiration
    if invitation.expires_at and invitation.expires_at < datetime.utcnow():
        flash('Invitation has expired', 'error')
        return redirect(url_for('index'))
    
    # Grant access
    grant_file_access(invitation.file_id, current_user.id, 
                     invitation.permission, invitation.invited_by, invitation.expires_at)
    
    # Mark invitation as accepted
    invitation.is_accepted = True
    invitation.accepted_at = datetime.utcnow()
    db.session.commit()
    
    flash('Invitation accepted! You now have access to the shared file.', 'success')
    return redirect(url_for('list_files'))

@app.route('/shared-files')
@login_required
def shared_files():
    """View files shared with current user"""
    # Get files shared with current user
    shared_access = FileAccess.query.filter_by(
        user_id=current_user.id, 
        is_active=True
    ).all()
    
    shared_files = []
    for access in shared_access:
        file_record = File.query.get(access.file_id)
        if file_record:
            shared_files.append({
                'file': file_record,
                'permission': access.permission,
                'granted_at': access.granted_at,
                'expires_at': access.expires_at
            })
    
    return render_template('shared_files.html', shared_files=shared_files)

@app.route('/access-logs/<int:file_id>')
@login_required
def file_access_logs(file_id):
    """View access logs for a file"""
    file_record = File.query.get(file_id)
    
    if not file_record:
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    # Check if user owns the file or has admin access
    if not has_file_access(current_user.id, file_id, 'admin'):
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    logs = AccessLog.query.filter_by(file_id=file_id).order_by(AccessLog.timestamp.desc()).all()
    return render_template('access_logs.html', file=file_record, logs=logs)

@app.route('/blockchain-status')
@login_required
def blockchain_status():
    """View blockchain status and contract information"""
    status = {
        'available': BLOCKCHAIN_AVAILABLE,
        'connected': False,
        'contract_deployed': False,
        'account_balance': 0,
        'contract_address': None,
        'chain_id': None
    }
    
    if blockchain_service:
        try:
            status['connected'] = True
            status['account_balance'] = float(blockchain_service.get_balance())
            status['chain_id'] = blockchain_service.chain_id
            
            if blockchain_service.contract_address:
                status['contract_deployed'] = True
                status['contract_address'] = blockchain_service.contract_address
                
        except Exception as e:
            status['error'] = str(e)
    
    return render_template('blockchain_status.html', status=status)

@app.route('/transaction-history/<int:file_id>')
@login_required
def transaction_history(file_id):
    """View blockchain transaction history for a file"""
    file_record = File.query.get(file_id)
    
    if not file_record:
        flash('File not found', 'error')
        return redirect(url_for('index'))
    
    # Check if user has access to this file
    if not has_file_access(current_user.id, file_id, 'read'):
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    # Get blockchain transactions for this file
    transactions = BlockchainTransaction.query.filter_by(file_id=file_id).order_by(BlockchainTransaction.timestamp.desc()).all()
    
    return render_template('transaction_history.html', file=file_record, transactions=transactions)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)
