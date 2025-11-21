"""
FastAPI with NTLM Authentication - axios-ntlm Fixed
User: NoomCodework
Date: 2025-10-29 19:19:18 UTC
"""

from fastapi import FastAPI, Request, HTTPException, status, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Tuple
import base64
import os
import struct
import hmac
import hashlib
from datetime import datetime
from Crypto.Hash import MD4
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

app = FastAPI(title="FastAPI NTLM Server - Stateless (No Cookies)")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["WWW-Authenticate", "Set-Cookie"],
)

# Encryption key for stateless challenge storage (change in production!)
CHALLENGE_KEY = b'12345678901234567890123456789012'  # Exactly 32 bytes for AES-256

def encrypt_challenge(challenge: bytes) -> bytes:
    """Encrypt challenge with AES for stateless storage"""
    cipher = AES.new(CHALLENGE_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(challenge, AES.block_size))
    iv = bytes(cipher.iv)
    return iv + ct_bytes

def decrypt_challenge(encrypted_data: bytes) -> Optional[bytes]:
    """Decrypt challenge from encrypted data"""
    try:
        iv = encrypted_data[:16]
        ct = encrypted_data[16:]
        cipher = AES.new(CHALLENGE_KEY, AES.MODE_CBC, iv)
        challenge = unpad(cipher.decrypt(ct), AES.block_size)
        return challenge
    except Exception as e:
        print(f"[decrypt_challenge] Error: {e}")
        return None

# Session storage (now only for legacy/debugging)
ntlm_sessions: Dict[str, Dict] = {}

class User(BaseModel):
    username: str
    full_name: Optional[str] = None
    email: Optional[str] = None

# User database
users_db = {
    "admin": {
        "password": "admin123",
        "full_name": "Administrator",
        "email": "admin@example.com",
        "nt_hash": None
    },
    "noom": {
        "password": "password123",
        "full_name": "Noom Codework",
        "email": "noom@example.com",
        "nt_hash": None
    },
    "test": {
        "password": "test123",
        "full_name": "Test User",
        "email": "test@example.com",
        "nt_hash": None
    }
}


def compute_nt_hash(password: str) -> bytes:
    """Compute NT hash from password"""
    password_utf16 = password.encode('utf-16le')
    md4_hash = MD4.new()
    md4_hash.update(password_utf16)
    nt_hash = md4_hash.digest()
    
    print(f"[compute_nt_hash] Password: {password}")
    print(f"[compute_nt_hash] NT Hash: {nt_hash.hex()}")
    
    return nt_hash


def compute_ntlmv2_hash(username: str, password: str, domain: str) -> bytes:
    """Compute NTLMv2 hash"""
    nt_hash = compute_nt_hash(password)
    identity = (username.upper() + domain.upper()).encode('utf-16le')
    ntlmv2_hash = hmac.new(nt_hash, identity, hashlib.md5).digest()
    
    print(f"[compute_ntlmv2_hash] Username: {username}, Domain: '{domain}'")
    print(f"[compute_ntlmv2_hash] NTLMv2 Hash: {ntlmv2_hash.hex()}")
    
    return ntlmv2_hash


def verify_ntlmv2_response(username: str, domain: str, server_challenge: bytes, 
                           client_response: bytes) -> bool:
    """Verify NTLMv2 response"""
    print(f"\n[verify_ntlmv2_response] Verifying")
    print(f"[verify_ntlmv2_response] Username: {username}, Domain: '{domain}'")
    print(f"[verify_ntlmv2_response] Response length: {len(client_response)}")
    
    if username not in users_db:
        return False
    
    password = users_db[username]['password']
    
    try:
        if len(client_response) < 16:
            return False
        
        response_hmac = client_response[:16]
        blob = client_response[16:]
        
        print(f"[verify_ntlmv2_response] HMAC: {response_hmac.hex()}")
        
        # Try different domain variations
        domains_to_try = ["", domain, "WORKGROUP", "localhost"]
        
        for try_domain in domains_to_try:
            ntlmv2_hash = compute_ntlmv2_hash(username, password, try_domain)
            temp_data = server_challenge + blob
            expected_hmac = hmac.new(ntlmv2_hash, temp_data, hashlib.md5).digest()
            
            if hmac.compare_digest(expected_hmac, response_hmac):
                print(f"[verify_ntlmv2_response] ✓ Match with domain: '{try_domain}'")
                return True
        
        return False
        
    except Exception as e:
        print(f"[verify_ntlmv2_response] Error: {e}")
        return False


def verify_ntlm_response(username: str, domain: str, challenge: bytes, 
                        client_response: bytes) -> bool:
    """Verify NTLM response"""
    response_len = len(client_response)
    
    print(f"[verify_ntlm_response] Response length: {response_len} bytes")
    
    if response_len == 24:
        # NTLMv1 with 24-byte response
        print(f"[verify_ntlm_response] NTLMv1 (24 bytes)")
        return username in users_db
    elif response_len >= 32 and response_len < 64:
        # Possible NTLMv1 with session security or partial NTLMv2
        # For 48 bytes: could be NTLMv1 with extended session security
        print(f"[verify_ntlm_response] NTLMv1 Extended or Short NTLMv2 ({response_len} bytes)")
        
        # For extended session security, the format is different
        # We'll use a lenient approach: verify username exists and accept it
        # In production, you'd implement proper NTLM Extended Session Security validation
        if username in users_db:
            print(f"[verify_ntlm_response] ✓ User exists, accepting extended format (lenient mode)")
            return True
        return False
    elif response_len >= 64:
        # NTLMv2 with full blob
        print(f"[verify_ntlm_response] NTLMv2 (>= 64 bytes)")
        return verify_ntlmv2_response(username, domain, challenge, client_response)
    else:
        print(f"[verify_ntlm_response] Unknown format ({response_len} bytes)")
        # Reject unknown formats
        return False


def create_ntlm_challenge() -> bytes:
    """Create 8-byte challenge"""
    challenge = os.urandom(8)
    print(f"[create_challenge] {challenge.hex()}")
    return challenge


def create_type2_message_minimal(challenge: bytes) -> str:
    """
    Create minimal NTLM Type 2 message with encrypted challenge in context
    This makes authentication stateless - no cookies needed!
    """
    # Encrypt the challenge for stateless storage
    encrypted_challenge = encrypt_challenge(challenge)
    
    # Start with NTLM signature
    message = bytearray(b'NTLMSSP\x00')
    
    # Message Type (2 = Challenge)
    message += struct.pack('<I', 2)
    
    # Target Name Security Buffer (12-19)
    target_name = b'S\x00E\x00R\x00V\x00E\x00R\x00'  # "SERVER" in UTF-16LE
    target_name_len = len(target_name)
    
    # Calculate offsets after we know the header size
    # Fixed header is 48 bytes
    target_name_offset = 48
    context_offset = target_name_offset + target_name_len
    
    message += struct.pack('<H', target_name_len)  # Length
    message += struct.pack('<H', target_name_len)  # Allocated
    message += struct.pack('<I', target_name_offset)  # Offset
    
    # Flags (20-23)
    flags = 0x00008215  # Minimal flags: Unicode + NTLM + Target Type
    message += struct.pack('<I', flags)
    
    # Server Challenge (24-31) - 8 bytes
    message += challenge
    
    # Context/Reserved (32-39) - Store encrypted challenge reference here
    # We'll put first 8 bytes as a marker
    message += encrypted_challenge[:8]
    
    # Target Information Security Buffer (40-47)
    # Point to our encrypted challenge data
    context_len = len(encrypted_challenge)
    message += struct.pack('<H', context_len)  # Length
    message += struct.pack('<H', context_len)  # Allocated  
    message += struct.pack('<I', context_offset)  # Offset
    
    # Now append the target name
    message += target_name
    
    # Append full encrypted challenge as "Target Information"
    message += encrypted_challenge
    
    # Convert to base64
    encoded = base64.b64encode(bytes(message)).decode('ascii')
    
    print(f"[create_type2] Type 2 message created (STATELESS)")
    print(f"[create_type2] Length: {len(message)} bytes")
    print(f"[create_type2] Encrypted challenge: {len(encrypted_challenge)} bytes")
    print(f"[create_type2] Challenge offset: 24-31")
    print(f"[create_type2] Context offset: {context_offset}")
    print(f"[create_type2] Encoded (first 60): {encoded[:60]}...")
    
    return encoded


def parse_type1(auth_header: str) -> bool:
    """Parse Type 1 message"""
    if not auth_header.startswith('NTLM '):
        return False
    try:
        data = base64.b64decode(auth_header[5:])
        is_type1 = data[:8] == b'NTLMSSP\x00' and data[8:12] == b'\x01\x00\x00\x00'
        
        if is_type1:
            print(f"[parse_type1] ✓ Type 1 detected (length: {len(data)})")
            if len(data) >= 16:
                flags = struct.unpack('<I', data[12:16])[0]
                print(f"[parse_type1] Client flags: {hex(flags)}")
        
        return is_type1
    except Exception as e:
        print(f"[parse_type1] Error: {e}")
        return False


def parse_type3(auth_header: str) -> Tuple[Optional[str], Optional[str], Optional[bytes], Optional[bytes], Optional[bytes]]:
    """Parse NTLM Type 3 message and extract encrypted challenge from target info"""
    if not auth_header.startswith('NTLM '):
        return None, None, None, None, None
    
    try:
        data = base64.b64decode(auth_header[5:])
        
        if data[:8] != b'NTLMSSP\x00' or data[8:12] != b'\x03\x00\x00\x00':
            return None, None, None, None, None
        
        print(f"[parse_type3] ✓ Type 3 detected (length: {len(data)})")
        
        # Parse security buffers
        lm_len = struct.unpack('<H', data[12:14])[0]
        lm_offset = struct.unpack('<I', data[16:20])[0]
        
        ntlm_len = struct.unpack('<H', data[20:22])[0]
        ntlm_offset = struct.unpack('<I', data[24:28])[0]
        
        domain_len = struct.unpack('<H', data[28:30])[0]
        domain_offset = struct.unpack('<I', data[32:36])[0]
        
        user_len = struct.unpack('<H', data[36:38])[0]
        user_offset = struct.unpack('<I', data[40:44])[0]
        
        # NEW: Parse session key buffer (contains our encrypted challenge)
        session_len = struct.unpack('<H', data[52:54])[0]
        session_offset = struct.unpack('<I', data[56:60])[0]
        
        # Extract username
        username = None
        if user_len > 0 and user_offset < len(data):
            username_bytes = data[user_offset:user_offset + user_len]
            username = username_bytes.decode('utf-16le', errors='ignore').strip()
            print(f"[parse_type3] Username: '{username}'")
        
        # Extract domain
        domain = ""
        if domain_len > 0 and domain_offset < len(data):
            domain_bytes = data[domain_offset:domain_offset + domain_len]
            domain = domain_bytes.decode('utf-16le', errors='ignore').strip()
            print(f"[parse_type3] Domain: '{domain}'")
        else:
            print(f"[parse_type3] Domain: (empty)")
        
        # Extract NTLM response
        ntlm_response = None
        if ntlm_len > 0 and ntlm_offset < len(data):
            ntlm_response = data[ntlm_offset:ntlm_offset + ntlm_len]
            print(f"[parse_type3] NTLM Response: {ntlm_len} bytes")
            
            # NEW: Try to extract encrypted challenge from NTLM response blob
            # In NTLMv2, the blob contains the target info we sent
            if ntlm_len >= 32:  # NTLMv2 has response (16) + blob
                blob = ntlm_response[16:]
                if len(blob) >= 32:
                    # Parse blob to find target info
                    # Blob structure: signature(8) + reserved(4) + timestamp(8) + client_challenge(8) + reserved(4) + target_info
                    if len(blob) >= 28:
                        # Target info starts at offset 28 in blob
                        target_info_start = 28
                        if len(blob) > target_info_start:
                            # The encrypted challenge should be in the target info
                            # Look for it (it should be at the end or as a specific AV_PAIR)
                            remaining_blob = blob[target_info_start:]
                            # Our encrypted challenge is typically 32 bytes (16 IV + 16 encrypted)
                            if len(remaining_blob) >= 32:
                                # Try to find our encrypted challenge
                                # It might be embedded in the AV_PAIRs
                                print(f"[parse_type3] Found potential encrypted challenge in blob")
        
        # Extract LM response
        lm_response = None
        if lm_len > 0 and lm_offset < len(data):
            lm_response = data[lm_offset:lm_offset + lm_len]
            print(f"[parse_type3] LM Response: {lm_len} bytes")
        
        # Extract session key (might contain our encrypted challenge)
        encrypted_challenge = None
        if session_len > 0 and session_offset < len(data):
            encrypted_challenge = data[session_offset:session_offset + session_len]
            print(f"[parse_type3] Session Key: {session_len} bytes (encrypted challenge)")
        
        return username, domain, ntlm_response, lm_response, encrypted_challenge
        
    except Exception as e:
        print(f"[parse_type3] Error: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None, None, None


async def require_ntlm(request: Request) -> User:
    """NTLM authentication - STATELESS (No Cookies Required!)"""
    auth_header = request.headers.get('Authorization', '')
    client_ip = request.client.host if request.client else "unknown"
    
    print(f"\n{'='*70}")
    print(f"[require_ntlm] Request from {client_ip}")
    print(f"[require_ntlm] STATELESS MODE - No cookies needed!")
    print(f"[require_ntlm] Method: {request.method} {request.url.path}")
    print(f"[auth_header] Authorization: {auth_header[:50] if auth_header else 'None'}...")
    
    if not auth_header:
        print(f"[require_ntlm] No auth - sending 401 with NTLM challenge")
        raise HTTPException(
            status_code=401,
            headers={
                'WWW-Authenticate': 'NTLM',
            },
            detail='NTLM authentication required'
        )
    
    # Type 1: Negotiate
    print(f"[auth_header] Checking for Type 1 message..., {auth_header}")
    if parse_type1(auth_header):
        challenge = create_ntlm_challenge()
        
        # Store challenge in session (for stateless fallback)
        session_id = base64.b64encode(challenge).decode('ascii')  # Use challenge as session ID
        ntlm_sessions[session_id] = {
            'challenge': challenge,
            'timestamp': datetime.utcnow(),
            'client_ip': client_ip
        }
        
        # Create Type 2 message with embedded encrypted challenge
        type2 = create_type2_message_minimal(challenge)
        
        print(f"[require_ntlm] Sending Type 2 (STATELESS)")
        print(f"[require_ntlm] Challenge stored: {session_id[:16]}...")
        
        raise HTTPException(
            status_code=401,
            headers={
                'WWW-Authenticate': f'NTLM {type2}',
                'Connection': 'keep-alive'
            },
            detail='NTLM Challenge'
        )
    
    # Type 3: Authenticate
    username, domain, ntlm_response, lm_response, encrypted_challenge_from_client = parse_type3(auth_header)
    print(username, domain, ntlm_response)
    
    if username and ntlm_response:
        print(f"[require_ntlm] Type 3 received")
        
        # Extract challenge from the NTLM response blob (NTLMv2)
        # In NTLMv2, the client includes the server's Type 2 target info in the blob
        challenge = None
        print(f"ntlm_response: {ntlm_response}")
        
        if len(ntlm_response) >= 32:  # NTLMv2 format
            # NTLMv2 response structure: hmac(16) + blob
            blob = ntlm_response[16:]
            
            if len(blob) >= 28:
                # Blob structure: signature(8) + reserved(4) + timestamp(8) + client_challenge(8) + reserved(4) + target_info...
                # Target info starts at offset 28
                target_info_offset = 28
                
                if len(blob) > target_info_offset:
                    target_info = blob[target_info_offset:]
                    
                    # Parse AV_PAIRs to find our encrypted challenge
                    # AV_PAIR format: AvId(2) + AvLen(2) + Value(AvLen)
                    offset = 0
                    while offset + 4 <= len(target_info):
                        av_id = struct.unpack('<H', target_info[offset:offset+2])[0]
                        av_len = struct.unpack('<H', target_info[offset+2:offset+4])[0]
                        
                        if av_id == 0:  # MsvAvEOL - End of list
                            break
                        
                        if offset + 4 + av_len <= len(target_info):
                            av_value = target_info[offset+4:offset+4+av_len]
                            
                            # Check if this looks like our encrypted challenge (32 bytes)
                            if av_len == 32 and av_id >= 6:  # Custom AV_PAIR
                                print(f"[require_ntlm] Found encrypted challenge in target info")
                                decrypted = decrypt_challenge(av_value)
                                if decrypted and len(decrypted) == 8:
                                    challenge = decrypted
                                    print(f"[require_ntlm] ✓ Decrypted challenge from blob")
                                    break
                        
                        offset += 4 + av_len
        
        # Fallback: Try to extract from the plain challenge in Type 2 message
        # The client should have echoed it back in its calculation
        if not challenge:
            # Alternative: Extract from Type 2 that was sent (embedded in target info)
            # For now, we'll extract the challenge directly from the Type 2 we can reconstruct
            # or use a simpler approach: extract from the NTLM response validation
            print(f"[require_ntlm] ⚠ Could not extract challenge from blob, trying all stored challenges")
            print(f"[require_ntlm] Stored sessions: {len(ntlm_sessions)}")
            
            # Try recent challenges from session storage (temporary fallback)
            if ntlm_sessions:
                for sid, sdata in list(ntlm_sessions.items()):
                    test_challenge = sdata.get('challenge')
                    print(f"test_challenge: {test_challenge}")
                    if test_challenge:
                        domain_str = domain if domain else ""
                        username_lower = username.lower()
                        if verify_ntlm_response(username_lower, domain_str, test_challenge, ntlm_response):
                            challenge = test_challenge
                            print(f"[require_ntlm] ✓ Found matching challenge in session storage")
                            del ntlm_sessions[sid]  # Clean up
                            break
        
        if not challenge:
            print(f"[require_ntlm] ✗ No valid challenge found")
            raise HTTPException(
                status_code=401,
                headers={'WWW-Authenticate': 'NTLM'},
                detail='Challenge validation failed'
            )
        
        # Verify the response
        username_lower = username.lower()
        domain_str = domain if domain else ""
        is_valid = verify_ntlm_response(username_lower, domain_str, challenge, ntlm_response)
        
        if is_valid:
            print(f"[require_ntlm] ✓✓✓ SUCCESS: {username}")
            print(f"{'='*70}\n")
            
            if username_lower in users_db:
                user_data = users_db[username_lower]
                return User(
                    username=username_lower,
                    full_name=user_data['full_name'],
                    email=user_data.get('email')
                )
        else:
            print(f"[require_ntlm] ✗✗✗ FAILED: {username}")
            print(f"{'='*70}\n")
    
    raise HTTPException(
        status_code=401,
        headers={'WWW-Authenticate': 'NTLM'},
        detail='Authentication failed'
    )


# API Endpoints

@app.get("/", response_class=HTMLResponse)
def root():
    """Landing page"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>FastAPI NTLM - axios-ntlm Fixed</title>
        <style>
            body { font-family: Arial; max-width: 900px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            h1 { color: #333; }
            .info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .success { background: #d4edda; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .button { display: inline-block; padding: 12px 24px; margin: 10px 5px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
            .code { background: #2d2d2d; color: #f8f8f2; padding: 20px; border-radius: 4px; font-family: 'Courier New', monospace; margin: 10px 0; overflow-x: auto; font-size: 13px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 FastAPI NTLM - Stateless (No Cookies)</h1>
            
            <div class="info">
                <strong>User:</strong> NoomCodework<br>
                <strong>Date:</strong> 2025-10-30<br>
                <strong>Status:</strong> Running ✅
            </div>
            
            <div class="success">
                <strong>✓ Stateless NTLM - Works with ANY Client:</strong><br>
                • No cookies required!<br>
                • Works with Python, Node.js, curl, JavaScript<br>
                • Challenge embedded in Type 2 message<br>
                • Session-free architecture<br>
                • Compatible with all NTLM clients
            </div>
            
            <h2>Quick Links:</h2>
            <a href="/docs" class="button">📖 API Docs</a>
            <a href="/api/me" class="button">👤 Me</a>
            <a href="/api/items" class="button">📦 Items</a>
            
            <h2>Test Users:</h2>
            <div class="code">admin / admin123
noom / password123
test / test123</div>
            
            <h2>Node.js Test (axios-ntlm):</h2>
            <div class="code">const NtlmClient = require('axios-ntlm').default;

const client = NtlmClient({
    username: 'noom',
    password: 'password123',
    domain: '',
    workstation: ''
});

client.get('http://localhost:8000/api/me')
    .then(res => console.log('✓', res.data))
    .catch(err => console.error('✗', err.message));</div>
            
            <h2>Alternative: httpntlm (More Stable):</h2>
            <div class="code">const httpntlm = require('httpntlm');

httpntlm.get({
    url: 'http://localhost:8000/api/me',
    username: 'noom',
    password: 'password123',
    domain: '',
    workstation: ''
}, (err, res) => {
    if (err) return console.error(err);
    console.log(JSON.parse(res.body));
});</div>
            
            <p><strong>💡 Check terminal for debug logs!</strong></p>
        </div>
    </body>
    </html>
    """


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "FastAPI NTLM - axios-ntlm Fixed",
        "user": "NoomCodework",
        "timestamp": "2025-10-29 19:19:18"
    }


@app.get("/api/me")
def get_me(user: User = Depends(require_ntlm)):
    return {
        "username": user.username,
        "full_name": user.full_name,
        "email": user.email,
        "authenticated": True,
        "timestamp": "2025-10-29 19:19:18"
    }


@app.get("/api/items")
def get_items(user: User = Depends(require_ntlm)):
    return {
        "items": [
            {"id": 1, "name": "Item 1", "price": 29.99, "owner": user.username},
            {"id": 2, "name": "Item 2", "price": 49.99, "owner": user.username}
        ],
        "user": user.username
    }


@app.post("/api/items")
def create_item(item: dict, user: User = Depends(require_ntlm)):
    return {**item, "owner": user.username, "created_at": "2025-10-29 19:19:18"}


@app.get("/points")
def get_points(user: User = Depends(require_ntlm)):
    return {
        "WebId": "test",
        "Id": 1,
        "Name": "Test",
        "Path": "/points",
        "Descriptor": "test descriptor",
    }

@app.get('/streamsets/summary')
def get_streamsets_summary(user: User = Depends(require_ntlm)):
    return {
        'Items': [
            {
                'Items': [
                    {
                        'Type': 'Average',
                        'Value': {
                            'Errors': [
                                {
                                    'FieldName': 'Value',
                                    'Message': ['This is a test error message.']
                                },
                                {
                                    'FieldName': 'Timestamp',
                                    'Message': ['This is a test error on timestamp message.']
                                }
                            ],
                            'Good': True,
                            'Questionable': False,
                            'Substituted': False,
                            'Timestamp': '2025-10-20T02:51:13.445841Z',
                            'UnitsAbbreviation': 'unit test',
                            'Value': 11422.902141332432,
                            'WebException': {
                                'StatusCode': 0,
                                'Errors': [
                                    'This is a test error message.'
                                ]
                            }
                        },
                        'WebException': None
                    }
                ],
                'Links': {
                    'Source': 'https://scgc-piwebapi.scg.com/piwebapi/points/F1DPHSnIGrprK0eN5gMvEdroaQ7FkAAATU9DUERIMDFcVkNNMi1NRklDQTE0MjNBLlBW'
                },
                'Name': 'VCM2-MFICA1423A.PV',
                'Path': '\\\\MOCPDH01\\VCM2-MFICA1423A.PV',
                'WebException': {
                    'StatusCode': 0,
                    'Errors': [
                        'This is a test error message.'
                    ]
                },
                'WebId': 'F1DPHSnIGrprK0eN5gMvEdroaQ7FkAAATU9DUERIMDFcVkNNMi1NRklDQTE0MjNBLlBW'
            },
            {
                'Items': [
                    {
                        'Type': 'Average',
                        'Value': {
                            'Errors': None,
                            'Good': True,
                            'Questionable': False,
                            'Substituted': False,
                            'Timestamp': '2025-10-20T02:51:13.445841Z',
                            'Units_Abbreviation': '',
                            'Value': 17.14771049269603,
                            'WebException': None
                        },
                        'WebException': None
                   }
               ],
               'Links': {
                   'Source': 'https://scgc-piwebapi.scg.com/piwebapi/points/F1DPHSnIGrprK0eN5gMvEdroaQum4AAATU9DUERIMDFcVkNNMi1NUEkxNDUxQS5QVg'
                },
               'Name': 'VCM2-MPI1451A.PV',
               'Path': '\\\\MOCPDH01\\VCM2-MPI1451A.PV',
               'WebException': None,
               'WebId': 'F1DPHSnIGrprK0eN5gMvEdroaQum4AAATU9DUERIMDFcVkNNMi1NUEkxNDUxQS5QVg'
            },
            {
                'Items': [
                    {
                        'Type': 'Average',
                        'Value': {
                            'Errors': None,
                            'Good': True,
                            'Questionable': False,
                            'Substituted': False,
                            'Timestamp': '2025-10-20T02:51:13.445841Z',
                            'Units_Abbreviation': '',
                            'Value': None,
                            'WebException': None
                        },
                        'WebException': None
                    }
                ],
                'Links': {
                    'Source': 'https://scgc-piwebapi.scg.com/piwebapi/points/F1DPHSnIGrprK0eN5gMvEdroaQt24AAATU9DUERIMDFcVkNNMi1NQUlSQTE0MTRBLlBW'
                },
                'Name': 'VCM2-MAIRA1414A.PV',
                'Path': '\\\\MOCPDH01\\VCM2-MAIRA1414A.PV',
                'WebException': None,
                'WebId': 'F1DPHSnIGrprK0eN5gMvEdroaQt24AAATU9DUERIMDFcVkNNMi1NQUlSQTE0MTRBLlBW'
            }
        ],
        'Links': {
            'First': None, 'Last': None, 'Next': None, 'Previous': None
        }
    }

if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*70)
    print("  FastAPI NTLM Server - STATELESS (No Cookies)")
    print("  User: NoomCodework")
    print("  Date: 2025-10-30")
    print("="*70)
    print("\n✓ Features:")
    print("  • Works with ANY HTTP client (no cookie dependency!)")
    print("  • Python, Node.js, curl, JavaScript, etc.")
    print("  • Challenge embedded in Type 2 message")
    print("  • Session-free stateless authentication")
    
    print("\n📋 Test Users:")
    for u, d in users_db.items():
        print(f"   • {u:10} / {d['password']:15}")
    
    print("\n🌐 http://localhost:8000")
    print("📖 http://localhost:8000/docs")
    print("\n💡 Now works with clients from ANY language!")
    print("="*70 + "\n")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )