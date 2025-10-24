"""
config.py
Configuration management for smart file transfer backend.
Provides robust defaults with environment variable overrides and validation.
"""

import os
import sys


# =============================================================================
# SERVER CONFIGURATION
# =============================================================================

# SERVER_HOST: Host address for the HTTP server
# Default: '0.0.0.0' (listens on all network interfaces)
# Production: Consider restricting to specific interface for security
# Override with environment variable: SERVER_HOST
SERVER_HOST = os.environ.get('SERVER_HOST', '0.0.0.0')

# SERVER_PORT: Port number for the HTTP server
# Default: 8080
# Production: Use standard ports (80/443) with reverse proxy recommended
# Override with environment variable: SERVER_PORT
try:
    SERVER_PORT = int(os.environ.get('SERVER_PORT', 8080))
    if not (1 <= SERVER_PORT <= 65535):
        raise ValueError(f"SERVER_PORT must be between 1-65535, got {SERVER_PORT}")
except ValueError as e:
    print(f"ERROR: Invalid SERVER_PORT configuration: {e}", file=sys.stderr)
    sys.exit(1)


# =============================================================================
# STORAGE CONFIGURATION
# =============================================================================

# UPLOAD_DIR: Directory for storing uploaded files
# Default: 'storage/' (relative to this config file)
# Production: Use absolute path on dedicated storage volume
# Override with environment variable: UPLOAD_DIR
UPLOAD_DIR = os.environ.get('UPLOAD_DIR', os.path.join(os.path.dirname(__file__), 'storage'))

# Additional storage paths
STORAGE_PATH = UPLOAD_DIR  # Alias for backward compatibility
TEMP_PATH = os.path.join(UPLOAD_DIR, 'temp')
ENCRYPTED_PATH = os.path.join(UPLOAD_DIR, 'encrypted')

# Validate UPLOAD_DIR configuration
if not UPLOAD_DIR:
    print("ERROR: UPLOAD_DIR cannot be empty", file=sys.stderr)
    sys.exit(1)


# =============================================================================
# TRANSFER STATUS CONFIGURATION
# =============================================================================

# LOG_FILE: JSON file for tracking transfer status and queue
# Default: 'transfer_status.json' (relative to this config file)
# Production: Store on persistent volume with regular backups
# Override with environment variable: LOG_FILE
LOG_FILE = os.environ.get('LOG_FILE', 
                          os.path.join(os.path.dirname(__file__), 'transfer_status.json'))

# Validate LOG_FILE configuration
if not LOG_FILE:
    print("ERROR: LOG_FILE cannot be empty", file=sys.stderr)
    sys.exit(1)

if not LOG_FILE.endswith('.json'):
    print(f"WARNING: LOG_FILE should be a .json file, got: {LOG_FILE}", file=sys.stderr)

STATUS_FILE = LOG_FILE  # Alias for backward compatibility


# =============================================================================
# ENCRYPTION CONFIGURATION
# =============================================================================

# ENCRYPTION_KEY: Symmetric key for AES encryption
# CRITICAL SECURITY REQUIREMENT:
# - Minimum 16 bytes (128-bit) for AES-128
# - NEVER hardcode in production code
# - ALWAYS use environment variables or secure key management service (KMS)
# - Rotate keys regularly in production
# - Consider using AWS KMS, Azure Key Vault, or HashiCorp Vault
#
# Development: Default placeholder key (INSECURE - for testing only)
# Production: Override with environment variable: ENCRYPTION_KEY
#
# Example production setup:
#   export ENCRYPTION_KEY="your-secure-16-byte-key-here"
#   OR
#   export ENCRYPTION_KEY=$(openssl rand -base64 16)

def _load_encryption_key():
    """
    Load and validate encryption key from environment or use default.
    
    Returns:
        bytes: Validated encryption key (16 bytes minimum)
    
    Raises:
        SystemExit: If key is invalid or missing in production
    """
    # Check for environment variable first (production)
    key_str = os.environ.get('ENCRYPTION_KEY')
    
    if key_str:
        # Convert string to bytes if necessary
        if isinstance(key_str, str):
            key = key_str.encode('utf-8')
        else:
            key = key_str
    else:
        # Development fallback (INSECURE)
        key = b'DevKey1234567890'  # Exactly 16 bytes for AES-128
        print("WARNING: Using default ENCRYPTION_KEY (INSECURE). "
              "Set ENCRYPTION_KEY environment variable in production!", 
              file=sys.stderr)
    
    # Validate key length
    if len(key) < 16:
        print(f"ERROR: ENCRYPTION_KEY must be at least 16 bytes, got {len(key)} bytes", 
              file=sys.stderr)
        sys.exit(1)
    
    # Warn if key is too long (will be truncated to 16 bytes for AES-128)
    if len(key) > 16:
        print(f"WARNING: ENCRYPTION_KEY is {len(key)} bytes, using first 16 bytes for AES-128", 
              file=sys.stderr)
        key = key[:16]
    
    return key


ENCRYPTION_KEY = _load_encryption_key()
AES_MODE = 'CBC'  # Cipher Block Chaining mode


# =============================================================================
# FILE TRANSFER CONFIGURATION
# =============================================================================

# Maximum file size for uploads (100 MB default)
MAX_FILE_SIZE = int(os.environ.get('MAX_FILE_SIZE', 100 * 1024 * 1024))

# Chunk size for streaming uploads/downloads (64 KB)
CHUNK_SIZE = int(os.environ.get('CHUNK_SIZE', 64 * 1024))


# =============================================================================
# AUTO-RESTART CONFIGURATION
# =============================================================================

# Enable automatic server restart on crash
AUTO_RESTART_ENABLED = os.environ.get('AUTO_RESTART_ENABLED', 'true').lower() == 'true'

# Maximum number of restart attempts before giving up
MAX_RESTART_ATTEMPTS = int(os.environ.get('MAX_RESTART_ATTEMPTS', 5))

# Delay between restart attempts (seconds)
RESTART_DELAY = int(os.environ.get('RESTART_DELAY', 5))


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

# Server application log file
SERVER_LOG_FILE = os.environ.get('SERVER_LOG_FILE', 'server.log')


# =============================================================================
# CONFIGURATION VALIDATION
# =============================================================================

def validate_config():
    """
    Validate all configuration settings.
    Raises SystemExit if any critical configuration is invalid.
    """
    errors = []
    
    # Validate server configuration
    if not isinstance(SERVER_PORT, int):
        errors.append(f"SERVER_PORT must be integer, got {type(SERVER_PORT)}")
    
    # Validate encryption key
    if len(ENCRYPTION_KEY) != 16:
        errors.append(f"ENCRYPTION_KEY must be exactly 16 bytes for AES-128, got {len(ENCRYPTION_KEY)}")
    
    # Validate file sizes
    if MAX_FILE_SIZE <= 0:
        errors.append(f"MAX_FILE_SIZE must be positive, got {MAX_FILE_SIZE}")
    
    if CHUNK_SIZE <= 0:
        errors.append(f"CHUNK_SIZE must be positive, got {CHUNK_SIZE}")
    
    # Report errors
    if errors:
        print("\nCONFIGURATION ERRORS:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        print("\nPlease fix configuration errors before starting the server.\n", file=sys.stderr)
        sys.exit(1)


# Run validation on import
validate_config()


# =============================================================================
# CONFIGURATION SUMMARY
# =============================================================================

if __name__ == '__main__':
    print("\n=== Smart File Transfer Configuration ===")
    print(f"Server: {SERVER_HOST}:{SERVER_PORT}")
    print(f"Upload Directory: {UPLOAD_DIR}")
    print(f"Status Log: {LOG_FILE}")
    print(f"Encryption Key Length: {len(ENCRYPTION_KEY)} bytes")
    print(f"Max File Size: {MAX_FILE_SIZE / (1024*1024):.2f} MB")
    print(f"Auto-restart: {AUTO_RESTART_ENABLED}")
    print(f"Log Level: {LOG_LEVEL}")
    print("=========================================\n")
