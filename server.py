"""
server.py
Main multi-client HTTP API server with POST/GET endpoints for file transfers.
Handles file uploads, downloads, and status queries with encryption support.
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import sys
import traceback
from datetime import datetime
from werkzeug.utils import secure_filename

# Import configuration and utilities
from config import (
    SERVER_HOST, 
    SERVER_PORT, 
    UPLOAD_DIR, 
    STORAGE_PATH,
    ENCRYPTED_PATH,
    TEMP_PATH,
    MAX_FILE_SIZE,
    ENCRYPTION_KEY
)
from utils.hash_util import file_checksum
from utils.encrypt_util import encrypt_data, decrypt_data
from utils.status_handler import StatusHandler

# Initialize Flask app
app = Flask(__name__)

# Enable CORS for local frontend development
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:*", "http://127.0.0.1:*"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Configure max upload size
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Initialize status handler
status_handler = StatusHandler()


def log_error(message, exception=None):
    """Log error messages with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] ERROR: {message}")
    if exception:
        print(f"[{timestamp}] {traceback.format_exc()}")


def log_info(message):
    """Log info messages with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] INFO: {message}")


@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for monitoring and uptime verification.
    
    Returns:
        JSON: {status: "ok", timestamp: ISO8601}
        HTTP 200: Service is healthy
    
    Example:
        GET /health
        Response: {"status": "ok", "timestamp": "2024-10-24T07:30:00Z"}
    """
    try:
        return jsonify({
            'status': 'ok',
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }), 200
    except Exception as e:
        log_error("Health check failed", e)
        return jsonify({'status': 'error', 'error': str(e)}), 500


@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Upload file endpoint with optional encryption.
    
    Input (multipart/form-data):
        - file: File to upload (required)
        - filename: Custom filename (optional, defaults to uploaded filename)
        - encryption: Boolean, encrypt file (optional, default: False)
        - priority: Integer, transfer priority (optional, default: 0)
    
    Returns:
        JSON: {
            success: Boolean,
            filename: String,
            hash: String (SHA-256),
            status: String,
            encryption: Boolean,
            nonce: String (hex, if encrypted),
            tag: String (hex, if encrypted),
            size: Integer (bytes),
            error: String (if failed)
        }
    
    Status Codes:
        200: Success
        400: Bad request (missing file, invalid parameters)
        413: File too large
        500: Internal server error
    
    Example:
        POST /upload
        Content-Type: multipart/form-data
        file=<binary data>
        filename=test.txt
        encryption=true
        priority=5
    """
    try:
        # Validate file presence
        if 'file' not in request.files:
            log_error("Upload request missing file")
            return jsonify({
                'success': False,
                'error': 'No file provided in request'
            }), 400
        
        file = request.files['file']
        
        # Check if file is empty
        if file.filename == '':
            log_error("Upload request with empty filename")
            return jsonify({
                'success': False,
                'error': 'Empty filename provided'
            }), 400
        
        # Get optional parameters with defaults
        custom_filename = request.form.get('filename', None)
        encryption_enabled = request.form.get('encryption', 'false').lower() in ['true', '1', 'yes']
        
        try:
            priority = int(request.form.get('priority', 0))
        except (ValueError, TypeError):
            priority = 0
        
        # Determine final filename (sanitize for security)
        if custom_filename:
            filename = secure_filename(custom_filename)
        else:
            filename = secure_filename(file.filename)
        
        # Additional filename validation
        if not filename or filename == '':
            log_error("Filename sanitization resulted in empty string")
            return jsonify({
                'success': False,
                'error': 'Invalid filename - contains illegal characters'
            }), 400
        
        # Ensure upload directory exists
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        os.makedirs(TEMP_PATH, exist_ok=True)
        if encryption_enabled:
            os.makedirs(ENCRYPTED_PATH, exist_ok=True)
        
        # Save to temporary location first
        temp_filepath = os.path.join(TEMP_PATH, filename)
        file.save(temp_filepath)
        
        # Check file size after saving
        file_size = os.path.getsize(temp_filepath)
        if file_size > MAX_FILE_SIZE:
            os.remove(temp_filepath)
            log_error(f"File too large: {file_size} bytes (max: {MAX_FILE_SIZE})")
            return jsonify({
                'success': False,
                'error': f'File too large. Maximum size: {MAX_FILE_SIZE / (1024*1024):.2f} MB'
            }), 413
        
        log_info(f"File uploaded to temp: {filename} ({file_size} bytes)")
        
        # Compute hash of original file
        file_hash = file_checksum(temp_filepath)
        if not file_hash:
            os.remove(temp_filepath)
            return jsonify({
                'success': False,
                'error': 'Failed to compute file checksum'
            }), 500
        
        # Handle encryption if requested
        nonce_hex = None
        tag_hex = None
        
        if encryption_enabled:
            try:
                log_info(f"Encrypting file: {filename}")
                
                # Read file data
                with open(temp_filepath, 'rb') as f:
                    file_data = f.read()
                
                # Encrypt data
                nonce, ciphertext, tag = encrypt_data(file_data, ENCRYPTION_KEY)
                nonce_hex = nonce.hex()
                tag_hex = tag.hex()
                
                # Save encrypted file
                final_filepath = os.path.join(ENCRYPTED_PATH, filename)
                with open(final_filepath, 'wb') as f:
                    # Store nonce + tag + ciphertext
                    f.write(nonce)
                    f.write(tag)
                    f.write(ciphertext)
                
                # Remove temp file
                os.remove(temp_filepath)
                
                log_info(f"File encrypted: {filename}")
            
            except Exception as e:
                log_error(f"Encryption failed for {filename}", e)
                if os.path.exists(temp_filepath):
                    os.remove(temp_filepath)
                return jsonify({
                    'success': False,
                    'error': f'Encryption failed: {str(e)}'
                }), 500
        else:
            # Move to final location (unencrypted)
            final_filepath = os.path.join(UPLOAD_DIR, filename)
            os.rename(temp_filepath, final_filepath)
            log_info(f"File saved (unencrypted): {filename}")
        
        # Update status handler
        status_handler.update_status(
            filename=filename,
            status='completed',
            checksum=file_hash,
            encryption=encryption_enabled,
            priority=priority
        )
        
        # Add to queue if priority is set
        if priority > 0:
            status_handler.add_to_queue(filename, priority=priority)
        
        # Build response
        response = {
            'success': True,
            'filename': filename,
            'hash': file_hash,
            'status': 'completed',
            'encryption': encryption_enabled,
            'size': file_size,
            'priority': priority
        }
        
        if encryption_enabled:
            response['nonce'] = nonce_hex
            response['tag'] = tag_hex
        
        log_info(f"Upload complete: {filename}")
        return jsonify(response), 200
    
    except Exception as e:
        log_error("Upload handler error", e)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@app.route('/status', methods=['GET'])
def get_all_status():
    """
    Get all transfer status entries.
    
    Returns:
        JSON: {
            transfers: [
                {
                    filename: String,
                    status: String,
                    checksum: String,
                    encryption: Boolean,
                    priority: Integer,
                    created_at: ISO8601,
                    updated_at: ISO8601
                }, ...
            ],
            queue: [filename, ...],
            metadata: {total_transfers: Integer, last_updated: ISO8601}
        }
    
    Status Codes:
        200: Success
        500: Internal server error
    
    Example:
        GET /status
    """
    try:
        all_status = status_handler.get_all_status()
        
        # Convert transfers dict to list for easier frontend consumption
        transfers_list = [
            {
                'filename': filename,
                **details
            }
            for filename, details in all_status.get('transfers', {}).items()
        ]
        
        response = {
            'transfers': transfers_list,
            'queue': all_status.get('queue', []),
            'metadata': all_status.get('metadata', {})
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        log_error("Get all status error", e)
        return jsonify({
            'error': f'Failed to retrieve status: {str(e)}'
        }), 500


@app.route('/status/<filename>', methods=['GET'])
def get_file_status(filename):
    """
    Get status for a specific file.
    
    Args:
        filename: Name of the file to query
    
    Returns:
        JSON: {
            filename: String,
            status: String,
            checksum: String,
            encryption: Boolean,
            priority: Integer,
            created_at: ISO8601,
            updated_at: ISO8601
        }
    
    Status Codes:
        200: Success
        404: File not found in status tracking
        500: Internal server error
    
    Example:
        GET /status/test.txt
    """
    try:
        # Sanitize filename
        filename = secure_filename(filename)
        
        if not filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        status = status_handler.get_status(filename)
        
        if status is None:
            log_info(f"Status not found for: {filename}")
            return jsonify({
                'error': f'File not found: {filename}',
                'filename': filename
            }), 404
        
        response = {
            'filename': filename,
            **status
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        log_error(f"Get status error for {filename}", e)
        return jsonify({
            'error': f'Failed to retrieve status: {str(e)}'
        }), 500


@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    """
    Download a file with optional decryption.
    
    Args:
        filename: Name of the file to download
    
    Query Parameters:
        decrypt: Boolean, decrypt encrypted files (optional, default: true)
    
    Returns:
        File stream with appropriate Content-Type and Content-Disposition headers
    
    Status Codes:
        200: Success (file stream)
        400: Invalid filename
        404: File not found
        403: Permission denied
        500: Internal server error
    
    Example:
        GET /download/test.txt
        GET /download/encrypted.dat?decrypt=true
    """
    try:
        # Sanitize filename for security
        filename = secure_filename(filename)
        
        if not filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        # Check if decryption is requested
        should_decrypt = request.args.get('decrypt', 'true').lower() in ['true', '1', 'yes']
        
        # Get file status to check if encrypted
        file_status = status_handler.get_status(filename)
        is_encrypted = file_status and file_status.get('encryption', False)
        
        # Determine file path
        if is_encrypted:
            filepath = os.path.join(ENCRYPTED_PATH, filename)
        else:
            filepath = os.path.join(UPLOAD_DIR, filename)
        
        # Check if file exists
        if not os.path.exists(filepath):
            log_error(f"File not found: {filepath}")
            return jsonify({'error': f'File not found: {filename}'}), 404
        
        # Check read permission
        if not os.access(filepath, os.R_OK):
            log_error(f"Permission denied: {filepath}")
            return jsonify({'error': 'Permission denied'}), 403
        
        # Handle decryption if needed
        if is_encrypted and should_decrypt:
            try:
                log_info(f"Decrypting file: {filename}")
                
                # Read encrypted file
                with open(filepath, 'rb') as f:
                    nonce = f.read(16)  # First 16 bytes
                    tag = f.read(16)    # Next 16 bytes
                    ciphertext = f.read()  # Rest is ciphertext
                
                # Decrypt
                plaintext = decrypt_data(nonce, ciphertext, tag, ENCRYPTION_KEY)
                
                # Save decrypted file to temp location
                temp_decrypted = os.path.join(TEMP_PATH, f"decrypted_{filename}")
                with open(temp_decrypted, 'wb') as f:
                    f.write(plaintext)
                
                log_info(f"File decrypted: {filename}")
                
                # Send decrypted file
                directory = TEMP_PATH
                actual_filename = f"decrypted_{filename}"
            
            except Exception as e:
                log_error(f"Decryption failed for {filename}", e)
                return jsonify({
                    'error': f'Decryption failed: {str(e)}'
                }), 500
        else:
            # Send file as-is
            if is_encrypted:
                directory = ENCRYPTED_PATH
            else:
                directory = UPLOAD_DIR
            actual_filename = filename
        
        log_info(f"Sending file: {filename}")
        
        # Stream file to client
        return send_from_directory(
            directory=directory,
            path=actual_filename,
            as_attachment=True,
            download_name=filename  # Original filename for download
        )
    
    except FileNotFoundError:
        return jsonify({'error': f'File not found: {filename}'}), 404
    
    except Exception as e:
        log_error(f"Download error for {filename}", e)
        return jsonify({
            'error': f'Download failed: {str(e)}'
        }), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large errors."""
    return jsonify({
        'success': False,
        'error': f'File too large. Maximum size: {MAX_FILE_SIZE / (1024*1024):.2f} MB'
    }), 413


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        'error': 'Endpoint not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors."""
    log_error("Internal server error", error)
    return jsonify({
        'error': 'Internal server error'
    }), 500


if __name__ == '__main__':
    # Ensure all required directories exist
    try:
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        os.makedirs(TEMP_PATH, exist_ok=True)
        os.makedirs(ENCRYPTED_PATH, exist_ok=True)
        log_info(f"Storage directories initialized: {UPLOAD_DIR}")
    except Exception as e:
        log_error("Failed to create storage directories", e)
        sys.exit(1)
    
    log_info("=" * 60)
    log_info("Smart File Transfer Server")
    log_info(f"Host: {SERVER_HOST}")
    log_info(f"Port: {SERVER_PORT}")
    log_info(f"Upload Directory: {UPLOAD_DIR}")
    log_info(f"Max File Size: {MAX_FILE_SIZE / (1024*1024):.2f} MB")
    log_info(f"Encryption: Enabled (AES-128-EAX)")
    log_info("=" * 60)
    
    # Start Flask server
    app.run(
        host=SERVER_HOST,
        port=SERVER_PORT,
        threaded=True,
        debug=False  # Set to True for development
    )
