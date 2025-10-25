"""
server.py
Main multi-client HTTP API server with POST/GET endpoints for file transfers.
Handles file uploads, downloads, and status queries with encryption support.
"""

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
import sys
import time
import threading
import zipfile
import io
import secrets
from datetime import datetime
from werkzeug.utils import secure_filename
from functools import wraps

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
from utils.progress_tracker import ProgressTracker, NetworkMonitor, format_speed, format_eta
from utils.metadata_util import get_file_metadata, generate_thumbnail, get_file_type_category, format_file_size

# Initialize Flask app
app = Flask(__name__)

# Enable CORS for local frontend development
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:*", "http://127.0.0.1:*"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-API-Key"]
    }
})

# Initialize SocketIO for WebSocket support
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Configure max upload size
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Initialize status handler and network monitor
status_handler = StatusHandler()
network_monitor = NetworkMonitor()

# Authentication
API_KEYS = set(os.environ.get('API_KEYS', 'dev-key-123,hackathon-key-456').split(','))

# Transfer cancellation tracking
cancellation_flags = {}
cancellation_lock = threading.Lock()


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


def require_api_key(f):
    """Decorator to require API key for endpoint access."""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        if api_key not in API_KEYS:
            return jsonify({'error': 'Invalid API key'}), 403
        
        return f(*args, **kwargs)
    return decorated


def is_cancelled(filename):
    """Check if transfer should be cancelled."""
    with cancellation_lock:
        return cancellation_flags.get(filename, False)


def set_cancelled(filename, cancelled=True):
    """Set cancellation flag for file."""
    with cancellation_lock:
        cancellation_flags[filename] = cancelled


def upload_with_progress(file_stream, filename, total_size, client_ip=None, client_agent=None, client_id=None):
    """
    Upload file with real-time progress tracking.
    
    Args:
        file_stream: File stream from request
        filename (str): Name of the file
        total_size (int): Total file size in bytes
        client_ip (str): Client IP address
        client_agent (str): Client user agent
        client_id (str): Custom client identifier
        
    Returns:
        tuple: (success, file_path, error_message)
    """
    chunk_size = 8192  # 8KB chunks
    received = 0
    start_time = time.time()
    
    # Initialize progress tracker
    progress_tracker = ProgressTracker(filename, total_size)
    
    # Update initial status
    status_handler.update_status(
        filename=filename,
        status='uploading',
        client_ip=client_ip,
        client_agent=client_agent,
        client_id=client_id,
        total_bytes=total_size,
        transferred_bytes=0,
        progress=0,
        speed=0,
        eta=0
    )
    
    # Save to temporary location first
    temp_filepath = os.path.join(TEMP_PATH, filename)
    
    try:
        with open(temp_filepath, 'wb') as f:
            while True:
                # Check if cancelled
                if is_cancelled(filename):
                    # Cleanup partial file
                    f.close()
                    if os.path.exists(temp_filepath):
                        os.remove(temp_filepath)
                    
                    status_handler.update_status(filename, 'cancelled')
                    
                    # Clear cancellation flag
                    set_cancelled(filename, False)
                    
                    # Emit WebSocket notification
                    socketio.emit('status_update', {
                        'filename': filename,
                        'status': 'cancelled',
                        'progress': 0
                    }, room=filename)
                    
                    raise Exception(f'Transfer cancelled by user')
                
                chunk = file_stream.read(chunk_size)
                if not chunk:
                    break
                
                f.write(chunk)
                received += len(chunk)
                
                # Update progress every 256KB or 5% of file
                if received % (256 * 1024) == 0 or received % max(1, total_size // 20) == 0:
                    progress_data = progress_tracker.update(received)
                    
                    # Update status with progress
                    status_handler.update_status(
                        filename=filename,
                        status='uploading',
                        progress=progress_data['progress'],
                        speed=progress_data['speed'],
                        eta=progress_data['eta'],
                        transferred_bytes=received,
                        total_bytes=total_size
                    )
                    
                    # Emit WebSocket notification
                    socketio.emit('status_update', {
                        'filename': filename,
                        'status': 'uploading',
                        'progress': progress_data['progress'],
                        'speed': progress_data['speed'],
                        'eta': progress_data['eta'],
                        'transferred_bytes': received,
                        'total_bytes': total_size
                    }, room=filename)
                    
                    # Also emit to global room
                    socketio.emit('transfer_update', {
                        'filename': filename,
                        'progress': progress_data['progress']
                    }, room='all_transfers')
        
        # Final progress update
        final_progress = progress_tracker.update(received)
        status_handler.update_status(
            filename=filename,
            status='uploading',
            progress=final_progress['progress'],
            speed=final_progress['speed'],
            eta=final_progress['eta'],
            transferred_bytes=received,
            total_bytes=total_size
        )
        
        log_info(f"Upload progress complete: {filename} ({received}/{total_size} bytes)")
        return True, temp_filepath, None
        
    except Exception as e:
        log_error(f"Upload progress failed for {filename}", e)
        return False, None, str(e)


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
        
        # Capture client information
        client_ip = request.remote_addr
        client_agent = request.headers.get('User-Agent', 'Unknown')
        client_id = request.form.get('client_id', client_ip)
        
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
        
        # Get file size from Content-Length header if available
        content_length = request.headers.get('Content-Length')
        if content_length:
            file_size = int(content_length)
        else:
            # Fallback: save to temp and check size
            temp_filepath = os.path.join(TEMP_PATH, filename)
            file.save(temp_filepath)
            file_size = os.path.getsize(temp_filepath)
            os.remove(temp_filepath)  # Remove temp file, we'll use progress tracking
        
        # Use progress tracking for upload
        success, temp_filepath, error_msg = upload_with_progress(
            file, filename, file_size, client_ip, client_agent, client_id
        )
        
        if not success:
            return jsonify({
                'success': False,
                'error': f'Upload failed: {error_msg}'
            }), 500
        
        # Check file size after upload
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
        
        # Update status handler with final completion
        status_handler.update_status(
            filename=filename,
            status='completed',
            checksum=file_hash,
            encryption=encryption_enabled,
            priority=priority,
            client_ip=client_ip,
            client_agent=client_agent,
            client_id=client_id,
            progress=100,
            transferred_bytes=file_size,
            total_bytes=file_size
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


@app.route('/upload_chunk', methods=['POST'])
def upload_chunk():
    """
    Upload a single chunk of a file with progress tracking.
    
    Form data:
        - chunk: file chunk (binary)
        - filename: target filename
        - chunk_number: current chunk (0-based)
        - total_chunks: total number of chunks
        - chunk_hash: SHA-256 of this chunk (for integrity)
        - client_id: Optional custom client identifier
    
    Returns:
        JSON: {
            success: Boolean,
            chunks_received: Integer,
            status: String (if all chunks received)
        }
    """
    try:
        # Validate required fields
        if 'chunk' not in request.files:
            return jsonify({'error': 'No chunk provided'}), 400
        
        chunk_file = request.files['chunk']
        filename = request.form.get('filename')
        chunk_number = request.form.get('chunk_number')
        total_chunks = request.form.get('total_chunks')
        chunk_hash = request.form.get('chunk_hash')
        client_id = request.form.get('client_id', request.remote_addr)
        
        if not all([filename, chunk_number, total_chunks, chunk_hash]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        try:
            chunk_number = int(chunk_number)
            total_chunks = int(total_chunks)
        except ValueError:
            return jsonify({'error': 'Invalid chunk_number or total_chunks'}), 400
        
        # Verify chunk integrity
        chunk_data = chunk_file.read()
        import hashlib
        received_hash = hashlib.sha256(chunk_data).hexdigest()
        if received_hash != chunk_hash:
            return jsonify({'error': 'Chunk integrity check failed'}), 400
        
        # Save chunk to temp directory
        chunk_dir = os.path.join(UPLOAD_DIR, 'chunks', filename)
        os.makedirs(chunk_dir, exist_ok=True)
        chunk_path = os.path.join(chunk_dir, f'chunk_{chunk_number}')
        
        with open(chunk_path, 'wb') as f:
            f.write(chunk_data)
        
        # Update progress
        progress = int(((chunk_number + 1) / total_chunks) * 100)
        status_handler.update_status(
            filename=filename,
            status='uploading',
            progress=progress,
            client_id=client_id,
            client_ip=request.remote_addr,
            client_agent=request.headers.get('User-Agent', 'Unknown')
        )
        
        # Check if all chunks received
        received_chunks = len([f for f in os.listdir(chunk_dir) if f.startswith('chunk_')])
        if received_chunks == total_chunks:
            # Assemble file
            assemble_chunks(filename, chunk_dir, total_chunks)
            return jsonify({'success': True, 'status': 'completed'}), 200
        
        return jsonify({'success': True, 'chunks_received': received_chunks}), 200
    
    except Exception as e:
        log_error("Chunk upload error", e)
        return jsonify({'error': f'Chunk upload failed: {str(e)}'}), 500


def assemble_chunks(filename, chunk_dir, total_chunks):
    """Combine all chunks into final file."""
    final_path = os.path.join(UPLOAD_DIR, filename)
    
    with open(final_path, 'wb') as outfile:
        for i in range(total_chunks):
            chunk_path = os.path.join(chunk_dir, f'chunk_{i}')
            with open(chunk_path, 'rb') as chunk:
                outfile.write(chunk.read())
    
    # Cleanup chunks
    import shutil
    shutil.rmtree(chunk_dir)
    
    # Update status
    status_handler.update_status(filename, 'completed', progress=100)


@app.route('/resume_info/<filename>', methods=['GET'])
def get_resume_info(filename):
    """Get which chunks have been received for resuming upload."""
    try:
        chunk_dir = os.path.join(UPLOAD_DIR, 'chunks', filename)
        
        if not os.path.exists(chunk_dir):
            return jsonify({'received_chunks': []}), 200
        
        received = sorted([
            int(f.split('_')[1]) 
            for f in os.listdir(chunk_dir) 
            if f.startswith('chunk_')
        ])
        
        return jsonify({
            'received_chunks': received,
            'can_resume': True
        }), 200
    
    except Exception as e:
        log_error(f"Resume info error for {filename}", e)
        return jsonify({'error': f'Failed to get resume info: {str(e)}'}), 500


@app.route('/clients', methods=['GET'])
def get_active_clients():
    """Get list of all clients that have uploaded/downloaded files."""
    try:
        all_status = status_handler.get_all_status()
        clients = {}
        
        for filename, info in all_status.get('transfers', {}).items():
            client_ip = info.get('client_ip', 'Unknown')
            
            if client_ip not in clients:
                clients[client_ip] = {
                    'ip': client_ip,
                    'files': [],
                    'total_uploads': 0,
                    'total_downloads': 0,
                    'last_activity': info.get('updated_at'),
                    'client_agent': info.get('client_agent', 'Unknown'),
                    'client_id': info.get('client_id', client_ip)
                }
            
            clients[client_ip]['files'].append(filename)
            if info.get('status') == 'completed':
                clients[client_ip]['total_uploads'] += 1
        
        return jsonify({'clients': list(clients.values())}), 200
    
    except Exception as e:
        log_error("Get clients error", e)
        return jsonify({'error': f'Failed to get clients: {str(e)}'}), 500


@app.route('/ping', methods=['POST'])
def ping():
    """Client pings to measure latency and network quality."""
    try:
        client_timestamp = float(request.json.get('timestamp', 0))
        server_timestamp = time.time()
        
        latency_ms = (server_timestamp - client_timestamp) * 1000
        network_monitor.add_latency(latency_ms)
        
        return jsonify({
            'server_timestamp': server_timestamp,
            'latency_ms': latency_ms,
            'network_quality': network_monitor.get_quality(),
            'recommended_chunk_size': network_monitor.get_recommended_chunk_size()
        }), 200
    
    except Exception as e:
        log_error("Ping error", e)
        return jsonify({'error': f'Ping failed: {str(e)}'}), 500


@app.route('/upload_batch', methods=['POST'])
@require_api_key
def upload_batch():
    """Upload multiple files in one request."""
    files = request.files.getlist('files')
    
    if not files:
        return jsonify({'error': 'No files provided'}), 400
    
    results = []
    encryption = request.form.get('encryption', 'false').lower() == 'true'
    priority = int(request.form.get('priority', 0))
    client_ip = request.remote_addr
    client_agent = request.headers.get('User-Agent')
    client_id = request.form.get('client_id')
    
    for file in files:
        try:
            filename = secure_filename(file.filename)
            if not filename:
                results.append({
                    'filename': file.filename,
                    'status': 'failed',
                    'error': 'Invalid filename'
                })
                continue
            
            filepath = os.path.join(UPLOAD_DIR, filename)
            
            # Save file
            file.save(filepath)
            
            # Calculate hash
            checksum = file_checksum(filepath)
            
            # Encrypt if requested
            if encryption:
                encrypt_data(filepath, ENCRYPTION_KEY)
                filename += '.enc'
                os.rename(filepath, os.path.join(UPLOAD_DIR, filename))
                filepath = os.path.join(UPLOAD_DIR, filename)
            
            # Get file metadata
            metadata = get_file_metadata(filepath)
            
            # Update status
            status_handler.update_status(
                filename=filename,
                status='completed',
                checksum=checksum,
                encryption=encryption,
                priority=priority,
                client_ip=client_ip,
                client_agent=client_agent,
                client_id=client_id,
                total_bytes=os.path.getsize(filepath)
            )
            
            results.append({
                'filename': filename,
                'status': 'success',
                'hash': checksum,
                'size': os.path.getsize(filepath),
                'metadata': metadata
            })
            
            # Emit WebSocket notification
            socketio.emit('batch_upload_complete', {
                'filename': filename,
                'status': 'completed'
            }, room='all_transfers')
            
        except Exception as e:
            results.append({
                'filename': file.filename,
                'status': 'failed',
                'error': str(e)
            })
    
    return jsonify({
        'success': True,
        'total_files': len(files),
        'successful': len([r for r in results if r['status'] == 'success']),
        'failed': len([r for r in results if r['status'] == 'failed']),
        'results': results
    }), 200


@app.route('/download_batch', methods=['POST'])
@require_api_key
def download_batch():
    """Download multiple files as a ZIP archive."""
    filenames = request.json.get('filenames', [])
    
    if not filenames:
        return jsonify({'error': 'No filenames provided'}), 400
    
    # Create ZIP archive in memory
    zip_buffer = io.BytesIO()
    
    try:
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for filename in filenames:
                filepath = os.path.join(UPLOAD_DIR, filename)
                
                if not os.path.exists(filepath):
                    continue  # Skip missing files
                
                # Decrypt if encrypted
                if filename.endswith('.enc'):
                    decrypted_data = decrypt_data(filepath, ENCRYPTION_KEY)
                    zip_file.writestr(filename[:-4], decrypted_data)
                else:
                    zip_file.write(filepath, filename)
        
        zip_buffer.seek(0)
        
        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'batch_download_{len(filenames)}_files.zip'
        )
        
    except Exception as e:
        return jsonify({'error': f'Batch download failed: {str(e)}'}), 500


@app.route('/cancel/<filename>', methods=['POST'])
@require_api_key
def cancel_transfer(filename):
    """Cancel an ongoing transfer."""
    set_cancelled(filename, True)
    
    # Update status
    status_handler.update_status(filename, 'cancelled', progress=0)
    
    # Emit WebSocket event
    socketio.emit('status_update', {
        'filename': filename,
        'status': 'cancelled'
    }, room=filename)
    
    return jsonify({'success': True, 'message': f'{filename} cancelled'}), 200


@app.route('/metadata/<filename>', methods=['GET'])
def get_metadata(filename):
    """Get file metadata including thumbnail."""
    filepath = os.path.join(UPLOAD_DIR, filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
    
    metadata = get_file_metadata(filepath)
    return jsonify(metadata), 200


@app.route('/thumbnail/<filename>', methods=['GET'])
def get_thumbnail(filename):
    """Serve thumbnail image."""
    thumb_path = os.path.join(UPLOAD_DIR, filename + '.thumb.jpg')
    
    if not os.path.exists(thumb_path):
        return jsonify({'error': 'Thumbnail not found'}), 404
    
    return send_file(thumb_path, mimetype='image/jpeg')


@app.route('/history', methods=['GET'])
def get_history():
    """Get transfer history with optional filters."""
    # Parse query parameters
    status_filter = request.args.get('status')  # completed, failed, uploading, etc.
    client_ip = request.args.get('client')
    from_date = request.args.get('from')  # ISO format: 2025-10-20
    to_date = request.args.get('to')
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    
    # Get all transfers
    all_data = status_handler._read_data()
    transfers = all_data.get('transfers', {})
    filtered = {}
    
    # Apply filters
    for filename, info in transfers.items():
        # Status filter
        if status_filter and info.get('status') != status_filter:
            continue
        
        # Client IP filter
        if client_ip and info.get('client_ip') != client_ip:
            continue
        
        # Date range filter
        created_at = info.get('created_at')
        if created_at:
            try:
                created_dt = datetime.fromisoformat(created_at)
                
                if from_date:
                    from_dt = datetime.fromisoformat(from_date)
                    if created_dt < from_dt:
                        continue
                
                if to_date:
                    to_dt = datetime.fromisoformat(to_date)
                    if created_dt > to_dt:
                        continue
            except:
                pass
        
        filtered[filename] = info
    
    # Sort by created_at (newest first)
    sorted_items = sorted(
        filtered.items(),
        key=lambda x: x[1].get('created_at', ''),
        reverse=True
    )
    
    # Apply pagination
    paginated = dict(sorted_items[offset:offset + limit])
    
    return jsonify({
        'transfers': paginated,
        'total_count': len(filtered),
        'returned_count': len(paginated),
        'offset': offset,
        'limit': limit
    }), 200


@app.route('/stats', methods=['GET'])
def get_statistics():
    """Get comprehensive transfer statistics."""
    all_data = status_handler._read_data()
    transfers = all_data.get('transfers', {})
    
    if not transfers:
        return jsonify({
            'total_transfers': 0,
            'message': 'No transfers yet'
        }), 200
    
    # Calculate metrics
    total_bytes = sum(t.get('total_bytes', 0) for t in transfers.values())
    completed = [t for t in transfers.values() if t.get('status') == 'completed']
    failed = [t for t in transfers.values() if t.get('status') == 'failed']
    active = [t for t in transfers.values() if t.get('status') in ['uploading', 'downloading']]
    
    speeds = [t.get('speed', 0) for t in transfers.values() if t.get('speed', 0) > 0]
    avg_speed = sum(speeds) / len(speeds) if speeds else 0
    
    unique_clients = set(t.get('client_ip') for t in transfers.values() if t.get('client_ip'))
    
    # File type distribution
    file_types = {}
    for t in transfers.values():
        ext = os.path.splitext(t.get('filename', ''))[1]
        file_types[ext] = file_types.get(ext, 0) + 1
    
    return jsonify({
        'total_transfers': len(transfers),
        'total_bytes': total_bytes,
        'total_size_mb': round(total_bytes / (1024 * 1024), 2),
        'completed_count': len(completed),
        'failed_count': len(failed),
        'active_count': len(active),
        'success_rate': round((len(completed) / len(transfers)) * 100, 2),
        'average_speed_mbps': round(avg_speed / (1024 * 1024), 2),
        'total_clients': len(unique_clients),
        'file_types': file_types,
        'encrypted_count': sum(1 for t in transfers.values() if t.get('encryption')),
        'queue_length': len(all_data.get('queue', []))
    }), 200


@app.route('/generate_key', methods=['POST'])
def generate_api_key():
    """Generate a new API key (admin only)."""
    new_key = secrets.token_urlsafe(32)
    return jsonify({'api_key': new_key}), 200


# WebSocket Event Handlers
@socketio.on('connect')
def handle_connect():
    """Client connects to WebSocket."""
    print(f'Client connected: {request.sid}')
    emit('connected', {'message': 'Connected to file transfer server'})


@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnects."""
    print(f'Client disconnected: {request.sid}')


@socketio.on('subscribe_status')
def handle_subscribe(data):
    """Client subscribes to specific file status updates."""
    filename = data.get('filename')
    join_room(filename)  # Join room for this file
    
    # Send current status immediately
    status = status_handler.get_status(filename)
    if status:
        emit('status_update', status, room=request.sid)
    else:
        emit('error', {'message': f'File {filename} not found'}, room=request.sid)


@socketio.on('unsubscribe_status')
def handle_unsubscribe(data):
    """Client unsubscribes from file updates."""
    filename = data.get('filename')
    leave_room(filename)


@socketio.on('subscribe_all')
def handle_subscribe_all():
    """Subscribe to all transfer updates."""
    join_room('all_transfers')
    all_status = status_handler.get_all_status()
    emit('status_update', all_status, room=request.sid)


@socketio.on('subscribe_stats')
def handle_subscribe_stats():
    """Subscribe to real-time statistics updates."""
    join_room('stats')
    # Send current stats immediately
    stats = get_statistics()
    emit('stats_update', stats.json if hasattr(stats, 'json') else stats, room=request.sid)


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


def emit_stats_periodically():
    """Emit statistics every 5 seconds to subscribed clients."""
    while True:
        time.sleep(5)
        with app.app_context():
            try:
                stats = get_statistics()
                socketio.emit('stats_update', stats.json if hasattr(stats, 'json') else stats, room='stats')
            except Exception as e:
                print(f"Error emitting stats: {e}")


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
    
    # Start background thread for periodic stats
    stats_thread = threading.Thread(target=emit_stats_periodically, daemon=True)
    stats_thread.start()
    
    log_info("=" * 60)
    log_info("Smart File Transfer Server")
    log_info(f"Host: {SERVER_HOST}")
    log_info(f"Port: {SERVER_PORT}")
    log_info(f"Upload Directory: {UPLOAD_DIR}")
    log_info(f"Max File Size: {MAX_FILE_SIZE / (1024*1024):.2f} MB")
    log_info(f"Encryption: Enabled (AES-128-EAX)")
    log_info(f"WebSocket: Enabled (Flask-SocketIO)")
    log_info("=" * 60)
    
    # Start SocketIO server
    port = int(os.environ.get('PORT', SERVER_PORT))
    socketio.run(app, host=SERVER_HOST, port=port, debug=True)
