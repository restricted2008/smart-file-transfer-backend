# Smart File Transfer Backend

A secure, feature-rich file transfer server with encryption support, priority queuing, and comprehensive status tracking.

## Features

### Core Transfer Features
- 🔐 **AES-128-EAX Encryption** - Optional end-to-end file encryption
- 📊 **Live Progress Tracking** - Real-time upload/download progress with speed and ETA
- 🧩 **Chunked Upload/Download** - Break large files into chunks with resume capability
- 🔄 **Automatic Retry** - Exponential backoff retry logic for failed transfers
- 👥 **Multi-Client Tracking** - Track which client uploaded/downloaded each file
- 🌐 **Network Health Monitoring** - Detect unstable connections and adapt transfer strategy
- ⚡ **Speed Tracking** - Display transfer speed in MB/s with network quality assessment
- 💾 **Queue Persistence** - Transfer queue survives server restarts
- 🎯 **Priority Queue** - Transfer priority management

### Advanced Features
- 🔌 **WebSocket Real-Time Notifications** - Live updates via WebSocket connections
- 📦 **Batch File Operations** - Upload/download multiple files in one request
- ❌ **Transfer Cancellation** - Cancel ongoing transfers mid-upload
- 🖼️ **File Metadata & Thumbnails** - Rich file information with image thumbnails
- 📈 **Transfer History** - Filterable transfer history with date and client filters
- 🔑 **API Key Authentication** - Secure access with API key authentication
- 📊 **Transfer Statistics** - Comprehensive analytics and performance metrics

### Security & Reliability
- 🔒 **Thread-safe** - Concurrent access with file locking
- ✅ **Checksums** - SHA-256 file integrity verification
- 🌐 **CORS Support** - Ready for frontend integration
- 📝 **Comprehensive Logging** - Detailed error and event tracking

## Architecture

```
backend/
├── server.py              # Flask HTTP API server with WebSocket support
├── client.py              # CLI client for testing
├── config.py              # Configuration management
├── requirements.txt       # Python dependencies
├── transfer_status.json   # Transfer status tracking
├── test_integration.py    # Integration test suite
└── utils/
    ├── hash_util.py       # SHA-256 checksums
    ├── encrypt_util.py    # AES-128-EAX encryption
    ├── status_handler.py  # Thread-safe status management
    ├── progress_tracker.py # Live progress tracking utilities
    ├── metadata_util.py   # File metadata and thumbnail generation
    └── auto_restart.py    # Auto-restart monitor
```

## Installation

### Requirements

- Python 3.8+
- Windows or Linux/Ubuntu

### Setup

1. **Navigate to backend directory:**
   ```bash
   cd backend
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure (optional):**
   Edit `config.py` or use environment variables:
   ```bash
   # Windows (PowerShell)
   $env:SERVER_PORT = "8080"
   $env:ENCRYPTION_KEY = "your-16-byte-key"
   
   # Linux/Mac
   export SERVER_PORT=8080
   export ENCRYPTION_KEY="your-16-byte-key"
   ```

## Usage

### Starting the Server

**Basic start:**
```bash
python server.py
```

**With auto-restart monitor:**
```bash
python utils/auto_restart.py
```

The server will start on `http://localhost:8080` by default.

### Using the CLI Client

**Upload a file:**
```bash
python client.py upload document.pdf
```

**Upload with encryption:**
```bash
python client.py upload secret.txt --encrypt --priority 5
```

**Upload with retry logic:**
```bash
python client.py upload large_file.zip --retry 5
```

**Chunked upload with resume:**
```bash
python client.py upload huge_file.zip --chunked --chunk-size 2097152
```

**Check all transfers:**
```bash
python client.py status
```

**Check specific file:**
```bash
python client.py status --file document.pdf
```

**Download a file:**
```bash
python client.py download document.pdf --output ./downloads/
```

**Health check:**
```bash
python client.py health
```

**Full CLI help:**
```bash
python client.py --help
python client.py upload --help
```

## API Endpoints

### `POST /upload`
Upload a file with optional encryption.

**Request (multipart/form-data):**
- `file`: File to upload (required)
- `filename`: Custom filename (optional)
- `encryption`: Enable encryption - `true`/`false` (default: `false`)
- `priority`: Transfer priority 0-10 (default: 0)

**Response (200 OK):**
```json
{
  "success": true,
  "filename": "document.pdf",
  "hash": "abc123...",
  "status": "completed",
  "encryption": false,
  "size": 1024,
  "priority": 0
}
```

**Errors:**
- `400`: Missing file or invalid parameters
- `413`: File too large (>100MB)
- `500`: Server error

---

### `GET /status`
Get all transfer status entries.

**Response (200 OK):**
```json
{
  "transfers": [
    {
      "filename": "document.pdf",
      "status": "completed",
      "checksum": "abc123...",
      "encryption": false,
      "priority": 0,
      "created_at": "2024-10-24T07:30:00",
      "updated_at": "2024-10-24T07:30:05"
    }
  ],
  "queue": [
    {"filename": "document.pdf", "priority": 5}
  ],
  "metadata": {
    "total_transfers": 10,
    "last_updated": "2024-10-24T07:35:00"
  }
}
```

---

### `GET /status/<filename>`
Get status for a specific file.

**Response (200 OK):**
```json
{
  "filename": "document.pdf",
  "status": "uploading",
  "checksum": "abc123...",
  "encryption": false,
  "priority": 0,
  "progress": 45,
  "speed": 5242880,
  "eta": 120,
  "transferred_bytes": 1048576,
  "total_bytes": 10485760,
  "client_ip": "192.168.1.100",
  "retry_count": 0,
  "created_at": "2024-10-24T07:30:00",
  "updated_at": "2024-10-24T07:30:05"
}
```

**Errors:**
- `404`: File not found

---

### `GET /download/<filename>`
Download a file with optional decryption.

**Query Parameters:**
- `decrypt`: Decrypt encrypted files - `true`/`false` (default: `true`)

**Response (200 OK):**
File stream with `Content-Disposition: attachment`

**Errors:**
- `404`: File not found
- `403`: Permission denied
- `500`: Decryption failed

---

### `GET /health`
Health check endpoint.

**Response (200 OK):**
```json
{
  "status": "ok",
  "timestamp": "2024-10-24T07:30:00Z"
}
```

---

### `POST /upload_chunk`
Upload a single chunk of a file with progress tracking.

**Request (multipart/form-data):**
- `chunk`: File chunk (binary, required)
- `filename`: Target filename (required)
- `chunk_number`: Current chunk number 0-based (required)
- `total_chunks`: Total number of chunks (required)
- `chunk_hash`: SHA-256 hash of this chunk (required)
- `client_id`: Optional custom client identifier

**Response (200 OK):**
```json
{
  "success": true,
  "chunks_received": 5,
  "status": "completed"
}
```

**Errors:**
- `400`: Missing required fields or chunk integrity check failed
- `500`: Chunk upload failed

---

### `GET /resume_info/<filename>`
Get which chunks have been received for resuming upload.

**Response (200 OK):**
```json
{
  "received_chunks": [0, 1, 2, 4],
  "can_resume": true
}
```

---

### `GET /clients`
Get list of all clients that have uploaded/downloaded files.

**Response (200 OK):**
```json
{
  "clients": [
    {
      "ip": "192.168.1.100",
      "files": ["file1.txt", "file2.pdf"],
      "total_uploads": 2,
      "total_downloads": 0,
      "last_activity": "2024-10-24T07:30:00",
      "client_agent": "Mozilla/5.0...",
      "client_id": "client_123"
    }
  ]
}
```

---

### `POST /ping`
Client pings to measure latency and network quality.

**Request (JSON):**
```json
{
  "timestamp": 1698123456.789
}
```

**Response (200 OK):**
```json
{
  "server_timestamp": 1698123456.790,
  "latency_ms": 1.2,
  "network_quality": "excellent",
  "recommended_chunk_size": 1048576
}
```

---

### `POST /upload_batch`
Upload multiple files in one request.

**Headers:**
- `X-API-Key`: API key for authentication (required)

**Request (multipart/form-data):**
- `files`: Multiple files to upload (required)
- `encryption`: Enable encryption - `true`/`false` (default: `false`)
- `priority`: Transfer priority 0-10 (default: 0)
- `client_id`: Custom client identifier (optional)

**Response (200 OK):**
```json
{
  "success": true,
  "total_files": 3,
  "successful": 3,
  "failed": 0,
  "results": [
    {
      "filename": "file1.txt",
      "status": "success",
      "hash": "abc123...",
      "size": 1024,
      "metadata": {...}
    }
  ]
}
```

---

### `POST /download_batch`
Download multiple files as a ZIP archive.

**Headers:**
- `X-API-Key`: API key for authentication (required)

**Request (JSON):**
```json
{
  "filenames": ["file1.txt", "file2.pdf", "file3.jpg"]
}
```

**Response (200 OK):**
ZIP file stream with `Content-Type: application/zip`

---

### `POST /cancel/<filename>`
Cancel an ongoing transfer.

**Headers:**
- `X-API-Key`: API key for authentication (required)

**Response (200 OK):**
```json
{
  "success": true,
  "message": "file.txt cancelled"
}
```

---

### `GET /metadata/<filename>`
Get file metadata including thumbnail.

**Response (200 OK):**
```json
{
  "filename": "image.jpg",
  "size": 1048576,
  "created": "2024-10-24T07:30:00",
  "modified": "2024-10-24T07:30:05",
  "mime_type": "image/jpeg",
  "extension": ".jpg",
  "thumbnail": "image.jpg.thumb.jpg"
}
```

---

### `GET /thumbnail/<filename>`
Serve thumbnail image.

**Response (200 OK):**
JPEG image stream with `Content-Type: image/jpeg`

---

### `GET /history`
Get transfer history with optional filters.

**Query Parameters:**
- `status`: Filter by status (completed, failed, uploading, etc.)
- `client`: Filter by client IP
- `from`: From date (YYYY-MM-DD)
- `to`: To date (YYYY-MM-DD)
- `limit`: Maximum results (default: 100)
- `offset`: Skip results (default: 0)

**Response (200 OK):**
```json
{
  "transfers": {
    "file1.txt": {
      "status": "completed",
      "client_ip": "192.168.1.100",
      "created_at": "2024-10-24T07:30:00"
    }
  },
  "total_count": 50,
  "returned_count": 10,
  "offset": 0,
  "limit": 100
}
```

---

### `GET /stats`
Get comprehensive transfer statistics.

**Response (200 OK):**
```json
{
  "total_transfers": 100,
  "total_bytes": 104857600,
  "total_size_mb": 100.0,
  "completed_count": 95,
  "failed_count": 5,
  "active_count": 0,
  "success_rate": 95.0,
  "average_speed_mbps": 10.5,
  "total_clients": 15,
  "file_types": {
    ".txt": 30,
    ".pdf": 20,
    ".jpg": 25
  },
  "encrypted_count": 40,
  "queue_length": 0
}
```

---

### `POST /generate_key`
Generate a new API key (admin only).

**Response (200 OK):**
```json
{
  "api_key": "new_generated_key_here"
}
```

---

## WebSocket Events

### Connection
```javascript
const socket = io('http://localhost:8080');

socket.on('connect', () => {
  console.log('Connected to file transfer server');
});
```

### Subscribe to File Updates
```javascript
// Subscribe to specific file
socket.emit('subscribe_status', { filename: 'document.pdf' });

// Subscribe to all transfers
socket.emit('subscribe_all');

// Subscribe to statistics
socket.emit('subscribe_stats');
```

### Event Handlers
```javascript
// File status updates
socket.on('status_update', (data) => {
  console.log('File update:', data.progress, '%');
});

// Transfer updates
socket.on('transfer_update', (data) => {
  console.log('Transfer update:', data.filename, data.progress);
});

// Statistics updates
socket.on('stats_update', (stats) => {
  console.log('Stats update:', stats.total_transfers);
});
```

## Testing

### Unit Tests

**Test individual modules:**
```bash
# Hash utility tests
python utils/hash_util.py

# Encryption utility tests
python utils/encrypt_util.py

# Status handler tests
python utils/status_handler.py
```

### Integration Tests

**Run full integration test suite:**
```bash
# Start server first
python server.py

# In another terminal, run tests
python test_integration.py
```

**Auto-start server and test:**
```bash
python test_integration.py --auto-start
```

**Test specific server:**
```bash
python test_integration.py --url http://localhost:9000
```

### Test Coverage

The integration tests verify:

✅ **Valid Requests:**
- File upload (unencrypted)
- File upload with encryption
- Chunked upload with resume capability
- Live progress tracking
- Client identification and tracking
- Network quality monitoring
- Status retrieval (all and specific)
- File download (unencrypted)
- File download with decryption
- Health check

✅ **Invalid Requests:**
- Missing file upload (400 expected)
- Large file upload >100MB (413 expected)
- Nonexistent file status (404 expected)
- Nonexistent file download (404 expected)
- Invalid endpoint (404 expected)

✅ **Error Handling:**
- All error responses are JSON formatted
- User-friendly error messages
- Proper HTTP status codes

✅ **Edge Cases:**
- File corruption recovery
- Thread-safe concurrent access
- Empty file handling
- Unicode filename support

### Manual Testing Examples

**1. Test encryption roundtrip:**
```bash
# Create test file
echo "Secret message" > test.txt

# Upload with encryption
python client.py upload test.txt --encrypt --filename encrypted_test.txt

# Download and verify
python client.py download encrypted_test.txt --output decrypted.txt
cat decrypted.txt
# Should output: "Secret message"
```

**2. Test priority queue:**
```bash
# Upload files with different priorities
python client.py upload file1.txt --priority 1
python client.py upload file2.txt --priority 10
python client.py upload file3.txt --priority 5

# Check queue order
python client.py status
# Queue should show highest priority first
```

**3. Test large file handling:**
```bash
# Create 10MB file
python -c "with open('large.bin', 'wb') as f: f.write(b'A' * (10*1024*1024))"

# Upload
python client.py upload large.bin

# Verify
python client.py status --file large.bin
```

**4. Test error handling:**
```bash
# Try to download nonexistent file
python client.py download nonexistent.txt
# Should show user-friendly error

# Try to upload without running server
# (stop server first)
python client.py upload test.txt
# Should show connection error with helpful message
```

**5. Test new features:**
```bash
# Batch upload multiple files
python client.py batch file1.txt file2.txt file3.txt --encrypt

# Cancel a transfer
python client.py cancel large_file.bin

# Get transfer history
python client.py history --status completed --limit 10

# Get statistics
python client.py stats

# Get file metadata
python client.py metadata image.jpg
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_HOST` | Server host address | `0.0.0.0` |
| `SERVER_PORT` | Server port | `8080` |
| `UPLOAD_DIR` | Upload directory path | `storage/` |
| `LOG_FILE` | Status tracking file | `transfer_status.json` |
| `ENCRYPTION_KEY` | 16-byte AES key | Dev default (change in production!) |
| `MAX_FILE_SIZE` | Max upload size (bytes) | `104857600` (100MB) |
| `AUTO_RESTART_ENABLED` | Enable auto-restart | `true` |

### Security Notes

⚠️ **IMPORTANT:** The default encryption key is for development only!

**Production setup:**
```bash
# Generate secure key
openssl rand -base64 16

# Set environment variable
export ENCRYPTION_KEY="your-generated-key"
```

**Additional security recommendations:**
- Use HTTPS in production (reverse proxy with nginx/Apache)
- Implement authentication/authorization
- Rate limiting for upload endpoint
- Input sanitization (already included)
- Regular key rotation
- Secure key management (AWS KMS, Azure Key Vault, etc.)

## Troubleshooting

### Server won't start

**Check port availability:**
```bash
# Windows
netstat -ano | findstr :8080

# Linux/Mac
lsof -i :8080
```

**Solution:** Change port in config or kill existing process.

---

### Upload fails with "File too large"

**Solution:** Increase `MAX_FILE_SIZE` in `config.py` or environment:
```bash
export MAX_FILE_SIZE=209715200  # 200MB
```

---

### Status file corrupted

The system automatically recovers from corruption using backups.

**Manual recovery:**
```bash
# Restore from backup
cp transfer_status.json.backup transfer_status.json

# Or reset to default
echo '{"transfers":{},"queue":[],"metadata":{"last_updated":null,"total_transfers":0,"version":"1.0"}}' > transfer_status.json
```

---

### Permission errors

**Windows:**
```bash
# Run as administrator
python server.py
```

**Linux/Mac:**
```bash
# Fix permissions
chmod 755 server.py
chmod 755 client.py
chmod -R 755 utils/

# Create storage directories
mkdir -p storage/temp storage/encrypted
chmod 755 storage
```

---

### Import errors

**Solution:** Ensure all dependencies installed:
```bash
pip install -r requirements.txt --upgrade
```

---

### Connection refused

**Check if server is running:**
```bash
python client.py health
```

**If not running:**
```bash
python server.py
```

## Hackathon / Team Workflow

### Quick Team Setup (5 minutes)

**1. One person sets up the backend:**
```bash
git clone <repo>
cd backend
pip install -r requirements.txt
python server.py
```

**2. Share server URL with team:**
```
http://<your-ip>:8080

# Find your local IP:
# Windows: ipconfig | findstr IPv4
# Linux/Mac: ifconfig | grep "inet "
```

**3. Frontend team can immediately start using API:**
```javascript
// Upload file from frontend
const formData = new FormData();
formData.append('file', fileInput.files[0]);
formData.append('encryption', 'true');

fetch('http://192.168.1.100:8080/upload', {
  method: 'POST',
  body: formData
})
.then(res => res.json())
.then(data => console.log('Uploaded:', data.filename));
```

### Division of Work

**Backend Team (this repo):**
- ✅ Already done! Just run `python server.py`
- Optional: Add authentication, custom endpoints
- Testing: Use `client.py` for demos

**Frontend Team:**
- Build UI for file upload/download
- Display transfer status table
- Show encryption toggle
- Progress bars for uploads

**DevOps Team:**
- Deploy to cloud (see Cloud Hosting section)
- Set up domain and HTTPS
- Monitor with health check endpoint

**Demo/Presentation:**
- Use `client.py` for CLI demos
- Show encryption working (upload encrypted, download decrypted)
- Show status tracking in real-time
- Explain security features

### Testing Tips for Teams

**1. Parallel testing:**
```bash
# Terminal 1 - Backend
python server.py

# Terminal 2 - Test uploads
python client.py upload file1.txt &
python client.py upload file2.txt &
python client.py upload file3.txt &

# Terminal 3 - Monitor status
watch -n 1 'python client.py status'
```

**2. Stress testing:**
```bash
# Upload multiple files quickly
for i in {1..10}; do
  echo "Test file $i" > test$i.txt
  python client.py upload test$i.txt --priority $i &
done
wait
```

**3. Integration testing:**
```bash
# Run full test suite before demo
python test_integration.py --auto-start
```

**4. Demo script:**
```bash
#!/bin/bash
echo "=== Smart File Transfer Demo ==="

echo "\n1. Health Check"
python client.py health

echo "\n2. Upload File (Unencrypted)"
python client.py upload demo.txt

echo "\n3. Upload File (Encrypted)"
python client.py upload secret.txt --encrypt --priority 5

echo "\n4. Check Status"
python client.py status

echo "\n5. Download File"
python client.py download demo.txt -o downloaded.txt

echo "\n6. Verify Integrity"
diff demo.txt downloaded.txt && echo "✓ Files match!"

echo "\nDemo complete!"
```

### Common Hackathon Issues & Solutions

**Issue 1: "Can't connect to server from other computer"**
```bash
# Solution: Bind to 0.0.0.0, not localhost
export SERVER_HOST="0.0.0.0"
python server.py

# Or edit config.py:
SERVER_HOST = '0.0.0.0'  # Not '127.0.0.1'
```

**Issue 2: "Port already in use"**
```bash
# Solution: Use different port
export SERVER_PORT="9000"
python server.py
```

**Issue 3: "CORS error in browser"**
- Already fixed! Flask-CORS is configured for localhost
- For other origins, edit `server.py`:
```python
CORS(app, resources={
    r"/*": {
        "origins": ["http://your-frontend-url.com"],
        # ...
    }
})
```

**Issue 4: "Files too large"**
```bash
# Increase limit temporarily
export MAX_FILE_SIZE="524288000"  # 500MB
python server.py
```

**Issue 5: "Server keeps crashing"**
```bash
# Use auto-restart
python utils/auto_restart.py
# Will automatically restart on crashes
```

### Git Workflow for Teams

**1. Backend dev workflow:**
```bash
# Create feature branch
git checkout -b feature/new-endpoint

# Make changes
edit server.py

# Test
python test_integration.py

# Commit and push
git add .
git commit -m "Add new endpoint: /list"
git push origin feature/new-endpoint

# Merge via PR
```

**2. Frontend dev workflow:**
```bash
# Frontend team uses stable backend
# Point to deployed URL, not local
const API_URL = 'http://stable-backend.herokuapp.com';
```

**3. Shared environment variables:**
```bash
# Create .env file (add to .gitignore!)
echo "ENCRYPTION_KEY=shared-dev-key-1234567890" > .env
echo "SERVER_PORT=8080" >> .env

# Share with team via secure channel (not git!)
```

## Cloud Hosting for Hackathons

### Quick Deploy Options (Fastest to Slowest)

#### 1. Replit (Fastest - 2 minutes)

**Pros:** Instant deployment, free tier, browser-based IDE

**Steps:**
1. Go to https://replit.com
2. Click "Create Repl"
3. Choose "Import from GitHub"
4. Paste repository URL
5. Click "Run"

**URL:** `https://your-repl-name.your-username.repl.co`

**Secrets (environment variables):**
- Click "Secrets" icon (lock)
- Add `ENCRYPTION_KEY` with secure value

#### 2. Heroku (Easy - 10 minutes)

**Pros:** Free tier, automatic HTTPS, easy scaling

**Steps:**
```bash
# Install Heroku CLI
# https://devcenter.heroku.com/articles/heroku-cli

# Login
heroku login

# Create app
heroku create your-app-name

# Set config
heroku config:set ENCRYPTION_KEY=$(openssl rand -base64 16)

# Deploy
git push heroku main

# Open
heroku open
```

**URL:** `https://your-app-name.herokuapp.com`

**Logs:**
```bash
heroku logs --tail
```

#### 3. Railway (Easy - 10 minutes)

**Pros:** Free tier, GitHub integration, automatic deploys

**Steps:**
1. Go to https://railway.app
2. Click "New Project" → "Deploy from GitHub repo"
3. Select your repository
4. Add environment variables in Settings
5. Railway auto-deploys on every git push

**URL:** Auto-generated or custom domain

#### 4. DigitalOcean App Platform (Medium - 20 minutes)

**Pros:** $5/month, good performance, easy management

**Steps:**
1. Go to https://cloud.digitalocean.com/apps
2. Click "Create App"
3. Connect GitHub repository
4. Configure:
   - **Build Command:** (leave empty)
   - **Run Command:** `python server.py`
   - **HTTP Port:** 8080
5. Add environment variables
6. Deploy

**URL:** `https://your-app-random.ondigitalocean.app`

#### 5. AWS EC2 (Advanced - 30 minutes)

**Pros:** Full control, free tier (12 months), scalable

**Steps:**
```bash
# 1. Launch EC2 instance (Ubuntu 22.04)
# 2. SSH into instance
ssh -i your-key.pem ubuntu@your-ec2-ip

# 3. Setup
sudo apt update && sudo apt install python3-pip git -y
git clone <your-repo>
cd backend
pip3 install -r requirements.txt

# 4. Set environment
export ENCRYPTION_KEY=$(openssl rand -base64 16)

# 5. Run in background
nohup python3 server.py > server.log 2>&1 &
```

**URL:** `http://your-ec2-ip:8080`

**Security Group:** Allow inbound on port 8080

### Cloud Configuration Tips

#### Environment Variables by Platform

**Heroku:**
```bash
heroku config:set ENCRYPTION_KEY="your-key"
heroku config:set MAX_FILE_SIZE="104857600"
```

**Railway:**
- Go to project → Variables
- Add `ENCRYPTION_KEY`, `MAX_FILE_SIZE`, etc.

**DigitalOcean:**
- App Settings → Environment Variables
- Add key-value pairs

**AWS:**
```bash
# Store in Systems Manager Parameter Store
aws ssm put-parameter --name /file-transfer/encryption-key \
  --value "your-key" --type SecureString

# Retrieve in startup script
ENCRYPTION_KEY=$(aws ssm get-parameter --name /file-transfer/encryption-key \
  --with-decryption --query Parameter.Value --output text)
```

#### Port Configuration

**Dynamic Port (Heroku, Railway):**
```python
# In server.py, change:
if __name__ == '__main__':
    port = int(os.environ.get('PORT', SERVER_PORT))  # Use dynamic port
    app.run(host=SERVER_HOST, port=port, threaded=True)
```

**Fixed Port (EC2, DigitalOcean):**
- Keep `SERVER_PORT = 8080`
- Configure firewall to allow port 8080

#### CORS for Cloud Deployment

**Option 1: Allow specific domain**
```python
# In server.py
CORS(app, resources={
    r"/*": {
        "origins": [
            "https://your-frontend.com",
            "https://your-frontend.netlify.app",
            "http://localhost:3000"  # Local dev
        ],
        # ...
    }
})
```

**Option 2: Allow all (hackathon only!)**
```python
CORS(app)  # Allows all origins
```

#### File Persistence

**Problem:** Cloud platforms may not persist uploaded files across restarts

**Solutions:**

**1. Use cloud storage (recommended):**
```bash
# AWS S3
pip install boto3
```

```python
import boto3

s3 = boto3.client('s3')

# Upload to S3 instead of local storage
s3.upload_file('local_file.txt', 'bucket-name', 'remote_file.txt')

# Download from S3
s3.download_file('bucket-name', 'remote_file.txt', 'local_file.txt')
```

**2. Use volume mounting (DigitalOcean, AWS):**
```bash
# Mount persistent volume
sudo mkdir /mnt/storage
sudo mount /dev/vdb /mnt/storage

# Set UPLOAD_DIR
export UPLOAD_DIR="/mnt/storage"
```

**3. Use database for small files (Heroku):**
```bash
pip install psycopg2-binary
```

```python
# Store files in PostgreSQL BYTEA column
import psycopg2

conn = psycopg2.connect(os.environ['DATABASE_URL'])
cur = conn.cursor()

# Store file
with open('file.txt', 'rb') as f:
    cur.execute("INSERT INTO files (name, data) VALUES (%s, %s)",
                ('file.txt', f.read()))
conn.commit()
```

### Monitoring Your Cloud Deployment

**Health check monitoring:**
```bash
# Use cron or monitoring service
*/5 * * * * curl https://your-app.com/health || echo "Server down!"
```

**Uptime monitoring services:**
- **UptimeRobot** (free): https://uptimerobot.com
- **Pingdom** (free tier): https://www.pingdom.com
- **StatusCake** (free tier): https://www.statuscake.com

**Log monitoring:**
```bash
# Heroku
heroku logs --tail

# Railway
railway logs

# AWS CloudWatch
aws logs tail /aws/ec2/file-transfer --follow
```

### Cost Optimization

**Free Tier Options:**
- **Heroku:** 550 hours/month (1 dyno always on)
- **Railway:** $5 credit/month (~700 hours)
- **AWS:** 750 hours/month (12 months)
- **DigitalOcean:** $200 credit for 60 days (new users)
- **Replit:** Always free (with limitations)

**Paid Recommendations (Hackathon Scale):**
- **Heroku Hobby:** $7/month (always on, custom domain)
- **Railway Pro:** $5/month (better resources)
- **DigitalOcean Droplet:** $6/month (1GB RAM)

## Development

### Project Structure

```
backend/
├── server.py                 # Main API server
│   └── Routes: /upload, /download, /status, /health
├── client.py                 # CLI client
│   └── Commands: upload, download, status, health
├── config.py                 # Configuration
│   └── Validates on import
├── utils/
│   ├── hash_util.py         # SHA-256 checksums
│   │   └── file_checksum(path) -> str
│   ├── encrypt_util.py      # AES-128-EAX encryption
│   │   ├── encrypt_data(data, key) -> (nonce, ciphertext, tag)
│   │   └── decrypt_data(nonce, ciphertext, tag, key) -> plaintext
│   ├── status_handler.py    # Status tracking
│   │   ├── update_status(filename, status, ...)
│   │   ├── get_status(filename) -> dict
│   │   └── get_all_status() -> dict
│   └── auto_restart.py      # Process monitoring
│       └── monitor_server(script, interval=5)
└── test_integration.py      # Integration tests
    └── IntegrationTest.run_all_tests()
```

### Adding New Features

1. **Add endpoint in server.py:**
   ```python
   @app.route('/new_endpoint', methods=['GET'])
   def new_endpoint():
       # Implementation
       return jsonify({'result': 'data'}), 200
   ```

2. **Add client command in client.py:**
   ```python
   # In argparse section
   new_parser = subparsers.add_parser('new_command')
   
   # In main section
   elif args.command == 'new_command':
       new_command_function()
   ```

3. **Add tests in test_integration.py:**
   ```python
   def test_new_feature(self):
       self.print_test("New Feature Test")
       # Test implementation
   ```

### Code Style

- Follow PEP 8
- Docstrings for all functions/classes
- Type hints where appropriate
- Comprehensive error handling
- Logging for debugging

## License

MIT License - see LICENSE file for details.

## Support

For issues, questions, or contributions, please open an issue or submit a pull request.

## Changelog

### v3.0.0 (2024-10-25)
- 🆕 **WebSocket Real-Time Notifications** - Live updates via WebSocket connections
- 🆕 **Batch File Operations** - Upload/download multiple files in one request
- 🆕 **Transfer Cancellation** - Cancel ongoing transfers mid-upload
- 🆕 **File Metadata & Thumbnails** - Rich file information with image thumbnails
- 🆕 **Transfer History** - Filterable transfer history with date and client filters
- 🆕 **API Key Authentication** - Secure access with API key authentication
- 🆕 **Transfer Statistics** - Comprehensive analytics and performance metrics
- 🆕 **Enhanced Client CLI** - New commands for batch operations, cancellation, history, stats, and metadata
- 🆕 **New API Endpoints** - `/upload_batch`, `/download_batch`, `/cancel`, `/metadata`, `/thumbnail`, `/history`, `/stats`, `/generate_key`
- 🆕 **Comprehensive Testing** - Updated test suite for all new features

### v2.0.0 (2024-10-25)
- 🆕 **Live Progress Tracking** - Real-time upload/download progress with speed and ETA
- 🆕 **Chunked Upload/Download** - Break large files into chunks with resume capability
- 🆕 **Automatic Retry** - Exponential backoff retry logic for failed transfers
- 🆕 **Multi-Client Tracking** - Track which client uploaded/downloaded each file
- 🆕 **Network Health Monitoring** - Detect unstable connections and adapt transfer strategy
- 🆕 **Speed Tracking** - Display transfer speed in MB/s with network quality assessment
- 🆕 **Queue Persistence** - Transfer queue survives server restarts
- 🆕 **New API Endpoints** - `/upload_chunk`, `/resume_info`, `/clients`, `/ping`
- 🆕 **Enhanced CLI** - New options for retry, chunked upload, and progress tracking
- 🆕 **Comprehensive Testing** - Updated test suite for all new features

### v1.0.0 (2024-10-24)
- Initial release
- File upload/download with encryption
- Status tracking and queue management
- CLI client
- Auto-restart monitor
- Comprehensive test suite
