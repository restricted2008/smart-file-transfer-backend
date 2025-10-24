"""
client.py
CLI client for Smart File Transfer Server.
Provides commands for uploading, downloading, and checking file transfer status.

USAGE:
    Upload a file:
        python client.py upload <file_path> [--encrypt] [--priority N] [--filename NAME]
    
    Check all transfer status:
        python client.py status
    
    Check specific file status:
        python client.py status --file <filename>
    
    Download a file:
        python client.py download <filename> [--output <path>] [--no-decrypt]
    
    Health check:
        python client.py health

EXAMPLES:
    # Upload with encryption and priority
    python client.py upload document.pdf --encrypt --priority 5
    
    # Upload with custom filename
    python client.py upload data.csv --filename report.csv
    
    # Check all transfers
    python client.py status
    
    # Check specific file
    python client.py status --file document.pdf
    
    # Download file
    python client.py download document.pdf --output ./downloads/
    
    # Download encrypted file without decryption
    python client.py download secret.txt --no-decrypt

OPTIONS:
    --encrypt           Encrypt file during upload (AES-128-EAX)
    --priority N        Set transfer priority (0-10, default: 0)
    --filename NAME     Custom filename on server
    --file NAME         Specific filename to query
    --output PATH       Output directory for download (default: current dir)
    --no-decrypt        Download encrypted file without decryption
    --server HOST       Server host (default: from config)
    --port PORT         Server port (default: from config)
    --help              Show this help message
"""

import argparse
import requests
import os
import sys
import json
from datetime import datetime
from config import SERVER_HOST, SERVER_PORT


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_success(message):
    """Print success message in green."""
    print(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")


def print_error(message):
    """Print error message in red."""
    print(f"{Colors.FAIL}✗ {message}{Colors.ENDC}")


def print_warning(message):
    """Print warning message in yellow."""
    print(f"{Colors.WARNING}⚠ {message}{Colors.ENDC}")


def print_info(message):
    """Print info message in cyan."""
    print(f"{Colors.OKCYAN}ℹ {message}{Colors.ENDC}")


def format_size(size_bytes):
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def format_timestamp(iso_timestamp):
    """Format ISO timestamp to readable format."""
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return iso_timestamp


def upload_file(file_path, encrypt=False, priority=0, filename=None, server_host=None, server_port=None):
    """
    Upload a file to the server.
    
    Args:
        file_path (str): Path to file to upload
        encrypt (bool): Enable encryption
        priority (int): Transfer priority
        filename (str): Custom filename
        server_host (str): Server host
        server_port (int): Server port
    """
    host = server_host or SERVER_HOST
    port = server_port or SERVER_PORT
    url = f"http://{host}:{port}/upload"
    
    # Check if file exists
    if not os.path.exists(file_path):
        print_error(f"File not found: {file_path}")
        return False
    
    # Check if file is readable
    if not os.access(file_path, os.R_OK):
        print_error(f"Permission denied: Cannot read {file_path}")
        return False
    
    file_size = os.path.getsize(file_path)
    print_info(f"Uploading: {file_path} ({format_size(file_size)})")
    
    if encrypt:
        print_info("Encryption: Enabled (AES-128-EAX)")
    if priority > 0:
        print_info(f"Priority: {priority}")
    
    try:
        # Prepare file and form data
        with open(file_path, 'rb') as f:
            files = {'file': f}
            data = {
                'encryption': 'true' if encrypt else 'false',
                'priority': str(priority)
            }
            
            if filename:
                data['filename'] = filename
            
            # Send POST request
            print_info(f"Connecting to {url}...")
            response = requests.post(url, files=files, data=data, timeout=30)
        
        # Handle response
        if response.status_code == 200:
            result = response.json()
            
            print_success("Upload successful!")
            print(f"\n{Colors.BOLD}Upload Details:{Colors.ENDC}")
            print(f"  Filename:    {result.get('filename')}")
            print(f"  Hash:        {result.get('hash')}")
            print(f"  Size:        {format_size(result.get('size', 0))}")
            print(f"  Status:      {result.get('status')}")
            print(f"  Encryption:  {'Yes' if result.get('encryption') else 'No'}")
            print(f"  Priority:    {result.get('priority')}")
            
            if result.get('nonce'):
                print(f"  Nonce:       {result.get('nonce')[:32]}...")
            if result.get('tag'):
                print(f"  Tag:         {result.get('tag')[:32]}...")
            
            return True
        
        elif response.status_code == 413:
            print_error("File too large!")
            error_data = response.json()
            print_error(error_data.get('error', 'Maximum file size exceeded'))
            print_info("Try uploading a smaller file or contact the administrator.")
            return False
        
        elif response.status_code == 400:
            print_error("Bad request")
            error_data = response.json()
            print_error(error_data.get('error', 'Invalid request parameters'))
            print_info("Check your file and parameters, then try again.")
            return False
        
        else:
            print_error(f"Upload failed with status code: {response.status_code}")
            try:
                error_data = response.json()
                print_error(error_data.get('error', 'Unknown error'))
            except Exception:
                print_error(response.text)
            return False
    
    except requests.exceptions.ConnectionError:
        print_error("Connection failed")
        print_error(f"Cannot connect to server at {host}:{port}")
        print_info("Make sure the server is running and the address is correct.")
        print_info(f"Try: python server.py")
        return False
    
    except requests.exceptions.Timeout:
        print_error("Request timeout")
        print_error("Server took too long to respond.")
        print_info("Try again or check your network connection.")
        return False
    
    except Exception as e:
        print_error(f"Upload error: {str(e)}")
        return False


def get_status(filename=None, server_host=None, server_port=None):
    """
    Get transfer status for a specific file or all files.
    
    Args:
        filename (str): Specific filename to query (optional)
        server_host (str): Server host
        server_port (int): Server port
    """
    host = server_host or SERVER_HOST
    port = server_port or SERVER_PORT
    
    if filename:
        url = f"http://{host}:{port}/status/{filename}"
        print_info(f"Fetching status for: {filename}")
    else:
        url = f"http://{host}:{port}/status"
        print_info("Fetching all transfer status...")
    
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if filename:
                # Single file status
                print_success(f"Status retrieved for: {filename}")
                print(f"\n{Colors.BOLD}File Details:{Colors.ENDC}")
                print(f"  Filename:    {data.get('filename')}")
                print(f"  Status:      {data.get('status')}")
                print(f"  Checksum:    {data.get('checksum', 'N/A')}")
                print(f"  Encryption:  {'Yes' if data.get('encryption') else 'No'}")
                print(f"  Priority:    {data.get('priority', 0)}")
                print(f"  Created:     {format_timestamp(data.get('created_at', 'N/A'))}")
                print(f"  Updated:     {format_timestamp(data.get('updated_at', 'N/A'))}")
            else:
                # All transfers
                transfers = data.get('transfers', [])
                queue = data.get('queue', [])
                metadata = data.get('metadata', {})
                
                print_success(f"Retrieved {len(transfers)} transfer(s)")
                
                if transfers:
                    print(f"\n{Colors.BOLD}Transfer Status Table:{Colors.ENDC}")
                    print("─" * 120)
                    print(f"{'Filename':<30} {'Status':<12} {'Encryption':<12} {'Priority':<10} {'Updated':<20}")
                    print("─" * 120)
                    
                    for transfer in transfers:
                        filename_str = transfer.get('filename', 'N/A')[:28]
                        status_str = transfer.get('status', 'N/A')[:10]
                        encrypt_str = 'Yes' if transfer.get('encryption') else 'No'
                        priority_str = str(transfer.get('priority', 0))
                        updated_str = format_timestamp(transfer.get('updated_at', 'N/A'))[:18]
                        
                        print(f"{filename_str:<30} {status_str:<12} {encrypt_str:<12} {priority_str:<10} {updated_str:<20}")
                    
                    print("─" * 120)
                else:
                    print_info("No transfers found.")
                
                if queue:
                    print(f"\n{Colors.BOLD}Queue ({len(queue)} item(s)):{Colors.ENDC}")
                    for item in queue:
                        print(f"  - {item.get('filename')} (priority: {item.get('priority', 0)})")
                
                print(f"\n{Colors.BOLD}Metadata:{Colors.ENDC}")
                print(f"  Total Transfers: {metadata.get('total_transfers', 0)}")
                print(f"  Last Updated:    {format_timestamp(metadata.get('last_updated', 'N/A'))}")
            
            return True
        
        elif response.status_code == 404:
            print_error(f"File not found: {filename}")
            print_info("Use 'status' without --file to see all available files.")
            return False
        
        else:
            print_error(f"Request failed with status code: {response.status_code}")
            try:
                error_data = response.json()
                print_error(error_data.get('error', 'Unknown error'))
            except Exception:
                print_error(response.text)
            return False
    
    except requests.exceptions.ConnectionError:
        print_error("Connection failed")
        print_error(f"Cannot connect to server at {host}:{port}")
        print_info("Make sure the server is running.")
        return False
    
    except Exception as e:
        print_error(f"Status check error: {str(e)}")
        return False


def download_file(filename, output_path='.', decrypt=True, server_host=None, server_port=None):
    """
    Download a file from the server.
    
    Args:
        filename (str): Name of file to download
        output_path (str): Output directory or file path
        decrypt (bool): Decrypt encrypted files
        server_host (str): Server host
        server_port (int): Server port
    """
    host = server_host or SERVER_HOST
    port = server_port or SERVER_PORT
    
    # Build URL with decrypt parameter
    url = f"http://{host}:{port}/download/{filename}"
    if not decrypt:
        url += "?decrypt=false"
    
    print_info(f"Downloading: {filename}")
    if not decrypt:
        print_info("Decryption: Disabled (downloading encrypted file)")
    
    try:
        response = requests.get(url, timeout=30, stream=True)
        
        if response.status_code == 200:
            # Determine output file path
            if os.path.isdir(output_path):
                output_file = os.path.join(output_path, filename)
            else:
                output_file = output_path
            
            # Download file
            file_size = int(response.headers.get('Content-Length', 0))
            
            with open(output_file, 'wb') as f:
                if file_size > 0:
                    downloaded = 0
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            # Simple progress indicator
                            progress = (downloaded / file_size) * 100
                            print(f"\rProgress: {progress:.1f}%", end='', flush=True)
                    print()  # New line after progress
                else:
                    f.write(response.content)
            
            print_success(f"Downloaded: {output_file}")
            print(f"  Size: {format_size(os.path.getsize(output_file))}")
            return True
        
        elif response.status_code == 404:
            print_error(f"File not found: {filename}")
            print_info("Use 'status' to see available files.")
            return False
        
        elif response.status_code == 403:
            print_error("Permission denied")
            print_error("You don't have permission to download this file.")
            return False
        
        else:
            print_error(f"Download failed with status code: {response.status_code}")
            try:
                error_data = response.json()
                print_error(error_data.get('error', 'Unknown error'))
            except Exception:
                print_error(response.text)
            return False
    
    except requests.exceptions.ConnectionError:
        print_error("Connection failed")
        print_error(f"Cannot connect to server at {host}:{port}")
        return False
    
    except Exception as e:
        print_error(f"Download error: {str(e)}")
        return False


def health_check(server_host=None, server_port=None):
    """
    Check server health.
    
    Args:
        server_host (str): Server host
        server_port (int): Server port
    """
    host = server_host or SERVER_HOST
    port = server_port or SERVER_PORT
    url = f"http://{host}:{port}/health"
    
    print_info(f"Checking server health at {host}:{port}...")
    
    try:
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            print_success("Server is healthy!")
            print(f"  Status:    {data.get('status')}")
            print(f"  Timestamp: {format_timestamp(data.get('timestamp', 'N/A'))}")
            return True
        else:
            print_error(f"Health check failed with status code: {response.status_code}")
            return False
    
    except requests.exceptions.ConnectionError:
        print_error("Server is unreachable")
        print_error(f"Cannot connect to {host}:{port}")
        print_info("Make sure the server is running.")
        return False
    
    except Exception as e:
        print_error(f"Health check error: {str(e)}")
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Smart File Transfer Client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='For detailed usage information, see the file header docstring.'
    )
    
    # Global options
    parser.add_argument('--server', help='Server host (default: from config)', default=None)
    parser.add_argument('--port', type=int, help='Server port (default: from config)', default=None)
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Upload command
    upload_parser = subparsers.add_parser('upload', help='Upload a file to the server')
    upload_parser.add_argument('file', help='Path to file to upload')
    upload_parser.add_argument('--encrypt', action='store_true', help='Encrypt file during upload')
    upload_parser.add_argument('--priority', type=int, default=0, help='Transfer priority (0-10)')
    upload_parser.add_argument('--filename', help='Custom filename on server')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Check transfer status')
    status_parser.add_argument('--file', help='Specific filename to query (optional)', default=None)
    
    # Download command
    download_parser = subparsers.add_parser('download', help='Download a file from the server')
    download_parser.add_argument('filename', help='Name of file to download')
    download_parser.add_argument('--output', help='Output directory or file path', default='.')
    download_parser.add_argument('--no-decrypt', action='store_true', help='Download without decryption')
    
    # Health check command
    health_parser = subparsers.add_parser('health', help='Check server health')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    # Execute command
    success = False
    
    if args.command == 'upload':
        success = upload_file(
            args.file,
            encrypt=args.encrypt,
            priority=args.priority,
            filename=args.filename,
            server_host=args.server,
            server_port=args.port
        )
    
    elif args.command == 'status':
        success = get_status(
            filename=args.file,
            server_host=args.server,
            server_port=args.port
        )
    
    elif args.command == 'download':
        success = download_file(
            args.filename,
            output_path=args.output,
            decrypt=not args.no_decrypt,
            server_host=args.server,
            server_port=args.port
        )
    
    elif args.command == 'health':
        success = health_check(
            server_host=args.server,
            server_port=args.port
        )
    
    sys.exit(0 if success else 1)
