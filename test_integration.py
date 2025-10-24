"""
test_integration.py
Integration tests for Smart File Transfer Server.
Tests all endpoints with valid/invalid requests, error handling, and edge cases.

USAGE:
    1. Start the server: python server.py
    2. Run tests: python test_integration.py
    
    Or run both automatically:
    python test_integration.py --auto-start

REQUIREMENTS:
    - Server must be running (or use --auto-start)
    - All dependencies installed: pip install -r requirements.txt
"""

import requests
import tempfile
import os
import sys
import time
import subprocess
import json
from datetime import datetime


class TestColors:
    """ANSI color codes for test output."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'


class IntegrationTest:
    """Integration test suite for file transfer server."""
    
    def __init__(self, base_url='http://localhost:8080'):
        self.base_url = base_url
        self.passed = 0
        self.failed = 0
        self.warnings = 0
    
    def print_test(self, name):
        """Print test name."""
        print(f"\n{TestColors.BOLD}[TEST] {name}{TestColors.ENDC}")
    
    def print_pass(self, message):
        """Print pass message."""
        print(f"{TestColors.GREEN}✓ PASS: {message}{TestColors.ENDC}")
        self.passed += 1
    
    def print_fail(self, message):
        """Print fail message."""
        print(f"{TestColors.RED}✗ FAIL: {message}{TestColors.ENDC}")
        self.failed += 1
    
    def print_warn(self, message):
        """Print warning message."""
        print(f"{TestColors.YELLOW}⚠ WARN: {message}{TestColors.ENDC}")
        self.warnings += 1
    
    def print_info(self, message):
        """Print info message."""
        print(f"{TestColors.CYAN}ℹ {message}{TestColors.ENDC}")
    
    def check_server_health(self):
        """Check if server is running."""
        self.print_test("Health Check")
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'ok':
                    self.print_pass("Server is healthy")
                    return True
                else:
                    self.print_fail(f"Server status: {data.get('status')}")
                    return False
            else:
                self.print_fail(f"Health check returned {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            self.print_fail("Cannot connect to server")
            return False
        except Exception as e:
            self.print_fail(f"Health check error: {e}")
            return False
    
    def test_upload_valid_file(self):
        """Test valid file upload."""
        self.print_test("Upload Valid File")
        
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Hello, this is a test file!")
            temp_file = f.name
        
        try:
            with open(temp_file, 'rb') as f:
                files = {'file': f}
                data = {'priority': '3'}
                response = requests.post(f"{self.base_url}/upload", files=files, data=data)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    self.print_pass(f"File uploaded: {result.get('filename')}")
                    self.print_info(f"Hash: {result.get('hash')}")
                    self.print_info(f"Size: {result.get('size')} bytes")
                    return True
                else:
                    self.print_fail(f"Upload failed: {result.get('error')}")
                    return False
            else:
                self.print_fail(f"Upload returned {response.status_code}")
                return False
        
        except Exception as e:
            self.print_fail(f"Upload error: {e}")
            return False
        finally:
            os.remove(temp_file)
    
    def test_upload_with_encryption(self):
        """Test file upload with encryption."""
        self.print_test("Upload File with Encryption")
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Encrypted secret message!")
            temp_file = f.name
        
        try:
            with open(temp_file, 'rb') as f:
                files = {'file': f}
                data = {'encryption': 'true', 'priority': '5'}
                response = requests.post(f"{self.base_url}/upload", files=files, data=data)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('encryption') and result.get('nonce') and result.get('tag'):
                    self.print_pass("File encrypted and uploaded")
                    self.print_info(f"Nonce: {result.get('nonce')[:32]}...")
                    self.print_info(f"Tag: {result.get('tag')[:32]}...")
                    return True
                else:
                    self.print_fail("Encryption metadata missing")
                    return False
            else:
                self.print_fail(f"Upload returned {response.status_code}")
                return False
        
        except Exception as e:
            self.print_fail(f"Upload error: {e}")
            return False
        finally:
            os.remove(temp_file)
    
    def test_upload_missing_file(self):
        """Test upload without file."""
        self.print_test("Upload Missing File (400 Expected)")
        
        try:
            response = requests.post(f"{self.base_url}/upload", data={'priority': '1'})
            
            if response.status_code == 400:
                result = response.json()
                if 'error' in result and not result.get('success', True):
                    self.print_pass("400 error correctly returned with JSON")
                    self.print_info(f"Error message: {result.get('error')}")
                    return True
                else:
                    self.print_fail("Error response not properly formatted")
                    return False
            else:
                self.print_fail(f"Expected 400, got {response.status_code}")
                return False
        
        except Exception as e:
            self.print_fail(f"Test error: {e}")
            return False
    
    def test_upload_large_file(self):
        """Test large file upload (should fail with 413)."""
        self.print_test("Upload Large File (413 Expected)")
        
        # Create file larger than 100MB
        large_size = 101 * 1024 * 1024  # 101 MB
        
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            # Write in chunks to avoid memory issues
            chunk = b'A' * (1024 * 1024)  # 1 MB chunk
            for _ in range(101):
                f.write(chunk)
            temp_file = f.name
        
        try:
            self.print_info(f"Uploading {large_size / (1024*1024):.2f} MB file...")
            
            with open(temp_file, 'rb') as f:
                files = {'file': f}
                response = requests.post(f"{self.base_url}/upload", files=files, timeout=60)
            
            if response.status_code == 413:
                result = response.json()
                if 'error' in result:
                    self.print_pass("413 error correctly returned")
                    self.print_info(f"Error message: {result.get('error')}")
                    return True
                else:
                    self.print_fail("413 response not properly formatted")
                    return False
            else:
                self.print_warn(f"Expected 413, got {response.status_code}")
                return False
        
        except Exception as e:
            self.print_fail(f"Test error: {e}")
            return False
        finally:
            os.remove(temp_file)
    
    def test_get_all_status(self):
        """Test getting all transfer status."""
        self.print_test("Get All Status")
        
        try:
            response = requests.get(f"{self.base_url}/status")
            
            if response.status_code == 200:
                result = response.json()
                if 'transfers' in result and 'queue' in result and 'metadata' in result:
                    self.print_pass("Status retrieved successfully")
                    self.print_info(f"Total transfers: {len(result['transfers'])}")
                    self.print_info(f"Queue length: {len(result['queue'])}")
                    return True
                else:
                    self.print_fail("Status response missing required fields")
                    return False
            else:
                self.print_fail(f"Status returned {response.status_code}")
                return False
        
        except Exception as e:
            self.print_fail(f"Test error: {e}")
            return False
    
    def test_get_file_status(self):
        """Test getting specific file status."""
        self.print_test("Get Specific File Status")
        
        # First upload a file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Status test file")
            temp_file = f.name
        
        try:
            # Upload file
            with open(temp_file, 'rb') as f:
                files = {'file': f}
                data = {'filename': 'status_test.txt'}
                upload_response = requests.post(f"{self.base_url}/upload", files=files, data=data)
            
            if upload_response.status_code != 200:
                self.print_fail("Failed to upload test file")
                return False
            
            # Get status
            response = requests.get(f"{self.base_url}/status/status_test.txt")
            
            if response.status_code == 200:
                result = response.json()
                if 'filename' in result and 'status' in result:
                    self.print_pass(f"Status retrieved for status_test.txt")
                    self.print_info(f"Status: {result.get('status')}")
                    return True
                else:
                    self.print_fail("Status response missing fields")
                    return False
            else:
                self.print_fail(f"Status returned {response.status_code}")
                return False
        
        except Exception as e:
            self.print_fail(f"Test error: {e}")
            return False
        finally:
            os.remove(temp_file)
    
    def test_get_nonexistent_file_status(self):
        """Test getting status for nonexistent file (404 expected)."""
        self.print_test("Get Nonexistent File Status (404 Expected)")
        
        try:
            response = requests.get(f"{self.base_url}/status/nonexistent_file_xyz.txt")
            
            if response.status_code == 404:
                result = response.json()
                if 'error' in result:
                    self.print_pass("404 error correctly returned")
                    self.print_info(f"Error message: {result.get('error')}")
                    return True
                else:
                    self.print_fail("404 response not properly formatted")
                    return False
            else:
                self.print_fail(f"Expected 404, got {response.status_code}")
                return False
        
        except Exception as e:
            self.print_fail(f"Test error: {e}")
            return False
    
    def test_download_file(self):
        """Test file download."""
        self.print_test("Download File")
        
        # First upload a file
        test_content = "Download test content!"
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(test_content)
            temp_file = f.name
        
        try:
            # Upload file
            with open(temp_file, 'rb') as f:
                files = {'file': f}
                data = {'filename': 'download_test.txt'}
                upload_response = requests.post(f"{self.base_url}/upload", files=files, data=data)
            
            if upload_response.status_code != 200:
                self.print_fail("Failed to upload test file")
                return False
            
            # Download file
            response = requests.get(f"{self.base_url}/download/download_test.txt")
            
            if response.status_code == 200:
                downloaded_content = response.content.decode('utf-8')
                if downloaded_content == test_content:
                    self.print_pass("File downloaded successfully with correct content")
                    return True
                else:
                    self.print_fail("Downloaded content doesn't match original")
                    return False
            else:
                self.print_fail(f"Download returned {response.status_code}")
                return False
        
        except Exception as e:
            self.print_fail(f"Test error: {e}")
            return False
        finally:
            os.remove(temp_file)
    
    def test_download_encrypted_file(self):
        """Test download of encrypted file with decryption."""
        self.print_test("Download Encrypted File")
        
        test_content = "Secret encrypted message!"
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(test_content)
            temp_file = f.name
        
        try:
            # Upload encrypted file
            with open(temp_file, 'rb') as f:
                files = {'file': f}
                data = {'filename': 'encrypted_download_test.txt', 'encryption': 'true'}
                upload_response = requests.post(f"{self.base_url}/upload", files=files, data=data)
            
            if upload_response.status_code != 200:
                self.print_fail("Failed to upload encrypted file")
                return False
            
            # Download with decryption
            response = requests.get(f"{self.base_url}/download/encrypted_download_test.txt?decrypt=true")
            
            if response.status_code == 200:
                downloaded_content = response.content.decode('utf-8')
                if downloaded_content == test_content:
                    self.print_pass("Encrypted file downloaded and decrypted successfully")
                    return True
                else:
                    self.print_fail("Decrypted content doesn't match original")
                    self.print_info(f"Expected: {test_content}")
                    self.print_info(f"Got: {downloaded_content}")
                    return False
            else:
                self.print_fail(f"Download returned {response.status_code}")
                return False
        
        except Exception as e:
            self.print_fail(f"Test error: {e}")
            return False
        finally:
            os.remove(temp_file)
    
    def test_download_nonexistent_file(self):
        """Test download nonexistent file (404 expected)."""
        self.print_test("Download Nonexistent File (404 Expected)")
        
        try:
            response = requests.get(f"{self.base_url}/download/nonexistent_xyz.txt")
            
            if response.status_code == 404:
                result = response.json()
                if 'error' in result:
                    self.print_pass("404 error correctly returned")
                    self.print_info(f"Error message: {result.get('error')}")
                    return True
                else:
                    self.print_fail("404 response not properly formatted")
                    return False
            else:
                self.print_fail(f"Expected 404, got {response.status_code}")
                return False
        
        except Exception as e:
            self.print_fail(f"Test error: {e}")
            return False
    
    def test_invalid_endpoint(self):
        """Test invalid endpoint (404 expected)."""
        self.print_test("Invalid Endpoint (404 Expected)")
        
        try:
            response = requests.get(f"{self.base_url}/invalid_endpoint_xyz")
            
            if response.status_code == 404:
                result = response.json()
                if 'error' in result:
                    self.print_pass("404 error for invalid endpoint")
                    return True
                else:
                    self.print_fail("404 response not JSON formatted")
                    return False
            else:
                self.print_fail(f"Expected 404, got {response.status_code}")
                return False
        
        except Exception as e:
            self.print_fail(f"Test error: {e}")
            return False
    
    def run_all_tests(self):
        """Run all integration tests."""
        print(f"\n{TestColors.BOLD}{'='*70}{TestColors.ENDC}")
        print(f"{TestColors.BOLD}Smart File Transfer Server - Integration Tests{TestColors.ENDC}")
        print(f"{TestColors.BOLD}{'='*70}{TestColors.ENDC}")
        
        # Check server health first
        if not self.check_server_health():
            self.print_fail("Server is not running. Please start the server first.")
            return False
        
        # Run all tests
        tests = [
            self.test_upload_valid_file,
            self.test_upload_with_encryption,
            self.test_upload_missing_file,
            self.test_get_all_status,
            self.test_get_file_status,
            self.test_get_nonexistent_file_status,
            self.test_download_file,
            self.test_download_encrypted_file,
            self.test_download_nonexistent_file,
            self.test_invalid_endpoint,
            # Skip large file test by default (too slow)
            # self.test_upload_large_file,
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                self.print_fail(f"Unexpected error in {test.__name__}: {e}")
        
        # Print summary
        print(f"\n{TestColors.BOLD}{'='*70}{TestColors.ENDC}")
        print(f"{TestColors.BOLD}Test Summary{TestColors.ENDC}")
        print(f"{TestColors.BOLD}{'='*70}{TestColors.ENDC}")
        print(f"{TestColors.GREEN}Passed:  {self.passed}{TestColors.ENDC}")
        print(f"{TestColors.RED}Failed:  {self.failed}{TestColors.ENDC}")
        print(f"{TestColors.YELLOW}Warnings: {self.warnings}{TestColors.ENDC}")
        print(f"Total:   {self.passed + self.failed}")
        
        success_rate = (self.passed / (self.passed + self.failed) * 100) if (self.passed + self.failed) > 0 else 0
        print(f"\nSuccess Rate: {success_rate:.1f}%")
        
        if self.failed == 0:
            print(f"\n{TestColors.GREEN}{TestColors.BOLD}✓ All tests passed!{TestColors.ENDC}")
            return True
        else:
            print(f"\n{TestColors.RED}{TestColors.BOLD}✗ Some tests failed.{TestColors.ENDC}")
            return False


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Integration tests for Smart File Transfer Server')
    parser.add_argument('--url', default='http://localhost:8080', help='Server URL')
    parser.add_argument('--auto-start', action='store_true', help='Auto-start server before testing')
    
    args = parser.parse_args()
    
    server_process = None
    
    try:
        # Auto-start server if requested
        if args.auto_start:
            print("Starting server...")
            server_process = subprocess.Popen(
                [sys.executable, 'server.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            print("Waiting for server to start...")
            time.sleep(3)
        
        # Run tests
        tester = IntegrationTest(base_url=args.url)
        success = tester.run_all_tests()
        
        sys.exit(0 if success else 1)
    
    finally:
        if server_process:
            print("\nShutting down server...")
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()
