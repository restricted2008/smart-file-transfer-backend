"""
hash_util.py
SHA-256 hash and checksum utility for file integrity verification.
"""

import hashlib
import os


def calculate_hash(file_path, algorithm='sha256', chunk_size=8192):
    """
    Calculate hash of a file using specified algorithm.
    
    Args:
        file_path (str): Path to the file
        algorithm (str): Hash algorithm (default: sha256)
        chunk_size (int): Size of chunks to read (default: 8192 bytes)
    
    Returns:
        str: Hexadecimal hash string
    """
    hash_obj = hashlib.new(algorithm)
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")
    except Exception as e:
        raise Exception(f"Error calculating hash: {str(e)}")


def verify_hash(file_path, expected_hash, algorithm='sha256'):
    """
    Verify file hash matches expected hash.
    
    Args:
        file_path (str): Path to the file
        expected_hash (str): Expected hash value
        algorithm (str): Hash algorithm (default: sha256)
    
    Returns:
        bool: True if hash matches, False otherwise
    """
    actual_hash = calculate_hash(file_path, algorithm)
    return actual_hash.lower() == expected_hash.lower()


def calculate_string_hash(data, algorithm='sha256'):
    """
    Calculate hash of a string or bytes.
    
    Args:
        data (str|bytes): Data to hash
        algorithm (str): Hash algorithm (default: sha256)
    
    Returns:
        str: Hexadecimal hash string
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(data)
    return hash_obj.hexdigest()


def file_checksum(path):
    """
    Compute SHA-256 checksum of a file with robust error handling.
    Reads file in 4096-byte chunks for memory efficiency.
    
    Args:
        path (str): Path to the file to checksum
    
    Returns:
        str: SHA-256 checksum as hexadecimal string, or None on error
    
    Logs:
        - FileNotFoundError: File does not exist
        - PermissionError: Insufficient permissions to read file
        - IOError: General I/O errors during reading
    """
    try:
        sha256_hash = hashlib.sha256()
        
        with open(path, 'rb') as f:
            # Read in 4096-byte chunks
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha256_hash.update(chunk)
        
        checksum = sha256_hash.hexdigest()
        print(f"[INFO] Checksum computed for '{path}': {checksum}")
        return checksum
    
    except FileNotFoundError:
        print(f"[ERROR] File not found: '{path}'")
        return None
    
    except PermissionError:
        print(f"[ERROR] Permission denied: Cannot read '{path}'")
        return None
    
    except IOError as e:
        print(f"[ERROR] I/O error reading '{path}': {e}")
        return None
    
    except Exception as e:
        print(f"[ERROR] Unexpected error processing '{path}': {e}")
        return None


if __name__ == '__main__':
    """
    CLI test block for hash utility functions.
    Tests file_checksum with various scenarios.
    """
    import tempfile
    import sys
    
    print("\n=== Hash Utility Test Suite ===")
    print("\nTest 1: Create temporary file and compute checksum")
    
    # Test 1: Normal file checksum
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp:
        test_file = tmp.name
        test_content = b"Hello, this is a test file for checksum validation!"
        tmp.write(test_content)
    
    print(f"Created test file: {test_file}")
    checksum1 = file_checksum(test_file)
    
    if checksum1:
        print(f"✓ Test 1 PASSED - Checksum: {checksum1}")
    else:
        print("✗ Test 1 FAILED")
    
    # Test 2: Verify checksum consistency (same file, same checksum)
    print("\nTest 2: Verify checksum consistency")
    checksum2 = file_checksum(test_file)
    
    if checksum1 == checksum2:
        print(f"✓ Test 2 PASSED - Checksums match")
    else:
        print(f"✗ Test 2 FAILED - Checksums don't match")
    
    # Test 3: Non-existent file
    print("\nTest 3: Non-existent file handling")
    checksum3 = file_checksum('nonexistent_file_xyz_123.txt')
    
    if checksum3 is None:
        print("✓ Test 3 PASSED - Properly handled missing file")
    else:
        print("✗ Test 3 FAILED - Should return None for missing file")
    
    # Test 4: Empty file
    print("\nTest 4: Empty file checksum")
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp_empty:
        empty_file = tmp_empty.name
    
    checksum4 = file_checksum(empty_file)
    expected_empty_sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    
    if checksum4 == expected_empty_sha256:
        print(f"✓ Test 4 PASSED - Empty file SHA-256 matches expected")
    else:
        print(f"✗ Test 4 FAILED - Expected {expected_empty_sha256}, got {checksum4}")
    
    # Test 5: Large file (1 MB)
    print("\nTest 5: Large file checksum (1 MB)")
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp_large:
        large_file = tmp_large.name
        # Write 1 MB of data
        tmp_large.write(b'A' * (1024 * 1024))
    
    checksum5 = file_checksum(large_file)
    
    if checksum5:
        print(f"✓ Test 5 PASSED - Large file checksum computed")
    else:
        print("✗ Test 5 FAILED")
    
    # Test 6: Test other utility functions
    print("\nTest 6: String hash function")
    test_string = "Hello World"
    string_hash = calculate_string_hash(test_string)
    expected = 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
    
    if string_hash == expected:
        print(f"✓ Test 6 PASSED - String hash matches expected")
    else:
        print(f"✗ Test 6 FAILED - Expected {expected}, got {string_hash}")
    
    # Cleanup
    print("\nCleaning up test files...")
    try:
        os.remove(test_file)
        os.remove(empty_file)
        os.remove(large_file)
        print("✓ Cleanup complete")
    except Exception as e:
        print(f"Warning: Cleanup error: {e}")
    
    print("\n=== Test Suite Complete ===")
