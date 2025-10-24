"""
encrypt_util.py
AES-128 encryption and decryption utility for secure file transfers.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os


def encrypt_file(input_path, output_path, key):
    """
    Encrypt a file using AES-128 CBC mode.
    
    Args:
        input_path (str): Path to input file
        output_path (str): Path to output encrypted file
        key (bytes): 16-byte encryption key
    
    Returns:
        dict: Encryption metadata including IV
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    # Generate random initialization vector
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    try:
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Write IV at the beginning of the file
            f_out.write(iv)
            
            while True:
                chunk = f_in.read(64 * 1024)  # 64KB chunks
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    # Pad the last chunk
                    chunk = pad(chunk, AES.block_size)
                    f_out.write(cipher.encrypt(chunk))
                    break
                else:
                    f_out.write(cipher.encrypt(chunk))
        
        return {
            'iv': iv.hex(),
            'algorithm': 'AES-128-CBC',
            'success': True
        }
    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")


def decrypt_file(input_path, output_path, key):
    """
    Decrypt a file using AES-128 CBC mode.
    
    Args:
        input_path (str): Path to encrypted file
        output_path (str): Path to output decrypted file
        key (bytes): 16-byte encryption key
    
    Returns:
        dict: Decryption metadata
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    try:
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Read IV from the beginning of the file
            iv = f_in.read(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Read and decrypt the rest of the file
            encrypted_data = f_in.read()
            decrypted_data = cipher.decrypt(encrypted_data)
            
            # Remove padding from the last block
            decrypted_data = unpad(decrypted_data, AES.block_size)
            f_out.write(decrypted_data)
        
        return {
            'algorithm': 'AES-128-CBC',
            'success': True
        }
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")


def encrypt_bytes(data, key):
    """
    Encrypt bytes using AES-128 CBC mode.
    
    Args:
        data (bytes): Data to encrypt
        key (bytes): 16-byte encryption key
    
    Returns:
        bytes: IV + encrypted data
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    
    return iv + encrypted_data


def decrypt_bytes(encrypted_data, key):
    """
    Decrypt bytes using AES-128 CBC mode.
    
    Args:
        encrypted_data (bytes): IV + encrypted data
        key (bytes): 16-byte encryption key
    
    Returns:
        bytes: Decrypted data
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    
    return unpad(decrypted_data, AES.block_size)


def encrypt_data(data, key):
    """
    Encrypt data using AES-128 EAX mode with authentication.
    
    EAX mode provides both confidentiality and authenticity, returning a tag
    that can be used to verify the data hasn't been tampered with.
    
    Args:
        data (bytes|str): Data to encrypt (strings are auto-converted to bytes)
        key (bytes): 16-byte encryption key for AES-128
    
    Returns:
        tuple: (nonce, ciphertext, tag)
            - nonce (bytes): 16-byte nonce/IV for decryption
            - ciphertext (bytes): Encrypted data
            - tag (bytes): 16-byte authentication tag
    
    Raises:
        TypeError: If data is not bytes or str, or key is not bytes
        ValueError: If key is not exactly 16 bytes
    
    Edge cases:
        - Empty data: Returns empty ciphertext with valid nonce/tag
        - String input: Automatically converted to UTF-8 bytes
    
    Example:
        >>> key = b'sixteen byte key'
        >>> nonce, ciphertext, tag = encrypt_data(b"secret message", key)
        >>> plaintext = decrypt_data(nonce, ciphertext, tag, key)
    """
    # Type checking
    if not isinstance(key, bytes):
        raise TypeError(f"Key must be bytes, got {type(key).__name__}")
    
    if not isinstance(data, (bytes, str)):
        raise TypeError(f"Data must be bytes or str, got {type(data).__name__}")
    
    # Convert string to bytes if necessary
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Validate key length (AES-128 requires exactly 16 bytes)
    if len(key) != 16:
        raise ValueError(f"AES-128 requires exactly 16-byte key, got {len(key)} bytes")
    
    try:
        # Create cipher in EAX mode (authenticated encryption)
        cipher = AES.new(key, AES.MODE_EAX)
        
        # Encrypt and generate authentication tag
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # Return nonce, ciphertext, and authentication tag
        return cipher.nonce, ciphertext, tag
    
    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")


def decrypt_data(nonce, ciphertext, tag, key):
    """
    Decrypt data using AES-128 EAX mode with authentication verification.
    
    Validates the authentication tag to ensure data integrity and authenticity.
    Will raise an exception if the data has been tampered with.
    
    Args:
        nonce (bytes): 16-byte nonce/IV used during encryption
        ciphertext (bytes): Encrypted data to decrypt
        tag (bytes): 16-byte authentication tag from encryption
        key (bytes): 16-byte encryption key (must match encryption key)
    
    Returns:
        bytes: Decrypted plaintext data
    
    Raises:
        TypeError: If inputs are not bytes
        ValueError: If key is not exactly 16 bytes, or tag verification fails
        Exception: For other decryption errors
    
    Edge cases:
        - Empty ciphertext: Returns empty bytes
        - Invalid tag: Raises ValueError (data tampered or corrupted)
        - Wrong key: Raises ValueError during tag verification
    
    Security notes:
        - ALWAYS check the return value - exceptions mean compromised data
        - Do NOT ignore ValueError exceptions - they indicate tampering
        - Tag verification happens before returning any decrypted data
    
    Example:
        >>> key = b'sixteen byte key'
        >>> nonce, ciphertext, tag = encrypt_data(b"secret", key)
        >>> plaintext = decrypt_data(nonce, ciphertext, tag, key)
        >>> assert plaintext == b"secret"
    """
    # Type checking
    if not isinstance(key, bytes):
        raise TypeError(f"Key must be bytes, got {type(key).__name__}")
    
    if not isinstance(nonce, bytes):
        raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")
    
    if not isinstance(ciphertext, bytes):
        raise TypeError(f"Ciphertext must be bytes, got {type(ciphertext).__name__}")
    
    if not isinstance(tag, bytes):
        raise TypeError(f"Tag must be bytes, got {type(tag).__name__}")
    
    # Validate key length
    if len(key) != 16:
        raise ValueError(f"AES-128 requires exactly 16-byte key, got {len(key)} bytes")
    
    try:
        # Create cipher with the same nonce used for encryption
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        
        # Decrypt and verify authentication tag
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext
    
    except ValueError as e:
        # Tag verification failed - data has been tampered with or corrupted
        raise ValueError(f"Authentication failed: Data integrity check failed. "
                        f"Data may be corrupted or tampered with. {str(e)}")
    
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")


if __name__ == '__main__':
    """
    CLI test suite for encryption utilities.
    Tests AES-128 EAX mode encryption/decryption with various scenarios.
    """
    import sys
    
    print("\n=== Encryption Utility Test Suite ===")
    
    # Test key (16 bytes for AES-128)
    test_key = b'TestKey123456789'[:16]  # Exactly 16 bytes
    
    # Test 1: Basic string encryption/decryption
    print("\nTest 1: Basic string encryption and decryption")
    try:
        original_str = "Hello, World! This is a secret message."
        nonce, ciphertext, tag = encrypt_data(original_str, test_key)
        decrypted = decrypt_data(nonce, ciphertext, tag, test_key)
        
        if decrypted.decode('utf-8') == original_str:
            print(f"✓ Test 1 PASSED")
            print(f"  Original:  {original_str}")
            print(f"  Nonce:     {nonce.hex()[:32]}...")
            print(f"  Encrypted: {ciphertext.hex()[:32]}...")
            print(f"  Tag:       {tag.hex()[:32]}...")
            print(f"  Decrypted: {decrypted.decode('utf-8')}")
        else:
            print("✗ Test 1 FAILED - Decrypted data doesn't match original")
    except Exception as e:
        print(f"✗ Test 1 FAILED - {e}")
    
    # Test 2: Binary data encryption
    print("\nTest 2: Binary data encryption")
    try:
        original_bytes = b"\x00\x01\x02\x03\x04\x05Binary data test\xff\xfe\xfd"
        nonce, ciphertext, tag = encrypt_data(original_bytes, test_key)
        decrypted = decrypt_data(nonce, ciphertext, tag, test_key)
        
        if decrypted == original_bytes:
            print(f"✓ Test 2 PASSED - Binary data encrypted/decrypted correctly")
        else:
            print("✗ Test 2 FAILED - Binary data mismatch")
    except Exception as e:
        print(f"✗ Test 2 FAILED - {e}")
    
    # Test 3: Empty data
    print("\nTest 3: Empty data encryption")
    try:
        empty_data = b""
        nonce, ciphertext, tag = encrypt_data(empty_data, test_key)
        decrypted = decrypt_data(nonce, ciphertext, tag, test_key)
        
        if decrypted == empty_data and len(ciphertext) == 0:
            print(f"✓ Test 3 PASSED - Empty data handled correctly")
        else:
            print("✗ Test 3 FAILED - Empty data not handled correctly")
    except Exception as e:
        print(f"✗ Test 3 FAILED - {e}")
    
    # Test 4: Large data (1 MB)
    print("\nTest 4: Large data encryption (1 MB)")
    try:
        large_data = b"A" * (1024 * 1024)  # 1 MB
        nonce, ciphertext, tag = encrypt_data(large_data, test_key)
        decrypted = decrypt_data(nonce, ciphertext, tag, test_key)
        
        if decrypted == large_data:
            print(f"✓ Test 4 PASSED - Large data (1 MB) encrypted/decrypted")
        else:
            print("✗ Test 4 FAILED - Large data mismatch")
    except Exception as e:
        print(f"✗ Test 4 FAILED - {e}")
    
    # Test 5: Invalid key length
    print("\nTest 5: Invalid key length detection")
    try:
        invalid_key = b"short"  # Too short
        nonce, ciphertext, tag = encrypt_data(b"test", invalid_key)
        print("✗ Test 5 FAILED - Should reject invalid key length")
    except ValueError as e:
        print(f"✓ Test 5 PASSED - Correctly rejected invalid key: {e}")
    except Exception as e:
        print(f"✗ Test 5 FAILED - Wrong exception type: {e}")
    
    # Test 6: Tampered data detection
    print("\nTest 6: Tampered data detection (tag verification)")
    try:
        original = b"Important message"
        nonce, ciphertext, tag = encrypt_data(original, test_key)
        
        # Tamper with ciphertext
        tampered_ciphertext = bytes([b ^ 0xFF for b in ciphertext])
        
        try:
            decrypted = decrypt_data(nonce, tampered_ciphertext, tag, test_key)
            print("✗ Test 6 FAILED - Should detect tampered data")
        except ValueError as e:
            print(f"✓ Test 6 PASSED - Correctly detected tampering: Authentication failed")
    except Exception as e:
        print(f"✗ Test 6 FAILED - {e}")
    
    # Test 7: Wrong key detection
    print("\nTest 7: Wrong decryption key detection")
    try:
        original = b"Secret data"
        nonce, ciphertext, tag = encrypt_data(original, test_key)
        
        wrong_key = b'WrongKey87654321'[:16]
        
        try:
            decrypted = decrypt_data(nonce, ciphertext, tag, wrong_key)
            print("✗ Test 7 FAILED - Should detect wrong key")
        except ValueError as e:
            print(f"✓ Test 7 PASSED - Correctly detected wrong key")
    except Exception as e:
        print(f"✗ Test 7 FAILED - {e}")
    
    # Test 8: Type checking
    print("\nTest 8: Type checking enforcement")
    try:
        encrypt_data("test", "not_bytes_key")
        print("✗ Test 8 FAILED - Should reject non-bytes key")
    except TypeError as e:
        print(f"✓ Test 8 PASSED - Correctly rejected invalid type: {e}")
    except Exception as e:
        print(f"✗ Test 8 FAILED - Wrong exception: {e}")
    
    # Test 9: Unicode string handling
    print("\nTest 9: Unicode string encryption")
    try:
        unicode_str = "Hello 世界! 🔒 Encryption test émojis: 🎉🔐"
        nonce, ciphertext, tag = encrypt_data(unicode_str, test_key)
        decrypted = decrypt_data(nonce, ciphertext, tag, test_key)
        
        if decrypted.decode('utf-8') == unicode_str:
            print(f"✓ Test 9 PASSED - Unicode handled correctly")
            print(f"  Original:  {unicode_str}")
            print(f"  Decrypted: {decrypted.decode('utf-8')}")
        else:
            print("✗ Test 9 FAILED - Unicode mismatch")
    except Exception as e:
        print(f"✗ Test 9 FAILED - {e}")
    
    print("\n=== Test Suite Complete ===")
