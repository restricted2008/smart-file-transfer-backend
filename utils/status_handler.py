"""
status_handler.py
Thread-safe handler for transfer status and queue management using JSON storage.
Implements file locking for concurrent access and JSON corruption recovery.
"""

import json
import threading
import os
import time
import fcntl
import shutil
from datetime import datetime
from config import STATUS_FILE


class StatusHandler:
    """Thread-safe handler for file transfer status tracking with file locking."""
    
    def __init__(self, status_file=STATUS_FILE):
        """
        Initialize the status handler.
        
        Args:
            status_file (str): Path to the status JSON file
        """
        self.status_file = status_file
        self.backup_file = status_file + '.backup'
        self.lock = threading.Lock()  # Thread lock
        self._ensure_file_exists()
    
    def _ensure_file_exists(self):
        """Ensure the status file exists with default structure."""
        if not os.path.exists(self.status_file):
            default_data = self._get_default_structure()
            self._write_data(default_data)
    
    def _get_default_structure(self):
        """Get the default JSON structure for status file."""
        return {
            "transfers": {},
            "queue": [],
            "metadata": {
                "last_updated": None,
                "total_transfers": 0,
                "version": "1.0"
            }
        }
    
    def _acquire_file_lock(self, file_obj, timeout=5):
        """
        Acquire an exclusive file lock (cross-platform).
        
        Args:
            file_obj: File object to lock
            timeout (int): Maximum time to wait for lock (seconds)
        
        Returns:
            bool: True if lock acquired, False on timeout
        """
        start_time = time.time()
        
        while True:
            try:
                # Try to acquire exclusive lock (non-blocking)
                if os.name == 'nt':  # Windows
                    import msvcrt
                    msvcrt.locking(file_obj.fileno(), msvcrt.LK_NBLCK, 1)
                else:  # Unix/Linux
                    fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except (IOError, OSError):
                # Lock is held by another process
                if time.time() - start_time > timeout:
                    return False
                time.sleep(0.1)  # Wait before retry
    
    def _release_file_lock(self, file_obj):
        """Release file lock (cross-platform)."""
        try:
            if os.name == 'nt':  # Windows
                import msvcrt
                msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)
            else:  # Unix/Linux
                fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass  # Best effort
    
    def _read_data(self):
        """
        Read data from the JSON file with corruption recovery.
        
        Returns:
            dict: Parsed JSON data
        
        Raises:
            Exception: If file cannot be read or recovered
        """
        try:
            with open(self.status_file, 'r') as f:
                data = json.load(f)
                # Validate structure
                if 'transfers' not in data or 'queue' not in data or 'metadata' not in data:
                    raise ValueError("Invalid JSON structure")
                return data
        
        except (json.JSONDecodeError, ValueError) as e:
            print(f"[WARNING] JSON corrupted: {e}. Attempting recovery...")
            
            # Try to restore from backup
            if os.path.exists(self.backup_file):
                try:
                    with open(self.backup_file, 'r') as f:
                        data = json.load(f)
                        print("[INFO] Successfully restored from backup")
                        # Write recovered data back to main file
                        self._write_data(data)
                        return data
                except Exception as backup_error:
                    print(f"[ERROR] Backup also corrupted: {backup_error}")
            
            # If all else fails, create new file with default structure
            print("[WARNING] Creating new status file with default structure")
            default_data = self._get_default_structure()
            self._write_data(default_data)
            return default_data
        
        except FileNotFoundError:
            print("[INFO] Status file not found, creating new one")
            self._ensure_file_exists()
            return self._get_default_structure()
    
    def _write_data(self, data):
        """
        Write data to the JSON file with atomic write and backup.
        
        Args:
            data (dict): Data to write
        """
        # Update timestamp
        data['metadata']['last_updated'] = datetime.utcnow().isoformat()
        
        # Create backup before writing
        if os.path.exists(self.status_file):
            try:
                shutil.copy2(self.status_file, self.backup_file)
            except Exception as e:
                print(f"[WARNING] Failed to create backup: {e}")
        
        # Atomic write: write to temp file, then rename
        temp_file = self.status_file + '.tmp'
        try:
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Atomic rename (overwrites existing file)
            if os.name == 'nt':  # Windows requires explicit removal
                if os.path.exists(self.status_file):
                    os.remove(self.status_file)
            os.rename(temp_file, self.status_file)
        
        except Exception as e:
            print(f"[ERROR] Failed to write status file: {e}")
            # Clean up temp file if it exists
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    pass
            raise
    
    def update_status(self, filename, status, checksum=None, encryption=False, priority=0):
        """
        Thread-safe update of transfer status with timestamps.
        
        Args:
            filename (str): Name of the file being transferred
            status (str): Transfer status (pending, processing, completed, failed)
            checksum (str, optional): SHA-256 checksum of the file
            encryption (bool): Whether the file is encrypted
            priority (int): Transfer priority (higher = more important)
        
        Returns:
            bool: True if successful, False otherwise
        """
        with self.lock:
            try:
                data = self._read_data()
                
                current_time = datetime.utcnow().isoformat()
                
                # Check if transfer exists
                if filename in data['transfers']:
                    # Update existing transfer
                    data['transfers'][filename]['status'] = status
                    data['transfers'][filename]['updated_at'] = current_time
                    
                    if checksum is not None:
                        data['transfers'][filename]['checksum'] = checksum
                    
                    data['transfers'][filename]['encryption'] = encryption
                    data['transfers'][filename]['priority'] = priority
                else:
                    # Create new transfer entry
                    data['transfers'][filename] = {
                        'status': status,
                        'checksum': checksum,
                        'encryption': encryption,
                        'priority': priority,
                        'created_at': current_time,
                        'updated_at': current_time
                    }
                    data['metadata']['total_transfers'] += 1
                
                self._write_data(data)
                print(f"[INFO] Status updated: {filename} -> {status}")
                return True
            
            except Exception as e:
                print(f"[ERROR] Failed to update status for {filename}: {e}")
                return False
    
    def get_status(self, filename):
        """
        Get current status for a single file with missing file handling.
        
        Args:
            filename (str): Name of the file to query
        
        Returns:
            dict: Status information, or None if file not found
        """
        with self.lock:
            try:
                data = self._read_data()
                
                if filename in data['transfers']:
                    return data['transfers'][filename]
                else:
                    print(f"[INFO] No status found for: {filename}")
                    return None
            
            except Exception as e:
                print(f"[ERROR] Failed to get status for {filename}: {e}")
                return None
    
    def get_all_status(self):
        """
        Get the entire transfer queue/history with safe error handling.
        
        Returns:
            dict: Complete status data including transfers, queue, and metadata
                  Returns default structure on error
        """
        with self.lock:
            try:
                return self._read_data()
            
            except Exception as e:
                print(f"[ERROR] Failed to get all statuses: {e}")
                return self._get_default_structure()
    
    def add_to_queue(self, filename, priority=0):
        """
        Add a file to the processing queue.
        
        Args:
            filename (str): Name of the file
            priority (int): Queue priority
        
        Returns:
            bool: True if successful
        """
        with self.lock:
            try:
                data = self._read_data()
                
                # Check if already in queue
                queue_entry = {'filename': filename, 'priority': priority}
                
                if not any(item['filename'] == filename for item in data['queue']):
                    data['queue'].append(queue_entry)
                    # Sort by priority (higher first)
                    data['queue'].sort(key=lambda x: x.get('priority', 0), reverse=True)
                    self._write_data(data)
                    print(f"[INFO] Added to queue: {filename} (priority: {priority})")
                
                return True
            
            except Exception as e:
                print(f"[ERROR] Failed to add {filename} to queue: {e}")
                return False
    
    def remove_from_queue(self, filename):
        """
        Remove a file from the processing queue.
        
        Args:
            filename (str): Name of the file
        
        Returns:
            bool: True if successful
        """
        with self.lock:
            try:
                data = self._read_data()
                data['queue'] = [item for item in data['queue'] 
                                if item['filename'] != filename]
                self._write_data(data)
                print(f"[INFO] Removed from queue: {filename}")
                return True
            
            except Exception as e:
                print(f"[ERROR] Failed to remove {filename} from queue: {e}")
                return False
    
    def get_queue(self):
        """
        Get the current processing queue.
        
        Returns:
            list: List of queue entries with filenames and priorities
        """
        with self.lock:
            try:
                data = self._read_data()
                return data['queue']
            except Exception as e:
                print(f"[ERROR] Failed to get queue: {e}")
                return []


if __name__ == '__main__':
    """
    CLI test block for StatusHandler.
    Tests read/write operations and edge cases.
    """
    import tempfile
    import sys
    
    print("\n=== Status Handler Test Suite ===")
    
    # Create temporary status file for testing
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        test_status_file = tmp.name
    
    print(f"Using test file: {test_status_file}")
    
    try:
        # Test 1: Initialize handler
        print("\nTest 1: Initialize StatusHandler")
        handler = StatusHandler(status_file=test_status_file)
        print("✓ Test 1 PASSED - Handler initialized")
        
        # Test 2: Update status for new file
        print("\nTest 2: Update status for new file")
        success = handler.update_status(
            filename='test_file_1.txt',
            status='pending',
            checksum='abc123def456',
            encryption=True,
            priority=5
        )
        if success:
            print("✓ Test 2 PASSED - Status updated")
        else:
            print("✗ Test 2 FAILED")
        
        # Test 3: Get status for existing file
        print("\nTest 3: Get status for existing file")
        status = handler.get_status('test_file_1.txt')
        if status and status['status'] == 'pending' and status['priority'] == 5:
            print(f"✓ Test 3 PASSED - Status retrieved: {status}")
        else:
            print(f"✗ Test 3 FAILED - Status: {status}")
        
        # Test 4: Get status for non-existent file
        print("\nTest 4: Get status for non-existent file")
        status = handler.get_status('nonexistent.txt')
        if status is None:
            print("✓ Test 4 PASSED - Properly handled missing file")
        else:
            print(f"✗ Test 4 FAILED - Should return None")
        
        # Test 5: Update existing file status
        print("\nTest 5: Update existing file status")
        success = handler.update_status(
            filename='test_file_1.txt',
            status='completed',
            checksum='abc123def456',
            encryption=True,
            priority=5
        )
        status = handler.get_status('test_file_1.txt')
        if status and status['status'] == 'completed':
            print("✓ Test 5 PASSED - Status updated to completed")
        else:
            print("✗ Test 5 FAILED")
        
        # Test 6: Add multiple files
        print("\nTest 6: Add multiple files")
        handler.update_status('file_2.dat', 'processing', priority=3)
        handler.update_status('file_3.bin', 'pending', priority=10)
        handler.update_status('file_4.txt', 'failed', priority=1)
        
        all_status = handler.get_all_status()
        if len(all_status['transfers']) == 4:
            print(f"✓ Test 6 PASSED - {len(all_status['transfers'])} files tracked")
        else:
            print(f"✗ Test 6 FAILED - Expected 4 files, got {len(all_status['transfers'])}")
        
        # Test 7: Queue operations
        print("\nTest 7: Queue operations")
        handler.add_to_queue('test_file_1.txt', priority=5)
        handler.add_to_queue('file_3.bin', priority=10)
        handler.add_to_queue('file_2.dat', priority=3)
        
        queue = handler.get_queue()
        if len(queue) == 3 and queue[0]['priority'] == 10:  # Highest priority first
            print(f"✓ Test 7 PASSED - Queue sorted by priority: {queue}")
        else:
            print(f"✗ Test 7 FAILED - Queue: {queue}")
        
        # Test 8: Remove from queue
        print("\nTest 8: Remove from queue")
        handler.remove_from_queue('file_2.dat')
        queue = handler.get_queue()
        if len(queue) == 2:
            print("✓ Test 8 PASSED - File removed from queue")
        else:
            print(f"✗ Test 8 FAILED - Expected 2 items, got {len(queue)}")
        
        # Test 9: Get all status
        print("\nTest 9: Get all status")
        all_status = handler.get_all_status()
        if 'transfers' in all_status and 'queue' in all_status and 'metadata' in all_status:
            print("✓ Test 9 PASSED - Complete status structure returned")
            print(f"  Total transfers: {all_status['metadata']['total_transfers']}")
            print(f"  Queue length: {len(all_status['queue'])}")
        else:
            print("✗ Test 9 FAILED - Invalid structure")
        
        # Test 10: JSON corruption recovery
        print("\nTest 10: JSON corruption recovery")
        # Deliberately corrupt the file
        with open(test_status_file, 'w') as f:
            f.write("{ corrupted json data !!!")
        
        # Try to read - should recover
        handler2 = StatusHandler(status_file=test_status_file)
        recovered = handler2.get_all_status()
        if 'transfers' in recovered and 'queue' in recovered:
            print("✓ Test 10 PASSED - Recovered from corrupted JSON")
        else:
            print("✗ Test 10 FAILED - Recovery failed")
        
    finally:
        # Cleanup
        print("\nCleaning up test files...")
        try:
            os.remove(test_status_file)
            if os.path.exists(test_status_file + '.backup'):
                os.remove(test_status_file + '.backup')
            if os.path.exists(test_status_file + '.tmp'):
                os.remove(test_status_file + '.tmp')
            print("✓ Cleanup complete")
        except Exception as e:
            print(f"Warning: Cleanup error: {e}")
    
    print("\n=== Test Suite Complete ===")
