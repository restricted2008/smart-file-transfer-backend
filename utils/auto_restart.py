"""
auto_restart.py
Auto-restart utility to monitor Flask server.py and restart on crash.
Monitors by process name/port and handles edge cases.
"""

import subprocess
import sys
import time
import os
import socket
import psutil
from datetime import datetime
from config import AUTO_RESTART_ENABLED, MAX_RESTART_ATTEMPTS, RESTART_DELAY, SERVER_PORT


def log_message(message):
    """Log a message with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")


def clear_terminal():
    """Clear terminal output (cross-platform)."""
    try:
        if os.name == 'nt':  # Windows
            os.system('cls')
        else:  # Unix/Linux/Mac
            os.system('clear')
    except Exception as e:
        log_message(f"Warning: Could not clear terminal: {e}")


def is_port_in_use(port):
    """
    Check if a port is currently in use.
    
    Args:
        port (int): Port number to check
    
    Returns:
        bool: True if port is in use, False otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0
    except Exception as e:
        log_message(f"Warning: Error checking port {port}: {e}")
        return False


def find_server_process(server_script_name='server.py'):
    """
    Find running server process by script name.
    
    Args:
        server_script_name (str): Name of the server script
    
    Returns:
        psutil.Process or None: Process object if found, None otherwise
    """
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info.get('cmdline')
                if cmdline and any(server_script_name in str(arg) for arg in cmdline):
                    return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        log_message(f"Warning: Error finding process: {e}")
    
    return None


def is_server_running(port, server_script_name='server.py'):
    """
    Check if server is running by checking both port and process.
    
    Args:
        port (int): Server port
        server_script_name (str): Server script name
    
    Returns:
        tuple: (is_running, process) - Boolean and process object if found
    """
    # Check by port first (most reliable)
    port_active = is_port_in_use(port)
    
    # Check by process name
    process = find_server_process(server_script_name)
    
    # Server is considered running if port is active OR process exists
    is_running = port_active or (process is not None)
    
    return is_running, process


def resolve_script_path(server_script):
    """
    Resolve server script path, handling symlinks.
    
    Args:
        server_script (str): Path to server script
    
    Returns:
        str: Resolved absolute path
    
    Raises:
        FileNotFoundError: If script doesn't exist
        PermissionError: If no permission to access script
    """
    # Handle symlinks
    if os.path.islink(server_script):
        log_message(f"Detected symlink: {server_script}")
        server_script = os.path.realpath(server_script)
        log_message(f"Resolved to: {server_script}")
    
    # Get absolute path
    server_script = os.path.abspath(server_script)
    
    # Check if file exists
    if not os.path.exists(server_script):
        raise FileNotFoundError(f"Server script not found: {server_script}")
    
    # Check if we have read permission
    if not os.access(server_script, os.R_OK):
        raise PermissionError(f"No read permission for: {server_script}")
    
    return server_script


def start_server_process(server_script):
    """
    Start the server process.
    
    Args:
        server_script (str): Path to server script
    
    Returns:
        subprocess.Popen: Process object
    
    Raises:
        Exception: If server cannot be started
    """
    try:
        # Resolve script path
        server_script = resolve_script_path(server_script)
        
        log_message(f"Starting server: {server_script}")
        
        # Start server process
        process = subprocess.Popen(
            [sys.executable, server_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Give server time to start
        time.sleep(2)
        
        # Check if it started successfully
        if process.poll() is not None:
            # Process already terminated
            raise Exception(f"Server process terminated immediately with code {process.returncode}")
        
        log_message(f"Server started with PID: {process.pid}")
        return process
    
    except FileNotFoundError as e:
        raise Exception(f"Script not found: {e}")
    except PermissionError as e:
        raise Exception(f"Permission denied: {e}")
    except Exception as e:
        raise Exception(f"Failed to start server: {e}")


def monitor_server(server_script='server.py', check_interval=5):
    """
    Monitor Flask server and restart if it crashes.
    Checks every N seconds if server is running by process name/port.
    
    Args:
        server_script (str): Path to the server script
        check_interval (int): Seconds between health checks (default: 5)
    
    Returns:
        int: Exit code
    """
    if not AUTO_RESTART_ENABLED:
        log_message("Auto-restart is disabled. Starting server without monitoring...")
        try:
            process = start_server_process(server_script)
            process.wait()
            return process.returncode
        except Exception as e:
            log_message(f"Error: {e}")
            return 1
    
    restart_count = 0
    server_process = None
    
    clear_terminal()
    log_message("=" * 60)
    log_message("Flask Server Auto-Restart Monitor")
    log_message(f"Script: {server_script}")
    log_message(f"Port: {SERVER_PORT}")
    log_message(f"Check interval: {check_interval}s")
    log_message(f"Max restart attempts: {MAX_RESTART_ATTEMPTS}")
    log_message("=" * 60)
    
    try:
        while restart_count < MAX_RESTART_ATTEMPTS:
            try:
                # Start server if not running
                is_running, process = is_server_running(SERVER_PORT, os.path.basename(server_script))
                
                if not is_running or server_process is None:
                    if restart_count > 0:
                        log_message(f"Server is down. Restart attempt {restart_count + 1}/{MAX_RESTART_ATTEMPTS}")
                    else:
                        log_message("Starting server for the first time...")
                    
                    try:
                        server_process = start_server_process(server_script)
                        restart_count += 1
                        
                        # Wait for server to stabilize
                        time.sleep(RESTART_DELAY)
                        
                        # Verify it's actually running
                        is_running, _ = is_server_running(SERVER_PORT, os.path.basename(server_script))
                        if is_running:
                            log_message(f"✓ Server is running on port {SERVER_PORT}")
                            restart_count = 0  # Reset counter on successful start
                        else:
                            log_message("✗ Server failed to start properly")
                            continue
                    
                    except Exception as e:
                        log_message(f"✗ Failed to start server: {e}")
                        if restart_count < MAX_RESTART_ATTEMPTS:
                            log_message(f"Retrying in {RESTART_DELAY} seconds...")
                            time.sleep(RESTART_DELAY)
                        continue
                
                else:
                    # Server is running, check if process is still alive
                    if server_process and server_process.poll() is not None:
                        # Our managed process died but port is still in use
                        # Another instance might be running
                        log_message("Warning: Managed process died but port is in use")
                        log_message("Another server instance may be running")
                        server_process = None
                
                # Sleep and check again
                time.sleep(check_interval)
            
            except KeyboardInterrupt:
                log_message("\nReceived keyboard interrupt. Shutting down...")
                if server_process:
                    log_message("Terminating server process...")
                    server_process.terminate()
                    try:
                        server_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        log_message("Force killing server process...")
                        server_process.kill()
                return 0
        
        log_message(f"\n✗ Max restart attempts ({MAX_RESTART_ATTEMPTS}) reached. Giving up.")
        return 1
    
    except Exception as e:
        log_message(f"\n✗ Fatal error in monitor loop: {e}")
        return 1
    
    finally:
        if server_process:
            try:
                server_process.terminate()
            except Exception:
                pass


if __name__ == '__main__':
    """
    Main entry point for auto-restart monitor.
    """
    # Get server script path
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    server_script = os.path.join(script_dir, 'server.py')
    
    # Check if script exists
    if not os.path.exists(server_script):
        log_message(f"✗ Error: Server script not found at {server_script}")
        sys.exit(1)
    
    # Check permissions
    if not os.access(server_script, os.R_OK):
        log_message(f"✗ Error: No read permission for {server_script}")
        sys.exit(1)
    
    # Start monitoring
    try:
        exit_code = monitor_server(server_script, check_interval=5)
        sys.exit(exit_code)
    except Exception as e:
        log_message(f"✗ Fatal error: {e}")
        sys.exit(1)
