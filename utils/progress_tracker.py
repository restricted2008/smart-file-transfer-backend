"""
progress_tracker.py
Utilities for tracking file transfer progress, speed, and ETA calculations.
"""

import time
import statistics
from typing import Optional, Dict, Any


class ProgressTracker:
    """Track file transfer progress with speed and ETA calculations."""
    
    def __init__(self, filename: str, total_bytes: int):
        """
        Initialize progress tracker.
        
        Args:
            filename (str): Name of the file being transferred
            total_bytes (int): Total file size in bytes
        """
        self.filename = filename
        self.total_bytes = total_bytes
        self.transferred_bytes = 0
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.speed_samples = []  # Store recent speed measurements
        self.max_samples = 10   # Keep last 10 speed measurements
        
    def update(self, transferred_bytes: int) -> Dict[str, Any]:
        """
        Update progress and calculate metrics.
        
        Args:
            transferred_bytes (int): Current bytes transferred
            
        Returns:
            dict: Progress metrics including percentage, speed, and ETA
        """
        self.transferred_bytes = transferred_bytes
        current_time = time.time()
        
        # Calculate progress percentage
        progress = int((transferred_bytes / self.total_bytes) * 100) if self.total_bytes > 0 else 0
        
        # Calculate speed (bytes per second)
        elapsed_time = current_time - self.start_time
        if elapsed_time > 0:
            current_speed = transferred_bytes / elapsed_time
            self.speed_samples.append(current_speed)
            
            # Keep only recent samples
            if len(self.speed_samples) > self.max_samples:
                self.speed_samples.pop(0)
            
            # Use average of recent samples for more stable speed calculation
            speed = statistics.mean(self.speed_samples) if self.speed_samples else 0
        else:
            speed = 0
        
        # Calculate ETA (estimated time remaining)
        remaining_bytes = self.total_bytes - transferred_bytes
        if speed > 0 and remaining_bytes > 0:
            eta = int(remaining_bytes / speed)
        else:
            eta = 0
        
        self.last_update_time = current_time
        
        return {
            'progress': progress,
            'speed': speed,
            'eta': eta,
            'transferred_bytes': transferred_bytes,
            'total_bytes': self.total_bytes,
            'elapsed_time': elapsed_time
        }
    
    def get_final_stats(self) -> Dict[str, Any]:
        """Get final transfer statistics."""
        total_time = time.time() - self.start_time
        avg_speed = self.transferred_bytes / total_time if total_time > 0 else 0
        
        return {
            'total_time': total_time,
            'avg_speed': avg_speed,
            'transferred_bytes': self.transferred_bytes,
            'total_bytes': self.total_bytes
        }


class NetworkMonitor:
    """Monitor network quality and recommend optimal settings."""
    
    def __init__(self):
        """Initialize network monitor."""
        self.latencies = []  # Store last 10 ping times
        self.max_samples = 10
        self.quality_history = []
    
    def add_latency(self, latency_ms: float):
        """
        Record a network round-trip time.
        
        Args:
            latency_ms (float): Latency in milliseconds
        """
        self.latencies.append(latency_ms)
        if len(self.latencies) > self.max_samples:
            self.latencies.pop(0)
    
    def get_quality(self) -> str:
        """
        Classify network quality based on latency measurements.
        
        Returns:
            str: Network quality ('excellent', 'good', 'poor', 'unstable', 'unknown')
        """
        if len(self.latencies) < 3:
            return 'unknown'
        
        avg_latency = statistics.mean(self.latencies)
        stdev_latency = statistics.stdev(self.latencies) if len(self.latencies) > 1 else 0
        
        if avg_latency < 50 and stdev_latency < 20:
            return 'excellent'
        elif avg_latency < 150 and stdev_latency < 50:
            return 'good'
        elif avg_latency < 300:
            return 'poor'
        else:
            return 'unstable'
    
    def get_recommended_chunk_size(self) -> int:
        """
        Recommend chunk size based on network quality.
        
        Returns:
            int: Recommended chunk size in bytes
        """
        quality = self.get_quality()
        return {
            'excellent': 1024 * 1024,    # 1MB
            'good': 512 * 1024,           # 512KB
            'poor': 256 * 1024,           # 256KB
            'unstable': 128 * 1024,       # 128KB
            'unknown': 512 * 1024         # 512KB default
        }[quality]
    
    def get_recommended_retry_delay(self) -> float:
        """
        Recommend retry delay based on network quality.
        
        Returns:
            float: Recommended delay in seconds
        """
        quality = self.get_quality()
        return {
            'excellent': 1.0,    # 1 second
            'good': 2.0,         # 2 seconds
            'poor': 5.0,         # 5 seconds
            'unstable': 10.0,    # 10 seconds
            'unknown': 3.0       # 3 seconds default
        }[quality]


def format_speed(bytes_per_sec: float) -> str:
    """
    Format transfer speed for display.
    
    Args:
        bytes_per_sec (float): Speed in bytes per second
        
    Returns:
        str: Formatted speed string (KB/s or MB/s)
    """
    if bytes_per_sec < 1024 * 1024:
        return f"{bytes_per_sec / 1024:.2f} KB/s"
    else:
        return f"{bytes_per_sec / (1024 * 1024):.2f} MB/s"


def format_eta(seconds: int) -> str:
    """
    Format ETA for display.
    
    Args:
        seconds (int): Estimated time remaining in seconds
        
    Returns:
        str: Formatted ETA string (e.g., "2m 30s" or "1h 5m")
    """
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        secs = seconds % 60
        return f"{minutes}m {secs}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"


def calculate_transfer_speed(transferred_bytes: int, elapsed_time: float) -> float:
    """
    Calculate transfer speed in bytes per second.
    
    Args:
        transferred_bytes (int): Bytes transferred
        elapsed_time (float): Time elapsed in seconds
        
    Returns:
        float: Transfer speed in bytes per second
    """
    if elapsed_time <= 0:
        return 0.0
    return transferred_bytes / elapsed_time
