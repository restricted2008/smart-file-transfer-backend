"""
metadata_util.py
Utilities for file metadata extraction and thumbnail generation.
"""

import os
import mimetypes
from PIL import Image
from datetime import datetime
from typing import Dict, Optional


def get_file_metadata(filepath: str) -> Optional[Dict]:
    """
    Get comprehensive file metadata.
    
    Args:
        filepath (str): Path to the file
        
    Returns:
        dict: File metadata including size, type, timestamps, and thumbnail
    """
    if not os.path.exists(filepath):
        return None
    
    stat = os.stat(filepath)
    mime_type, _ = mimetypes.guess_type(filepath)
    
    metadata = {
        'filename': os.path.basename(filepath),
        'size': stat.st_size,
        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        'mime_type': mime_type or 'application/octet-stream',
        'extension': os.path.splitext(filepath)[1],
        'thumbnail': None
    }
    
    # Generate thumbnail for images
    if mime_type and mime_type.startswith('image/'):
        try:
            thumb_path = generate_thumbnail(filepath)
            metadata['thumbnail'] = os.path.basename(thumb_path)
        except Exception as e:
            print(f'Thumbnail generation failed: {e}')
    
    return metadata


def generate_thumbnail(filepath: str, size: tuple = (200, 200)) -> str:
    """
    Generate thumbnail for image file.
    
    Args:
        filepath (str): Path to the image file
        size (tuple): Thumbnail size (width, height)
        
    Returns:
        str: Path to the generated thumbnail
    """
    img = Image.open(filepath)
    img.thumbnail(size, Image.Resampling.LANCZOS)
    
    thumb_path = filepath + '.thumb.jpg'
    img.save(thumb_path, 'JPEG', quality=85)
    
    return thumb_path


def get_file_type_category(mime_type: str) -> str:
    """
    Categorize file type for analytics.
    
    Args:
        mime_type (str): MIME type of the file
        
    Returns:
        str: Category (image, video, audio, document, archive, other)
    """
    if mime_type.startswith('image/'):
        return 'image'
    elif mime_type.startswith('video/'):
        return 'video'
    elif mime_type.startswith('audio/'):
        return 'audio'
    elif mime_type.startswith('text/') or mime_type in [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ]:
        return 'document'
    elif mime_type in [
        'application/zip',
        'application/x-rar-compressed',
        'application/x-7z-compressed'
    ]:
        return 'archive'
    else:
        return 'other'


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes (int): File size in bytes
        
    Returns:
        str: Formatted file size (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"
