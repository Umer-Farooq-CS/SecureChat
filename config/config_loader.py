"""
================================================================================
Assignment #2 - Secure Chat System
Information Security (CS-3002)
FAST-NUCES, Fall 2025
================================================================================

Student Information:
    Name: Umer Farooq
    Roll No: 22I-0891
    Section: CS-7D
    Instructor: Urooj Ghani

================================================================================
File: config/config_loader.py
Purpose: Configuration loader and manager
================================================================================

Description:
    This module loads configuration from config.json and provides a Config
    class for easy access to configuration values. It supports environment
    variable overrides for sensitive values like database passwords.

Usage:
    from config import get_config
    
    config = get_config()
    server_port = config.server.port
    db_host = config.database.host

================================================================================
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


class Config:
    """Configuration class that provides easy access to config values."""
    
    def __init__(self, config_dict: Dict[str, Any]):
        """
        Initializes configuration from dictionary.
        
        Args:
            config_dict: Configuration dictionary loaded from JSON
        """
        # Server configuration
        server = config_dict.get("server", {})
        self.server = type('ServerConfig', (), {
            'host': server.get("host", "localhost"),
            'port': int(server.get("port", 8888)),
            'cert_path': server.get("cert_path", "certs/server-cert.pem"),
            'key_path': server.get("key_path", "certs/server-key.pem")
        })()
        
        # Client configuration
        client = config_dict.get("client", {})
        self.client = type('ClientConfig', (), {
            'cert_path': client.get("cert_path", "certs/client-cert.pem"),
            'key_path': client.get("key_path", "certs/client-key.pem")
        })()
        
        # CA configuration
        ca = config_dict.get("ca", {})
        self.ca = type('CAConfig', (), {
            'cert_path': ca.get("cert_path", "certs/ca-cert.pem")
        })()
        
        # Database configuration (with environment variable overrides)
        database = config_dict.get("database", {})
        self.database = type('DatabaseConfig', (), {
            'host': os.getenv("DB_HOST", database.get("host", "localhost")),
            'port': int(os.getenv("DB_PORT", str(database.get("port", 3306)))),
            'name': os.getenv("DB_NAME", database.get("name", "securechat")),
            'user': os.getenv("DB_USER", database.get("user", "")),
            'password': os.getenv("DB_PASSWORD", database.get("password", ""))
        })()
        
        # Paths configuration
        paths = config_dict.get("paths", {})
        self.paths = type('PathsConfig', (), {
            'certs_dir': paths.get("certs_dir", "certs"),
            'transcripts_dir': paths.get("transcripts_dir", "transcripts")
        })()
        
        # Crypto configuration
        crypto = config_dict.get("crypto", {})
        self.crypto = type('CryptoConfig', (), {
            'dh_key_size': int(crypto.get("dh_key_size", 2048)),
            'dh_generator': int(crypto.get("dh_generator", 2)),
            'aes_key_size': int(crypto.get("aes_key_size", 16))
        })()
    
    def __repr__(self) -> str:
        """String representation of configuration."""
        return f"Config(server={self.server.host}:{self.server.port})"


# Global configuration instance
_config: Optional[Config] = None


def load_config(config_path: Optional[str] = None) -> Config:
    """
    Loads configuration from JSON file.
    
    Args:
        config_path: Path to config.json file. If None, uses default location.
        
    Returns:
        Config: Configuration object
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        json.JSONDecodeError: If config file is invalid JSON
    """
    if config_path is None:
        # Default to config/config.json relative to project root
        project_root = Path(__file__).parent.parent
        config_path = project_root / "config" / "config.json"
    else:
        config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config_dict = json.load(f)
    
    return Config(config_dict)


def get_config(config_path: Optional[str] = None) -> Config:
    """
    Gets the global configuration instance, loading it if necessary.
    
    Args:
        config_path: Path to config.json file. Only used on first call.
        
    Returns:
        Config: Configuration object
    """
    global _config
    if _config is None:
        _config = load_config(config_path)
    return _config


def reload_config(config_path: Optional[str] = None) -> Config:
    """
    Reloads configuration from file.
    
    Args:
        config_path: Path to config.json file. If None, uses default location.
        
    Returns:
        Config: Newly loaded configuration object
    """
    global _config
    _config = load_config(config_path)
    return _config

