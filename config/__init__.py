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
File: config/__init__.py
Purpose: Configuration management module
================================================================================

Description:
    This module provides configuration management for the SecureChat system.
    It loads configuration from config.json and provides easy access to all
    configuration values.

================================================================================
"""

from .config_loader import Config, get_config, load_config

__all__ = ['Config', 'get_config', 'load_config']

