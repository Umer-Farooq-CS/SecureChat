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
File: tests/run_all_tests.py
Purpose: Run all test suites
================================================================================

Description:
    This script runs all test suites in the tests directory:
    - test_utils.py: Utility function tests
    - test_aes.py: AES encryption tests
    - test_sign.py: RSA signature tests
    - test_dh.py: Diffie-Hellman tests
    - test_pki.py: PKI certificate tests
    - test_integration.py: Integration tests

Usage:
    python -m tests.run_all_tests
    or
    python tests/run_all_tests.py

Result:
    - Runs all test suites
    - Provides summary of results
    - Exits with code 0 if all tests pass, 1 otherwise

================================================================================
"""

import sys
import unittest

# Import all test modules
from tests import test_utils
from tests import test_aes
from tests import test_sign
from tests import test_dh
from tests import test_pki
from tests import test_integration


def run_all_tests():
    """Run all test suites."""
    print("=" * 70)
    print("Running All Test Suites")
    print("=" * 70)
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test suites
    print("Loading test suites...")
    suite.addTests(loader.loadTestsFromModule(test_utils))
    print("  ✓ test_utils.py")
    
    suite.addTests(loader.loadTestsFromModule(test_aes))
    print("  ✓ test_aes.py")
    
    suite.addTests(loader.loadTestsFromModule(test_sign))
    print("  ✓ test_sign.py")
    
    suite.addTests(loader.loadTestsFromModule(test_dh))
    print("  ✓ test_dh.py")
    
    suite.addTests(loader.loadTestsFromModule(test_pki))
    print("  ✓ test_pki.py")
    
    suite.addTests(loader.loadTestsFromModule(test_integration))
    print("  ✓ test_integration.py")
    
    print()
    print("=" * 70)
    print("Running Tests...")
    print("=" * 70)
    print()
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print()
    print("=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print()
    
    if result.wasSuccessful():
        print("✓ ALL TESTS PASSED")
        print("=" * 70)
        return 0
    else:
        print("✗ SOME TESTS FAILED")
        print("=" * 70)
        if result.failures:
            print("\nFailures:")
            for test, traceback in result.failures:
                print(f"  - {test}")
        if result.errors:
            print("\nErrors:")
            for test, traceback in result.errors:
                print(f"  - {test}")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())

