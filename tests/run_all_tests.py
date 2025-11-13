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
from pathlib import Path

# Add parent directory to path to ensure we import from local tests
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import report generator
from tests.report_generator import TestReportGenerator

# Import all test modules
import tests.test_utils as test_utils
import tests.test_aes as test_aes
import tests.test_sign as test_sign
import tests.test_dh as test_dh
import tests.test_pki as test_pki
import tests.test_integration as test_integration
import tests.test_protocol as test_protocol
import tests.test_cert_gen as test_cert_gen
import tests.test_db as test_db
import tests.test_transcript as test_transcript
import tests.test_config as test_config
import tests.test_server_client as test_server_client


def run_all_tests():
    """Run all test suites."""
    print("=" * 70)
    print("Running All Test Suites")
    print("=" * 70)
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Track test modules for report
    test_modules = []
    
    # Add all test suites
    print("Loading test suites...")
    print()
    print("Phase 1: Foundation Tests")
    suite.addTests(loader.loadTestsFromModule(test_protocol))
    test_modules.append("test_protocol.py - Protocol message models")
    print("   test_protocol.py - Protocol message models")
    
    suite.addTests(loader.loadTestsFromModule(test_cert_gen))
    test_modules.append("test_cert_gen.py - Certificate generation")
    print("   test_cert_gen.py - Certificate generation")
    
    print()
    print("Phase 2: Storage Layer Tests")
    suite.addTests(loader.loadTestsFromModule(test_db))
    test_modules.append("test_db.py - Database operations")
    print("   test_db.py - Database operations")
    
    suite.addTests(loader.loadTestsFromModule(test_transcript))
    test_modules.append("test_transcript.py - Transcript management")
    print("   test_transcript.py - Transcript management")
    
    print()
    print("Phase 3: Application Layer Tests")
    suite.addTests(loader.loadTestsFromModule(test_server_client))
    test_modules.append("test_server_client.py - Server/Client integration")
    print("   test_server_client.py - Server/Client integration")
    
    print()
    print("Crypto Primitives Tests")
    suite.addTests(loader.loadTestsFromModule(test_utils))
    test_modules.append("test_utils.py - Utility functions")
    print("   test_utils.py - Utility functions")
    
    suite.addTests(loader.loadTestsFromModule(test_aes))
    test_modules.append("test_aes.py - AES encryption")
    print("   test_aes.py - AES encryption")
    
    suite.addTests(loader.loadTestsFromModule(test_sign))
    test_modules.append("test_sign.py - RSA signatures")
    print("   test_sign.py - RSA signatures")
    
    suite.addTests(loader.loadTestsFromModule(test_dh))
    test_modules.append("test_dh.py - Diffie-Hellman key exchange")
    print("   test_dh.py - Diffie-Hellman key exchange")
    
    suite.addTests(loader.loadTestsFromModule(test_pki))
    test_modules.append("test_pki.py - PKI certificate validation")
    print("   test_pki.py - PKI certificate validation")
    
    suite.addTests(loader.loadTestsFromModule(test_integration))
    test_modules.append("test_integration.py - Crypto integration")
    print("   test_integration.py - Crypto integration")
    
    print()
    print("Configuration Tests")
    suite.addTests(loader.loadTestsFromModule(test_config))
    test_modules.append("test_config.py - Configuration system")
    print("   test_config.py - Configuration system")
    
    print()
    print("=" * 70)
    print("Running Tests...")
    print("=" * 70)
    print()
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print comprehensive summary
    print()
    print("=" * 70)
    print("COMPREHENSIVE TEST SUMMARY")
    print("=" * 70)
    print()
    
    total_tests = result.testsRun
    passed_tests = total_tests - len(result.failures) - len(result.errors)
    failed_tests = len(result.failures)
    error_tests = len(result.errors)
    skipped_tests = len(result.skipped)
    
    print(f"Total Tests Run:     {total_tests}")
    print(f"Passed:              {passed_tests}")
    print(f"Failed:              {failed_tests}")
    print(f"Errors:              {error_tests}")
    print(f"Skipped:             {skipped_tests}")
    print()
    
    if total_tests > 0:
        success_rate = (passed_tests / total_tests) * 100
        print(f"Success Rate:        {success_rate:.1f}%")
        print()
    
    if result.wasSuccessful():
        print("=" * 70)
        print("ALL TESTS PASSED")
        print("=" * 70)
    else:
        print("=" * 70)
        print("SOME TESTS FAILED")
        print("=" * 70)
        
        if result.failures:
            print(f"\nFailures ({len(result.failures)}):")
            for i, (test, traceback) in enumerate(result.failures, 1):
                print(f"  {i}. {test}")
                # Print first line of traceback
                first_line = traceback.split('\n')[0] if traceback else ""
                if first_line:
                    print(f"     {first_line}")
        
        if result.errors:
            print(f"\nErrors ({len(result.errors)}):")
            for i, (test, traceback) in enumerate(result.errors, 1):
                print(f"  {i}. {test}")
                # Print first line of traceback
                first_line = traceback.split('\n')[0] if traceback else ""
                if first_line:
                    print(f"     {first_line}")
        
        print()
    
    # Generate test report
    print()
    print("=" * 70)
    print("GENERATING TEST REPORT")
    print("=" * 70)
    print()
    
    try:
        report_generator = TestReportGenerator()
        report_path = report_generator.generate_automatic_test_report(result, test_modules)
        print(f"[SUCCESS] Test report generated: {report_path}")
        
        # Also print text report location
        text_report_path = report_path.replace('.json', '.txt')
        print(f"[INFO] Text report available: {text_report_path}")
        print()
    except Exception as e:
        print(f"[WARNING] Failed to generate report: {e}")
        print()
    
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_all_tests())

