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
File: tests/report_generator.py
Purpose: Generate comprehensive test reports
================================================================================
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class TestReportGenerator:
    """Generate comprehensive test reports."""
    
    def __init__(self, report_dir: str = "reports"):
        """Initialize report generator."""
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def generate_automatic_test_report(self, test_result, test_modules: List[str]) -> str:
        """Generate report for automatic test suite."""
        
        report_data = {
            "report_type": "automatic_tests",
            "timestamp": datetime.now().isoformat(),
            "test_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_tests": test_result.testsRun,
                "passed": test_result.testsRun - len(test_result.failures) - len(test_result.errors),
                "failed": len(test_result.failures),
                "errors": len(test_result.errors),
                "skipped": len(test_result.skipped),
                "success_rate": round(
                    ((test_result.testsRun - len(test_result.failures) - len(test_result.errors)) / test_result.testsRun * 100)
                    if test_result.testsRun > 0 else 0, 2
                ),
                "overall_status": "PASS" if test_result.wasSuccessful() else "FAIL"
            },
            "test_modules": test_modules,
            "test_details": {
                "passed_tests": [],
                "failed_tests": [],
                "error_tests": [],
                "skipped_tests": []
            },
            "failures": [],
            "errors": []
        }
        
        # Collect all test names from the test result
        all_tests = []
        failed_test_names = [str(f[0]) for f in test_result.failures]
        error_test_names = [str(e[0]) for e in test_result.errors]
        skipped_test_names = [str(s[0]) for s in test_result.skipped]
        
        # Note: We can't easily get all test names from unittest.TestResult
        # So we'll just track what we know: failures, errors, and skipped
        # Passed tests = total - failed - errors - skipped
        
        # Collect failures
        for test, traceback in test_result.failures:
            error_lines = traceback.split('\n')
            error_msg = error_lines[-2] if len(error_lines) > 2 else (error_lines[0] if error_lines else "Unknown error")
            failure_info = {
                "test": str(test),
                "error": error_msg.strip(),
                "traceback": traceback
            }
            report_data["failures"].append(failure_info)
            report_data["test_details"]["failed_tests"].append(str(test))
        
        # Collect errors
        for test, traceback in test_result.errors:
            error_lines = traceback.split('\n')
            error_msg = error_lines[-2] if len(error_lines) > 2 else (error_lines[0] if error_lines else "Unknown error")
            error_info = {
                "test": str(test),
                "error": error_msg.strip(),
                "traceback": traceback
            }
            report_data["errors"].append(error_info)
            report_data["test_details"]["error_tests"].append(str(test))
        
        # Collect skipped tests
        for test, reason in test_result.skipped:
            report_data["test_details"]["skipped_tests"].append({
                "test": str(test),
                "reason": str(reason)
            })
        
        # Calculate passed tests count
        passed_count = report_data["summary"]["passed"]
        report_data["test_details"]["passed_count"] = passed_count
        
        # Generate filename
        filename = f"automatic_tests_{self.timestamp}.json"
        filepath = self.report_dir / filename
        
        # Save JSON report
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        # Generate human-readable report
        text_report = self._generate_text_report(report_data, "automatic")
        text_filepath = self.report_dir / f"automatic_tests_{self.timestamp}.txt"
        with open(text_filepath, 'w', encoding='utf-8') as f:
            f.write(text_report)
        
        return str(filepath)
    
    def generate_manual_test_report(self, test_name: str, test_results: Dict) -> str:
        """Generate report for manual test."""
        
        report_data = {
            "report_type": "manual_test",
            "test_name": test_name,
            "timestamp": datetime.now().isoformat(),
            "test_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "results": test_results
        }
        
        # Generate filename
        filename = f"manual_{test_name}_{self.timestamp}.json"
        filepath = self.report_dir / filename
        
        # Save JSON report
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        # Generate human-readable report
        text_report = self._generate_manual_text_report(report_data)
        text_filepath = self.report_dir / f"manual_{test_name}_{self.timestamp}.txt"
        with open(text_filepath, 'w', encoding='utf-8') as f:
            f.write(text_report)
        
        return str(filepath)
    
    def _generate_text_report(self, report_data: Dict, report_type: str) -> str:
        """Generate human-readable text report."""
        
        lines = []
        lines.append("=" * 80)
        lines.append("TEST REPORT - AUTOMATIC TEST SUITE")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Report Type: {report_data['report_type']}")
        lines.append(f"Test Date: {report_data['test_date']}")
        lines.append("")
        lines.append("-" * 80)
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append("")
        
        summary = report_data['summary']
        lines.append(f"Total Tests Run:     {summary['total_tests']}")
        lines.append(f"Passed:              {summary['passed']}")
        lines.append(f"Failed:              {summary['failed']}")
        lines.append(f"Errors:              {summary['errors']}")
        lines.append(f"Skipped:             {summary['skipped']}")
        lines.append(f"Success Rate:        {summary['success_rate']}%")
        lines.append(f"Overall Status:      {summary['overall_status']}")
        lines.append("")
        
        if report_data['test_modules']:
            lines.append("-" * 80)
            lines.append("TEST MODULES")
            lines.append("-" * 80)
            lines.append("")
            for module in report_data['test_modules']:
                lines.append(f"  - {module}")
            lines.append("")
        
        if report_data['failures']:
            lines.append("-" * 80)
            lines.append(f"FAILURES ({len(report_data['failures'])})")
            lines.append("-" * 80)
            lines.append("")
            for i, failure in enumerate(report_data['failures'], 1):
                lines.append(f"{i}. {failure['test']}")
                lines.append(f"   Error: {failure['error']}")
                lines.append("")
        
        if report_data['errors']:
            lines.append("-" * 80)
            lines.append(f"ERRORS ({len(report_data['errors'])})")
            lines.append("-" * 80)
            lines.append("")
            for i, error in enumerate(report_data['errors'], 1):
                lines.append(f"{i}. {error['test']}")
                lines.append(f"   Error: {error['error']}")
                lines.append("")
        
        if report_data['test_details']['skipped_tests']:
            lines.append("-" * 80)
            lines.append(f"SKIPPED TESTS ({len(report_data['test_details']['skipped_tests'])})")
            lines.append("-" * 80)
            lines.append("")
            for skipped in report_data['test_details']['skipped_tests']:
                lines.append(f"  - {skipped['test']}")
                lines.append(f"    Reason: {skipped['reason']}")
                lines.append("")
        
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def _generate_manual_text_report(self, report_data: Dict) -> str:
        """Generate human-readable text report for manual tests."""
        
        lines = []
        lines.append("=" * 80)
        lines.append(f"TEST REPORT - MANUAL TEST: {report_data['test_name'].upper()}")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Test Name: {report_data['test_name']}")
        lines.append(f"Test Date: {report_data['test_date']}")
        lines.append("")
        lines.append("-" * 80)
        lines.append("TEST RESULTS")
        lines.append("-" * 80)
        lines.append("")
        
        results = report_data['results']
        for key, value in results.items():
            if isinstance(value, dict):
                lines.append(f"{key}:")
                for sub_key, sub_value in value.items():
                    lines.append(f"  {sub_key}: {sub_value}")
            elif isinstance(value, list):
                lines.append(f"{key}:")
                for item in value:
                    lines.append(f"  - {item}")
            else:
                lines.append(f"{key}: {value}")
            lines.append("")
        
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def generate_summary_report(self, all_reports: List[str]) -> str:
        """Generate summary report from all test reports."""
        
        summary_data = {
            "report_type": "summary",
            "timestamp": datetime.now().isoformat(),
            "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_reports": len(all_reports),
            "reports": all_reports
        }
        
        filename = f"test_summary_{self.timestamp}.json"
        filepath = self.report_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(summary_data, f, indent=2)
        
        # Generate text summary
        lines = []
        lines.append("=" * 80)
        lines.append("TEST SUMMARY REPORT")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Report Date: {summary_data['report_date']}")
        lines.append(f"Total Reports: {summary_data['total_reports']}")
        lines.append("")
        lines.append("-" * 80)
        lines.append("REPORTS GENERATED")
        lines.append("-" * 80)
        lines.append("")
        for report in all_reports:
            lines.append(f"  - {report}")
        lines.append("")
        lines.append("=" * 80)
        
        text_filepath = self.report_dir / f"test_summary_{self.timestamp}.txt"
        with open(text_filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        
        return str(filepath)

