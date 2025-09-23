#!/usr/bin/env python3
"""
Validation script for the monthly security scan workflow.
This script validates the workflow configuration and dependencies.
"""

import os
import sys
import json
import yaml
import subprocess
from pathlib import Path

def check_file_exists(filepath, description):
    """Check if a file exists and report status."""
    if os.path.exists(filepath):
        print(f"[OK] {description}: {filepath}")
        return True
    else:
        print(f"[FAIL] {description}: {filepath} (NOT FOUND)")
        return False

def validate_yaml_syntax(filepath):
    """Validate YAML syntax."""
    try:
        with open(filepath, 'r') as f:
            yaml.safe_load(f)
        print(f"[OK] YAML syntax valid: {filepath}")
        return True
    except yaml.YAMLError as e:
        print(f"[FAIL] YAML syntax error in {filepath}: {e}")
        return False
    except Exception as e:
        print(f"[FAIL] Error reading {filepath}: {e}")
        return False

def check_python_dependencies():
    """Check if required Python packages are available."""
    required_packages = [
        'jinja2',
        'matplotlib',
        'pandas',
        'requests',
        'yaml'
    ]

    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
            print(f"[OK] Python package available: {package}")
        except ImportError:
            print(f"[FAIL] Python package missing: {package}")
            missing_packages.append(package)

    return len(missing_packages) == 0

def validate_workflow_file():
    """Validate the GitHub workflow file."""
    workflow_path = ".github/workflows/monthly-security-scan.yml"

    if not check_file_exists(workflow_path, "GitHub workflow file"):
        return False

    # Validate YAML syntax
    if not validate_yaml_syntax(workflow_path):
        return False

    # Load and validate workflow content
    try:
        with open(workflow_path, 'r') as f:
            workflow = yaml.safe_load(f)

        # Check required sections
        required_sections = ['name', 'on', 'jobs']
        for section in required_sections:
            if section in workflow:
                print(f"[OK] Workflow section found: {section}")
            else:
                print(f"[FAIL] Missing workflow section: {section}")
                return False

        # Check if required jobs exist
        required_jobs = ['security-scan', 'generate-executive-report', 'notify-google-workspace']
        jobs = workflow.get('jobs', {})

        for job in required_jobs:
            if job in jobs:
                print(f"[OK] Required job found: {job}")
            else:
                print(f"[FAIL] Missing required job: {job}")
                return False

        # Check matrix configuration
        security_scan = jobs.get('security-scan', {})
        strategy = security_scan.get('strategy', {})
        matrix = strategy.get('matrix', {})

        if 'target' in matrix:
            targets = matrix['target']
            print(f"[OK] Scan targets configured: {len(targets)} targets")
            for target in targets:
                print(f"   - {target}")
        else:
            print("[FAIL] No scan targets configured in matrix")
            return False

        return True

    except Exception as e:
        print(f"[FAIL] Error validating workflow content: {e}")
        return False

def validate_autoDAST_structure():
    """Validate AutoDast project structure."""
    autoDAST_path = "autoDAST"

    if not os.path.exists(autoDAST_path):
        print(f"[FAIL] AutoDast directory not found: {autoDAST_path}")
        return False

    print(f"[OK] AutoDast directory found: {autoDAST_path}")

    # Check required files
    required_files = [
        "autoDAST/main.py",
        "autoDAST/requirements.txt",
        "autoDAST/src/autodast.py",
        "autoDAST/src/report_generator.py"
    ]

    all_exist = True
    for filepath in required_files:
        if not check_file_exists(filepath, f"AutoDast file"):
            all_exist = False

    # Check if executive report generator exists
    exec_report_path = "autoDAST/src/executive_report_generator.py"
    check_file_exists(exec_report_path, "Executive report generator")

    return all_exist

def validate_requirements():
    """Validate requirements.txt file."""
    req_path = "autoDAST/requirements.txt"

    if not os.path.exists(req_path):
        print(f"[FAIL] Requirements file not found: {req_path}")
        return False

    # Read requirements and check for essential packages
    try:
        with open(req_path, 'r') as f:
            requirements = f.read().lower()

        essential_packages = ['jinja2', 'matplotlib', 'pandas', 'requests']
        missing = []

        for package in essential_packages:
            if package in requirements:
                print(f"[OK] Required package in requirements.txt: {package}")
            else:
                print(f"[WARN] Package not found in requirements.txt: {package}")
                missing.append(package)

        if missing:
            print(f"[INFO] Consider adding these packages to requirements.txt: {', '.join(missing)}")

        return True

    except Exception as e:
        print(f"[FAIL] Error reading requirements.txt: {e}")
        return False

def check_git_repository():
    """Check if this is a git repository."""
    if os.path.exists(".git"):
        print("[OK] Git repository detected")
        return True
    else:
        print("[FAIL] Not a git repository - GitHub Actions require a git repository")
        return False

def validate_secrets_documentation():
    """Check if secrets are documented."""
    setup_file = "MONTHLY_SCAN_SETUP.md"

    if check_file_exists(setup_file, "Setup documentation"):
        try:
            with open(setup_file, 'r') as f:
                content = f.read()

            if "GOOGLE_WORKSPACE_WEBHOOK_URL" in content:
                print("[OK] Google Workspace webhook configuration documented")
            else:
                print("[WARN] Google Workspace webhook not documented in setup")

            return True
        except Exception as e:
            print(f"[FAIL] Error reading setup documentation: {e}")
            return False

    return False

def main():
    """Main validation function."""
    print("Validating Monthly Security Scan Workflow Configuration")
    print("=" * 60)

    validation_results = []

    # Run all validations
    print("\nChecking project structure...")
    validation_results.append(check_git_repository())
    validation_results.append(validate_autoDAST_structure())

    print("\nValidating workflow configuration...")
    validation_results.append(validate_workflow_file())

    print("\nChecking dependencies...")
    validation_results.append(validate_requirements())
    validation_results.append(check_python_dependencies())

    print("\nChecking documentation...")
    validation_results.append(validate_secrets_documentation())

    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)

    passed = sum(validation_results)
    total = len(validation_results)

    if passed == total:
        print(f"All validations passed ({passed}/{total})")
        print("\nYour workflow is ready to use!")
        print("\nNext steps:")
        print("1. Add GOOGLE_WORKSPACE_WEBHOOK_URL to GitHub repository secrets")
        print("2. Update target list in the workflow file")
        print("3. Test the workflow manually or wait for the scheduled run")
        return 0
    else:
        print(f"Some validations failed ({passed}/{total})")
        print(f"\nPlease fix the issues above before using the workflow.")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)