#!/usr/bin/env python3
"""
Test runner for vex-reader project.
This script can run tests with either unittest or pytest.
"""

import os
import sys
import subprocess
import argparse

def run_command(cmd, description="", ignore_errors=False):
    """Run a command and handle errors."""
    print(f"\n{'='*60}")
    print(f"Running: {description or ' '.join(cmd)}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=False)
        print(f"✅ {description or 'Command'} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        if ignore_errors:
            print(f"⚠️  {description or 'Command'} failed but continuing...")
            return False
        else:
            print(f"❌ {description or 'Command'} failed with exit code {e.returncode}")
            return False
    except FileNotFoundError:
        print(f"❌ Command not found: {cmd[0]}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Run tests for vex-reader")
    parser.add_argument("--unittest", action="store_true", help="Use unittest only")
    parser.add_argument("--pytest", action="store_true", help="Use pytest only")
    parser.add_argument("--coverage", action="store_true", help="Run with coverage")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--install-deps", action="store_true", help="Install test dependencies")
    
    args = parser.parse_args()
    
    # Change to project directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    success = True
    
    # Install dependencies if requested
    if args.install_deps:
        print("Installing test dependencies...")
        success &= run_command([sys.executable, "-m", "pip", "install", "-e", ".[test]"], 
                              "Install test dependencies", ignore_errors=True)
        success &= run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                              "Install requirements", ignore_errors=True)
    
    # Run tests
    if args.unittest or (not args.pytest and not args.coverage):
        # Run with unittest
        cmd = [sys.executable, "-m", "unittest", "discover", "tests"]
        if args.verbose:
            cmd.append("-v")
        success &= run_command(cmd, "Run tests with unittest")
    
    if args.pytest or args.coverage:
        # Try to run with pytest
        cmd = [sys.executable, "-m", "pytest", "tests/"]
        if args.verbose:
            cmd.append("-v")
        if args.coverage:
            cmd.extend(["--cov=vex", "--cov-report=term-missing", "--cov-report=html"])
        
        success &= run_command(cmd, "Run tests with pytest", ignore_errors=True)
    
    # Final result
    if success:
        print(f"\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print(f"\n💥 Some tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 