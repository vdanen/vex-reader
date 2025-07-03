# Testing Guide for vex-reader

This document explains how to run tests for the vex-reader project.

## Test Setup

The project has been configured with a comprehensive testing setup that includes:

- **Unit tests** using Python's built-in `unittest` framework
- **pytest** support for advanced testing features
- **Coverage reporting** to track test coverage
- **GitHub Actions** for continuous integration
- **Multiple Python version support** (3.8 - 3.12)

## Test Structure

```
tests/
├── __init__.py
├── test_vex1.py           # Main test file
├── cve-2024-21626.json    # Test data
├── cve-2024-40951.json    # Test data
└── cisco-sa-openssh-rce-2024.json  # Test data
```

## Running Tests

### Option 1: Using the Test Runner Script

The easiest way to run tests is using the provided test runner script:

```bash
# Run tests with unittest (default)
python run_tests.py --verbose

# Run tests with unittest only
python run_tests.py --unittest --verbose

# Run tests with pytest and coverage
python run_tests.py --pytest --coverage --verbose

# Install dependencies and run tests
python run_tests.py --install-deps --verbose
```

### Option 2: Using Makefile

```bash
# Show available targets
make help

# Run basic tests
make test

# Install development dependencies
make install-dev

# Run tests with coverage (requires pytest)
make test-cov

# Run linting checks
make lint

# Clean build artifacts
make clean

# Build the package
make build
```

### Option 3: Direct Commands

```bash
# Using unittest (no additional dependencies required)
python -m unittest discover tests -v

# Using pytest (requires pytest installation)
python -m pytest tests/ -v

# Using pytest with coverage
python -m pytest tests/ --cov=vex --cov-report=term-missing --cov-report=html
```

## Installing Test Dependencies

To install the optional test dependencies:

```bash
# Install test dependencies
pip install -e .[test]

# Or install specific packages
pip install pytest pytest-cov pytest-xdist
```

## Test Coverage

The project is configured to generate coverage reports:

- **Terminal output**: Shows coverage percentage per file
- **HTML report**: Generates detailed coverage report in `htmlcov/` directory

```bash
# Generate coverage report
python -m pytest tests/ --cov=vex --cov-report=html
# Open htmlcov/index.html in your browser
```

## Continuous Integration

The project uses GitHub Actions for continuous integration:

- **Multiple Python versions**: Tests run on Python 3.8, 3.9, 3.10, 3.11, and 3.12
- **Automatic testing**: Tests run on every push and pull request
- **Code quality checks**: Includes linting and security scanning
- **Build verification**: Ensures the package builds correctly

### GitHub Actions Workflow

The CI workflow includes:

1. **Test job**: Runs tests on multiple Python versions
2. **Lint job**: Checks code quality with flake8, black, and isort
3. **Security job**: Scans for security vulnerabilities
4. **Build job**: Builds and validates the package

## Test Data

The tests use real VEX (Vulnerability Exchange) files as test data:

- `cve-2024-21626.json`: Contains CVSS data and vulnerability information
- `cve-2024-40951.json`: Contains vulnerability data without CVSS scores
- `cisco-sa-openssh-rce-2024.json`: Cisco security advisory format

## Writing New Tests

When adding new tests:

1. Follow the existing test structure in `tests/test_vex1.py`
2. Use descriptive test method names starting with `test_`
3. Include test data files in the `tests/` directory
4. Use proper assertions and error handling
5. Test both success and failure cases

Example test structure:

```python
import os
import sys
from unittest import TestCase

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vex import Vex, VexPackages

class TestNewFeature(TestCase):
    def setUp(self):
        test_file = os.path.join(os.path.dirname(__file__), 'test-data.json')
        self.vex = Vex(test_file)
    
    def test_feature_functionality(self):
        # Test implementation here
        self.assertEqual(self.vex.some_property, 'expected_value')
```

## Troubleshooting

### Common Issues

1. **Import errors**: Make sure the vex module is properly installed
2. **File not found**: Check that test data files exist in the tests directory
3. **Permission errors**: Ensure you have read permissions for test files
4. **Python version**: Some features may require specific Python versions

### Getting Help

If you encounter issues:

1. Check the GitHub Actions logs for CI failures
2. Run tests locally with verbose output
3. Verify all dependencies are installed
4. Check that test data files are present and accessible

## Best Practices

1. **Run tests before committing**: Always run tests locally before pushing
2. **Keep tests fast**: Unit tests should run quickly
3. **Test edge cases**: Include tests for error conditions and edge cases
4. **Maintain test data**: Keep test data files up to date
5. **Document changes**: Update this guide when adding new testing features 