.PHONY: help test test-unit test-cov install install-dev lint clean build

# Default target
help:
	@echo "Available targets:"
	@echo "  help        - Show this help"
	@echo "  install     - Install the package"
	@echo "  install-dev - Install development dependencies"
	@echo "  test        - Run tests with unittest"
	@echo "  test-unit   - Run tests with unittest (verbose)"
	@echo "  test-cov    - Run tests with coverage (requires pytest)"
	@echo "  lint        - Run linting checks"
	@echo "  clean       - Clean build artifacts"
	@echo "  build       - Build the package"
	@echo "  upload      - Upload the package to PyPI"

# Install the package
install:
	pip install -e .

# Install development dependencies
install-dev:
	pip install -e .[test]
	pip install -r requirements.txt

# Run tests with unittest
test:
	python -m unittest discover tests -v

# Run tests with unittest (verbose)
test-unit:
	python -m unittest discover tests -v

# Run tests with coverage (requires pytest)
test-cov:
	python -m pytest tests/ --cov=vex --cov-report=term-missing --cov-report=html

# Run linting checks
lint:
	@echo "Running flake8..."
	-flake8 vex/ --count --select=E9,F63,F7,F82 --show-source --statistics
	@echo "Running black (check only)..."
	-black --check --diff vex/
	@echo "Running isort (check only)..."
	-isort --check-only --diff vex/

# Clean build artifacts
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .pytest_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Build the package
build: clean
	python -m build .

# Upload the package
upload: build
	python -m twine upload dist/*

# Run the test runner script
run-tests:
	python run_tests.py --verbose

# Install and run tests
test-all: install-dev test 
