.PHONY: help test test-unit test-cov install install-dev lint clean build upload version run-tests test-all

# Default target
help:
	@echo "Available targets:"
	@echo "  help        - Show this help"
	@echo "  install     - Install the package and dependencies with uv"
	@echo "  install-dev - Same as install (dev dependency group included)"
	@echo "  test        - Run tests with unittest"
	@echo "  test-unit   - Run tests with unittest (verbose)"
	@echo "  test-cov    - Run tests with coverage (requires pytest)"
	@echo "  lint        - Run linting checks"
	@echo "  clean       - Clean build artifacts"
	@echo "  build       - Build the package"
	@echo "  upload      - Upload the package to PyPI"
	@echo "  version     - Bump version, commit, and tag (VERSION=x.y.z)"

# Install the package and dependencies
install:
	uv sync

# Install development dependencies (same as install; dev group is default)
install-dev: install

# Run tests with unittest
test:
	uv run python -m unittest discover tests -v

# Run tests with unittest (verbose)
test-unit:
	uv run python -m unittest discover tests -v

# Run tests with coverage (requires pytest)
test-cov:
	uv run pytest tests/ --cov=vex --cov-report=term-missing --cov-report=html

# Run linting checks
lint:
	@echo "Running flake8..."
	-uv run flake8 vex/ --count --select=E9,F63,F7,F82 --show-source --statistics
	@echo "Running black (check only)..."
	-uv run black --check --diff vex/
	@echo "Running isort (check only)..."
	-uv run isort --check-only --diff vex/

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
	uv build

# Upload the package
upload: build
	uv run twine upload dist/*

# Bump version, commit, and create an annotated git tag.
# Usage: make version VERSION=1.2.3
version:
ifndef VERSION
	$(error VERSION is required. Usage: make version VERSION=1.2.3)
endif
	uv version $(VERSION)
	git add pyproject.toml uv.lock
	git commit -m "Bump version to $(VERSION)"
	git tag -a "v$(VERSION)" -m "v$(VERSION)"
	@echo "Created commit and tag v$(VERSION). Push with: git push && git push origin v$(VERSION)"

# Run the test runner script
run-tests:
	uv run python run_tests.py --verbose

# Install and run tests
test-all: install-dev test
