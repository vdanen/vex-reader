#!/bin/bash
# Script to install pre-commit hooks for the vex-reader project

set -e

echo "🔧 Installing pre-commit hooks for vex-reader..."

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "❌ Not in a git repository. Please run this script from the project root."
    exit 1
fi

# Create hooks directory if it doesn't exist
mkdir -p hooks

# Check if pre-commit hook already exists
if [ -f ".git/hooks/pre-commit" ]; then
    echo "⚠️  Pre-commit hook already exists."
    read -p "Do you want to overwrite it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Installation cancelled."
        exit 1
    fi
fi

# Copy the pre-commit hook
if [ -f "hooks/pre-commit" ]; then
    cp hooks/pre-commit .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
    echo "✅ Pre-commit hook installed successfully!"
else
    echo "❌ Pre-commit hook file not found at hooks/pre-commit"
    exit 1
fi

# Test the hook
echo "🧪 Testing the pre-commit hook..."
if .git/hooks/pre-commit; then
    echo "✅ Pre-commit hook test passed!"
else
    echo "❌ Pre-commit hook test failed!"
    exit 1
fi

echo ""
echo "🎉 Pre-commit hooks have been installed successfully!"
echo ""
echo "What this means:"
echo "• Tests will run automatically before each commit"
echo "• Commits will be blocked if tests fail"
echo "• Python syntax will be checked before commits"
echo "• Optional linting checks will run if flake8 is available"
echo ""
echo "To disable the hook temporarily, use:"
echo "  git commit --no-verify"
echo ""
echo "To uninstall the hook:"
echo "  rm .git/hooks/pre-commit"
echo ""
echo "Happy coding! 🚀" 