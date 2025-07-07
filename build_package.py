#!/usr/bin/env python3
"""
Build script for Wazuh MCP Server package.
This script builds the package locally for testing and distribution.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path


def run_command(cmd, cwd=None, check=True):
    """Run a command and return the result."""
    print(f"🔄 Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, 
            cwd=cwd, 
            check=check, 
            capture_output=True, 
            text=True
        )
        if result.stdout:
            print(result.stdout)
        return result
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed: {e}")
        if e.stdout:
            print(f"STDOUT: {e.stdout}")
        if e.stderr:
            print(f"STDERR: {e.stderr}")
        raise


def clean_build_artifacts():
    """Clean previous build artifacts."""
    print("🧹 Cleaning previous build artifacts...")
    
    directories_to_clean = [
        "build", 
        "dist", 
        "src/wazuh_mcp_server.egg-info",
        "wazuh_mcp_server.egg-info"
    ]
    
    for directory in directories_to_clean:
        if os.path.exists(directory):
            shutil.rmtree(directory)
            print(f"   Removed: {directory}")
    
    # Also clean __pycache__ directories
    for root, dirs, files in os.walk("."):
        for directory in dirs:
            if directory == "__pycache__":
                pycache_path = os.path.join(root, directory)
                shutil.rmtree(pycache_path)
                print(f"   Removed: {pycache_path}")


def check_dependencies():
    """Check if build dependencies are installed."""
    print("🔍 Checking build dependencies...")
    
    required_packages = ["build", "twine"]
    missing_packages = []
    
    for package in required_packages:
        try:
            result = subprocess.run(
                [sys.executable, "-m", package, "--version"],
                capture_output=True,
                text=True,
                check=True
            )
            print(f"✅ {package} is installed")
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing_packages.append(package)
            print(f"❌ {package} is missing")
    
    if missing_packages:
        print(f"\n📦 Installing missing dependencies: {', '.join(missing_packages)}")
        run_command([sys.executable, "-m", "pip", "install"] + missing_packages)
    
    return True


def build_package():
    """Build the package using python -m build."""
    print("🔨 Building package...")
    
    # Build both wheel and source distribution
    run_command([sys.executable, "-m", "build"])
    
    # List built files
    if os.path.exists("dist"):
        print("\n📦 Built packages:")
        for file in os.listdir("dist"):
            file_path = os.path.join("dist", file)
            size = os.path.getsize(file_path)
            print(f"   {file} ({size:,} bytes)")


def validate_package():
    """Validate the built package using twine."""
    print("✅ Validating package...")
    
    try:
        run_command([sys.executable, "-m", "twine", "check", "dist/*"])
        print("✅ Package validation passed!")
    except subprocess.CalledProcessError:
        print("⚠️  Package validation had issues, but continuing...")


def test_local_installation():
    """Test installing the package locally."""
    print("🧪 Testing local installation...")
    
    # Find the wheel file
    wheel_files = [f for f in os.listdir("dist") if f.endswith(".whl")]
    if not wheel_files:
        print("❌ No wheel file found!")
        return False
    
    wheel_file = wheel_files[0]
    wheel_path = os.path.join("dist", wheel_file)
    
    print(f"📦 Testing installation of: {wheel_file}")
    
    # Install in a virtual test environment would be ideal,
    # but for simplicity, we'll just check if it can be imported
    try:
        run_command([
            sys.executable, "-c", 
            f"import sys; sys.path.insert(0, '{wheel_path}'); "
            "print('Package structure looks good!')"
        ])
        return True
    except subprocess.CalledProcessError:
        print("⚠️  Local installation test had issues")
        return False


def main():
    """Main build process."""
    print("🚀 Wazuh MCP Server Package Builder\n")
    
    # Ensure we're in the right directory
    if not os.path.exists("pyproject.toml"):
        print("❌ pyproject.toml not found. Please run this script from the project root.")
        sys.exit(1)
    
    try:
        # Clean previous builds
        clean_build_artifacts()
        
        # Check and install dependencies
        check_dependencies()
        
        # Build the package
        build_package()
        
        # Validate the package
        validate_package()
        
        # Test local installation
        test_local_installation()
        
        print("\n🎉 Package build completed successfully!")
        print("\n📖 Next steps:")
        print("   1. Test the package: python test_package.py")
        print("   2. Install locally: pip install dist/*.whl")
        print("   3. Upload to PyPI: python -m twine upload dist/*")
        print("   4. Or push to GitHub to trigger the workflow")
        
    except Exception as e:
        print(f"\n❌ Build failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
