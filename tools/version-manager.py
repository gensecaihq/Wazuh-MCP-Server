#!/usr/bin/env python3
"""
Wazuh MCP Server - Version Manager
Manages synchronized releases across multiple packages.
"""

import subprocess
import sys
from pathlib import Path
from typing import Dict, List
try:
    import tomllib
except ImportError:
    try:
        import toml as tomllib
    except ImportError:
        tomllib = None
import click

class VersionManager:
    """Manages versions across multiple packages."""
    
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.packages_dir = repo_root / "packages"
        
    def get_package_version(self, package: str) -> str:
        """Get current version of a package."""
        pyproject_path = self.packages_dir / package / "pyproject.toml"
        if not pyproject_path.exists():
            return "0.0.0"
        
        try:
            if hasattr(tomllib, 'load'):
                with open(pyproject_path, 'rb') as f:
                    data = tomllib.load(f)
            else:
                # Fallback to simple parsing
                with open(pyproject_path) as f:
                    for line in f:
                        if line.strip().startswith('version = '):
                            return line.split('"')[1]
                return "0.0.0"
        except Exception:
            return "0.0.0"
        
        return data.get("project", {}).get("version", "0.0.0")
    
    def set_package_version(self, package: str, version: str):
        """Set version for a package."""
        pyproject_path = self.packages_dir / package / "pyproject.toml"
        
        # Read current content
        with open(pyproject_path, 'r') as f:
            content = f.read()
        
        # Simple find and replace for version
        import re
        pattern = r'version = "[^"]*"'
        replacement = f'version = "{version}"'
        content = re.sub(pattern, replacement, content)
        
        # Write back
        with open(pyproject_path, 'w') as f:
            f.write(content)
        
        print(f"✓ Updated {package} to v{version}")
    
    def get_all_versions(self) -> Dict[str, str]:
        """Get versions of all packages."""
        packages = ["core", "stdio", "remote"]
        return {pkg: self.get_package_version(pkg) for pkg in packages}
    
    def update_core_dependencies(self, core_version: str):
        """Update core dependency version in transport packages."""
        transport_packages = ["stdio", "remote"]
        
        for package in transport_packages:
            pyproject_path = self.packages_dir / package / "pyproject.toml"
            
            if not pyproject_path.exists():
                continue
                
            # Read current content
            with open(pyproject_path, 'r') as f:
                content = f.read()
            
            # Update core dependency constraint
            major_version = core_version.split('.')[0]
            next_major = str(int(major_version) + 1)
            new_dep = f"wazuh-mcp-core>={core_version},<{next_major}.0.0"
            
            import re
            pattern = r'wazuh-mcp-core[>=<,\.\d]*'
            content = re.sub(pattern, new_dep, content)
            
            # Write back
            with open(pyproject_path, 'w') as f:
                f.write(content)
            
            print(f"✓ Updated {package} core dependency to >={core_version}")
    
    def tag_release(self, package: str, version: str):
        """Create git tag for package release."""
        tag_name = f"{package}-v{version}"
        
        try:
            subprocess.run(["git", "tag", tag_name], check=True)
            print(f"✓ Created tag {tag_name}")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to create tag {tag_name}")

@click.group()
def cli():
    """Wazuh MCP Server Version Manager"""
    pass

@cli.command()
def status():
    """Show current versions of all packages."""
    manager = VersionManager(Path.cwd())
    versions = manager.get_all_versions()
    
    print("📦 Package Versions:")
    print("-" * 30)
    for package, version in versions.items():
        print(f"{package:10} v{version}")

@cli.command()
@click.argument('package')
@click.argument('version')
def bump(package: str, version: str):
    """Bump version for a specific package."""
    manager = VersionManager(Path.cwd())
    
    if package not in ["core", "stdio", "remote"]:
        print(f"❌ Invalid package: {package}")
        sys.exit(1)
    
    manager.set_package_version(package, version)
    
    # If core version changed, update dependencies
    if package == "core":
        manager.update_core_dependencies(version)
    
    # Create git tag
    manager.tag_release(package, version)

@cli.command()
@click.argument('core_version')
@click.argument('stdio_version')
@click.argument('remote_version')
def coordinated_release(core_version: str, stdio_version: str, remote_version: str):
    """Perform coordinated release of all packages."""
    manager = VersionManager(Path.cwd())
    
    print("🚀 Starting coordinated release...")
    print("=" * 40)
    
    # Update core first
    manager.set_package_version("core", core_version)
    manager.tag_release("core", core_version)
    
    # Update core dependencies
    manager.update_core_dependencies(core_version)
    
    # Update transport packages
    manager.set_package_version("stdio", stdio_version)
    manager.set_package_version("remote", remote_version)
    
    # Create tags
    manager.tag_release("stdio", stdio_version)
    manager.tag_release("remote", remote_version)
    
    print("=" * 40)
    print("✅ Coordinated release completed!")
    print(f"📦 Core: v{core_version}")
    print(f"📡 STDIO: v{stdio_version}")  
    print(f"🌐 Remote: v{remote_version}")

@cli.command()
def validate():
    """Validate package configurations."""
    manager = VersionManager(Path.cwd())
    packages_dir = manager.packages_dir
    
    print("🔍 Validating package configurations...")
    
    issues = []
    
    # Check if all packages exist
    required_packages = ["core", "stdio", "remote"]
    for package in required_packages:
        package_dir = packages_dir / package
        if not package_dir.exists():
            issues.append(f"Missing package directory: {package}")
            continue
            
        pyproject = package_dir / "pyproject.toml"
        if not pyproject.exists():
            issues.append(f"Missing pyproject.toml in {package}")
            continue
            
        # Check src directory
        src_dir = package_dir / "src"
        if not src_dir.exists():
            issues.append(f"Missing src/ directory in {package}")
    
    # Check dependency versions
    versions = manager.get_all_versions()
    core_version = versions["core"]
    
    for transport_package in ["stdio", "remote"]:
        pyproject_path = packages_dir / transport_package / "pyproject.toml"
        if pyproject_path.exists():
            try:
                if hasattr(tomllib, 'load'):
                    with open(pyproject_path, 'rb') as f:
                        data = tomllib.load(f)
                else:
                    # Skip validation if no toml parser
                    continue
            except Exception:
                continue
            
            # Check core dependency
            deps = data["project"]["dependencies"]
            core_dep = next((dep for dep in deps if dep.startswith("wazuh-mcp-core")), None)
            
            if not core_dep:
                issues.append(f"{transport_package} missing wazuh-mcp-core dependency")
    
    if issues:
        print("❌ Validation failed:")
        for issue in issues:
            print(f"  • {issue}")
        sys.exit(1)
    else:
        print("✅ All package configurations are valid!")

if __name__ == "__main__":
    cli()