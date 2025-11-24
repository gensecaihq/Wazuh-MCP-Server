#!/usr/bin/env python3
"""
Release Coordinator - Manages releases across both branches safely
"""

import subprocess
import json
from pathlib import Path

class ReleaseCoordinator:
    """Coordinates releases between main (STDIO) and mcp-remote branches."""
    
    def __init__(self):
        self.repo_root = Path(__file__).parent.parent
    
    def get_current_branch(self) -> str:
        """Get current git branch."""
        try:
            result = subprocess.run(
                ["git", "branch", "--show-current"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except:
            return "unknown"
    
    def switch_branch(self, branch_name: str):
        """Switch to specified branch."""
        try:
            subprocess.run(["git", "checkout", branch_name], check=True)
            print(f"✅ Switched to {branch_name}")
            return True
        except subprocess.CalledProcessError:
            print(f"❌ Failed to switch to {branch_name}")
            return False
    
    def bump_version_in_branch(self, branch_name: str, version: str):
        """Bump version in specified branch."""
        current = self.get_current_branch()
        
        # Switch to target branch
        if not self.switch_branch(branch_name):
            return False
        
        # Bump version using our branch-sync tool
        try:
            subprocess.run([
                "python3", 
                str(self.repo_root / "tools" / "branch-sync.py"), 
                "bump", 
                version
            ], check=True)
            
            # Create tag
            subprocess.run([
                "python3",
                str(self.repo_root / "tools" / "branch-sync.py"),
                "tag"
            ], check=True)
            
            print(f"✅ Updated {branch_name} to v{version}")
            return True
        except subprocess.CalledProcessError:
            print(f"❌ Failed to update {branch_name}")
            return False
        finally:
            # Switch back to original branch
            self.switch_branch(current)
    
    def coordinated_release(self, stdio_version: str, remote_version: str):
        """Perform coordinated release of both branches."""
        print("🚀 Starting Coordinated Release")
        print("=" * 40)
        
        success = True
        
        # Update STDIO (main branch)
        print(f"📡 Updating STDIO to v{stdio_version}...")
        if not self.bump_version_in_branch("main", stdio_version):
            success = False
        
        # Update Remote (mcp-remote branch)  
        print(f"🌐 Updating Remote to v{remote_version}...")
        if not self.bump_version_in_branch("mcp-remote", remote_version):
            success = False
        
        print("=" * 40)
        if success:
            print("✅ Coordinated release completed successfully!")
            print(f"📡 STDIO: v{stdio_version}")
            print(f"🌐 Remote: v{remote_version}")
            
            # Save release info
            release_info = {
                "release_date": str(subprocess.check_output(["date"], text=True).strip()),
                "stdio_version": stdio_version,
                "remote_version": remote_version,
                "status": "success"
            }
            
            release_file = self.repo_root / ".last-release.json"
            with open(release_file, 'w') as f:
                json.dump(release_info, f, indent=2)
            
            print(f"💾 Release info saved to {release_file}")
        else:
            print("❌ Coordinated release had errors!")
    
    def show_release_status(self):
        """Show status of both branches."""
        print("📊 Release Status:")
        print("=" * 30)
        
        current_branch = self.get_current_branch()
        
        # Check main branch
        if current_branch != "main":
            self.switch_branch("main")
        
        subprocess.run([
            "python3",
            str(self.repo_root / "tools" / "branch-sync.py"),
            "status"
        ])
        
        print()
        print("🔄 Checking mcp-remote branch...")
        
        # Check remote branch  
        if self.switch_branch("mcp-remote"):
            subprocess.run([
                "python3", 
                str(self.repo_root / "tools" / "branch-sync.py"),
                "status"
            ])
        else:
            print("⚠️  mcp-remote branch not available")
        
        # Switch back
        self.switch_branch(current_branch)

def main():
    """Main CLI interface."""
    import sys
    
    coordinator = ReleaseCoordinator()
    
    if len(sys.argv) == 1 or sys.argv[1] == "status":
        coordinator.show_release_status()
    elif sys.argv[1] == "release" and len(sys.argv) == 4:
        stdio_version = sys.argv[2]
        remote_version = sys.argv[3]
        coordinator.coordinated_release(stdio_version, remote_version)
    else:
        print("Usage:")
        print("  python3 release-coordinator.py status           # Show status")
        print("  python3 release-coordinator.py release 2.1.1 3.0.1  # Coordinated release")
        print()
        print("Examples:")
        print("  python3 release-coordinator.py release 2.1.1 3.0.1")
        print("  python3 release-coordinator.py release 2.2.0 3.1.0")

if __name__ == "__main__":
    main()