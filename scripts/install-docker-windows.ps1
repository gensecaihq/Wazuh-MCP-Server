# Wazuh MCP Server - Docker Installation Script for Windows
# Supports: Windows 10 Pro/Enterprise/Education, Windows 11, Windows Server 2019+

param(
    [switch]$UseWSL2 = $true,
    [switch]$Force = $false,
    [switch]$Verbose = $false
)

$ScriptVersion = "v2.0.0"
$DockerDesktopVersion = "4.26.1"

# Set error action preference
$ErrorActionPreference = "Stop"

# Enable verbose output if requested
if ($Verbose) {
    $VerbosePreference = "Continue"
}

# Colors for output (Windows PowerShell compatible)
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    switch ($Color) {
        "Red" { Write-Host $Message -ForegroundColor Red }
        "Green" { Write-Host $Message -ForegroundColor Green }
        "Yellow" { Write-Host $Message -ForegroundColor Yellow }
        "Blue" { Write-Host $Message -ForegroundColor Blue }
        "Cyan" { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
}

# Logging functions
function Write-Info { Write-ColorOutput "[INFO] $args" "Blue" }
function Write-Success { Write-ColorOutput "[SUCCESS] $args" "Green" }
function Write-Warning { Write-ColorOutput "[WARNING] $args" "Yellow" }
function Write-Error { Write-ColorOutput "[ERROR] $args" "Red" }

# Banner
function Show-Banner {
    Write-Host "=================================================================="
    Write-Host "🐳 Wazuh MCP Server - Docker Installation (Windows)" -ForegroundColor Cyan
    Write-Host "=================================================================="
    Write-Host "Version: $ScriptVersion"
    Write-Host "Supported: Windows 10 Pro/Enterprise/Education, Windows 11, Windows Server 2019+"
    Write-Host "=================================================================="
    Write-Host ""
}

# Check if running as Administrator
function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check Windows version and edition
function Test-WindowsCompatibility {
    Write-Info "Checking Windows compatibility..."
    
    $osInfo = Get-ComputerInfo
    $windowsVersion = $osInfo.WindowsVersion
    $windowsEdition = $osInfo.WindowsEditionId
    $buildNumber = $osInfo.WindowsBuildNumber
    
    Write-Info "Windows Version: $($osInfo.WindowsProductName)"
    Write-Info "Build Number: $buildNumber"
    Write-Info "Edition: $windowsEdition"
    
    # Check minimum Windows version (Windows 10 build 19041 or Windows 11)
    if ($buildNumber -lt 19041) {
        Write-Error "Windows 10 build 19041 (version 2004) or later required. Current build: $buildNumber"
        exit 1
    }
    
    # Check Windows edition
    $supportedEditions = @("Professional", "Enterprise", "Education", "ServerDatacenter", "ServerStandard")
    if ($windowsEdition -notin $supportedEditions) {
        Write-Warning "Windows edition '$windowsEdition' may not support Docker Desktop with Hyper-V"
        Write-Warning "Consider using Docker with WSL2 backend instead"
    }
    
    Write-Success "Windows compatibility verified"
    
    return @{
        Version = $windowsVersion
        Build = $buildNumber
        Edition = $windowsEdition
    }
}

# Check system requirements
function Test-SystemRequirements {
    Write-Info "Checking system requirements..."
    
    # Check memory
    $totalMemoryGB = [Math]::Round((Get-ComputerInfo).TotalPhysicalMemory / 1GB, 1)
    if ($totalMemoryGB -lt 4) {
        Write-Warning "Low memory detected: ${totalMemoryGB}GB. Docker Desktop requires 4GB minimum."
    } else {
        Write-Success "Memory: ${totalMemoryGB}GB"
    }
    
    # Check disk space
    $systemDrive = Get-PSDrive C
    $freeSpaceGB = [Math]::Round($systemDrive.Free / 1GB, 1)
    if ($freeSpaceGB -lt 20) {
        Write-Warning "Low disk space: ${freeSpaceGB}GB. Docker Desktop requires 20GB minimum."
    } else {
        Write-Success "Disk space: ${freeSpaceGB}GB available"
    }
    
    # Check virtualization
    $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All 2>$null
    $vmPlatform = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform 2>$null
    
    Write-Info "Hyper-V: $($hyperVFeature.State)"
    Write-Info "Virtual Machine Platform: $($vmPlatform.State)"
}

# Enable required Windows features
function Enable-RequiredFeatures {
    param([bool]$UseWSL2)
    
    Write-Info "Enabling required Windows features..."
    
    if ($UseWSL2) {
        Write-Info "Configuring for WSL2 backend..."
        
        # Enable WSL and Virtual Machine Platform
        $features = @("Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform")
        
        foreach ($feature in $features) {
            $featureStatus = Get-WindowsOptionalFeature -Online -FeatureName $feature
            if ($featureStatus.State -ne "Enabled") {
                Write-Info "Enabling $feature..."
                Enable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
            } else {
                Write-Success "$feature already enabled"
            }
        }
        
        # Download and install WSL2 Linux kernel update
        $kernelUpdateUrl = "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi"
        $kernelUpdatePath = "$env:TEMP\wsl_update_x64.msi"
        
        Write-Info "Downloading WSL2 Linux kernel update..."
        Invoke-WebRequest -Uri $kernelUpdateUrl -OutFile $kernelUpdatePath
        
        Write-Info "Installing WSL2 Linux kernel update..."
        Start-Process msiexec.exe -ArgumentList "/i `"$kernelUpdatePath`" /quiet" -Wait
        
        # Set WSL2 as default
        wsl --set-default-version 2
        
    } else {
        Write-Info "Configuring for Hyper-V backend..."
        
        # Enable Hyper-V
        $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
        if ($hyperVFeature.State -ne "Enabled") {
            Write-Info "Enabling Hyper-V..."
            Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart
        } else {
            Write-Success "Hyper-V already enabled"
        }
    }
    
    Write-Success "Required features enabled"
}

# Check for existing Docker installations
function Test-ExistingDocker {
    Write-Info "Checking for existing Docker installations..."
    
    # Check for Docker Desktop
    $dockerDesktopPath = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"
    if (Test-Path $dockerDesktopPath) {
        Write-Warning "Docker Desktop already installed at: $dockerDesktopPath"
        
        # Get version if available
        try {
            $dockerVersion = & docker --version 2>$null
            if ($dockerVersion) {
                Write-Info "Current Docker version: $dockerVersion"
            }
        } catch {
            Write-Warning "Docker CLI not available in PATH"
        }
        
        if (-not $Force) {
            $response = Read-Host "Do you want to continue with the existing installation? (y/N)"
            if ($response -notmatch '^[Yy]') {
                Write-Info "Continuing with fresh installation..."
                return $false
            } else {
                Write-Info "Using existing Docker installation"
                return $true
            }
        }
    }
    
    return $false
}

# Uninstall existing Docker
function Remove-ExistingDocker {
    Write-Info "Removing existing Docker installations..."
    
    # Stop Docker Desktop if running
    $dockerProcesses = Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue
    if ($dockerProcesses) {
        Write-Info "Stopping Docker Desktop..."
        $dockerProcesses | Stop-Process -Force
        Start-Sleep -Seconds 10
    }
    
    # Uninstall Docker Desktop
    $uninstallPath = "${env:ProgramFiles}\Docker\Docker\unins000.exe"
    if (Test-Path $uninstallPath) {
        Write-Info "Uninstalling Docker Desktop..."
        Start-Process -FilePath $uninstallPath -ArgumentList "/SILENT" -Wait
    }
    
    # Clean up remaining files
    $dockerPaths = @(
        "${env:ProgramFiles}\Docker",
        "${env:APPDATA}\Docker",
        "${env:LOCALAPPDATA}\Docker"
    )
    
    foreach ($path in $dockerPaths) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Success "Existing Docker installations removed"
}

# Install Docker Desktop
function Install-DockerDesktop {
    param([bool]$UseWSL2)
    
    Write-Info "Installing Docker Desktop..."
    
    # Determine download URL
    $dockerInstallerUrl = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
    $installerPath = "$env:TEMP\DockerDesktopInstaller.exe"
    
    # Download Docker Desktop installer
    Write-Info "Downloading Docker Desktop installer..."
    Invoke-WebRequest -Uri $dockerInstallerUrl -OutFile $installerPath
    
    # Install Docker Desktop
    Write-Info "Installing Docker Desktop (this may take several minutes)..."
    
    $installArgs = @("install", "--quiet")
    if ($UseWSL2) {
        $installArgs += "--backend=wsl-2"
    } else {
        $installArgs += "--backend=hyper-v"
    }
    
    $process = Start-Process -FilePath $installerPath -ArgumentList $installArgs -Wait -PassThru
    
    if ($process.ExitCode -eq 0) {
        Write-Success "Docker Desktop installed successfully"
    } else {
        Write-Error "Docker Desktop installation failed with exit code: $($process.ExitCode)"
        exit 1
    }
    
    # Clean up installer
    Remove-Item -Path $installerPath -Force -ErrorAction SilentlyContinue
}

# Configure Docker Desktop
function Set-DockerConfiguration {
    Write-Info "Configuring Docker Desktop..."
    
    # Start Docker Desktop
    Write-Info "Starting Docker Desktop..."
    $dockerDesktopPath = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"
    Start-Process -FilePath $dockerDesktopPath -WindowStyle Hidden
    
    # Wait for Docker to start
    Write-Info "Waiting for Docker to start (this may take a few minutes)..."
    
    $timeout = 300  # 5 minutes
    $elapsed = 0
    
    do {
        Start-Sleep -Seconds 10
        $elapsed += 10
        
        try {
            $dockerInfo = & docker info 2>$null
            if ($dockerInfo) {
                break
            }
        } catch {
            # Continue waiting
        }
        
        Write-Host "." -NoNewline
        
        if ($elapsed -ge $timeout) {
            Write-Error "Docker failed to start within $timeout seconds"
            exit 1
        }
    } while ($true)
    
    Write-Host ""
    Write-Success "Docker Desktop started successfully"
    
    # Configure Docker settings
    $dockerConfigPath = "$env:APPDATA\Docker\settings.json"
    $dockerConfigDir = Split-Path $dockerConfigPath -Parent
    
    if (-not (Test-Path $dockerConfigDir)) {
        New-Item -Path $dockerConfigDir -ItemType Directory -Force
    }
    
    $dockerConfig = @{
        "buildkitEnabled" = $true
        "analyticsEnabled" = $false
        "autoStart" = $true
        "showWindowsContainers" = $false
        "exposeDockerAPIOnTcp2375" = $false
        "displayedTutorial" = $true
    }
    
    $dockerConfig | ConvertTo-Json -Depth 10 | Set-Content $dockerConfigPath
    
    Write-Success "Docker configured"
}

# Verify Docker installation
function Test-DockerInstallation {
    Write-Info "Verifying Docker installation..."
    
    # Check Docker version
    try {
        $dockerVersion = & docker --version
        Write-Success "Docker version: $dockerVersion"
    } catch {
        Write-Error "Docker command not found"
        return $false
    }
    
    # Check Docker Compose
    try {
        $composeVersion = & docker compose version
        Write-Success "Docker Compose version: $composeVersion"
    } catch {
        Write-Error "Docker Compose not available"
        return $false
    }
    
    # Test Docker with hello-world
    Write-Info "Testing Docker installation..."
    try {
        $testOutput = & docker run --rm hello-world 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Docker is working correctly"
            return $true
        } else {
            Write-Error "Docker test failed"
            return $false
        }
    } catch {
        Write-Error "Docker test failed: $_"
        return $false
    }
}

# Install additional tools
function Install-AdditionalTools {
    Write-Info "Installing additional development tools..."
    
    # Check if Chocolatey is installed
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Info "Installing Chocolatey package manager..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }
    
    # Install useful tools
    $tools = @("git", "curl", "wget", "jq", "python3")
    foreach ($tool in $tools) {
        try {
            choco install $tool -y --limit-output
        } catch {
            Write-Warning "Failed to install $tool via Chocolatey"
        }
    }
    
    Write-Success "Additional tools installed"
}

# Setup Wazuh MCP Server
function Set-WazuhMCPServer {
    Write-Info "Setting up Wazuh MCP Server..."
    
    # Create project directory
    $projectDir = "$env:USERPROFILE\wazuh-mcp-server"
    if (-not (Test-Path $projectDir)) {
        New-Item -Path $projectDir -ItemType Directory -Force
        Set-Location $projectDir
        
        # Download or clone the project
        if (Get-Command git -ErrorAction SilentlyContinue) {
            Write-Info "Cloning Wazuh MCP Server repository..."
            try {
                git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git .
            } catch {
                Write-Error "Failed to clone repository"
                return $false
            }
        } else {
            Write-Info "Git not available. Please download the project manually."
            Write-Info "Visit: https://github.com/gensecaihq/Wazuh-MCP-Server"
            return $false
        }
    } else {
        Set-Location $projectDir
        Write-Info "Using existing project directory: $projectDir"
    }
    
    Write-Success "Wazuh MCP Server setup complete"
    Write-Info "Project location: $projectDir"
    return $true
}

# Generate deployment script
function New-DeploymentScript {
    Write-Info "Generating deployment script..."
    
    $deployScript = @'
@echo off
echo Starting Wazuh MCP Server deployment...

REM Check if Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker is not running!
    echo Please start Docker Desktop and try again.
    pause
    exit /b 1
)

REM Check if .env exists
if not exist .env (
    echo ERROR: .env file not found!
    echo Please run: python configure.py
    echo Or create .env file manually with required settings.
    pause
    exit /b 1
)

echo Configuration loaded
echo Building Docker image...
docker compose build

echo Starting services...
docker compose up -d

echo Checking service status...
docker compose ps

echo Deployment complete!
echo.
echo Next steps:
echo 1. Check logs: docker compose logs -f wazuh-mcp-server
echo 2. Test functionality: python test-functionality.py
echo 3. Verify production readiness: python validate-production.py --quick
pause
'@
    
    $deployScriptPath = "$env:USERPROFILE\wazuh-mcp-server\deploy.bat"
    $deployScript | Set-Content $deployScriptPath
    
    Write-Success "Deployment script created: $deployScriptPath"
}

# Generate Claude Desktop configuration helper
function New-ClaudeDesktopHelper {
    Write-Info "Generating Claude Desktop configuration helper..."
    
    $claudeScript = @'
@echo off
echo Setting up Claude Desktop integration...

set "CLAUDE_CONFIG_DIR=%APPDATA%\Claude"
set "CLAUDE_CONFIG_FILE=%CLAUDE_CONFIG_DIR%\claude_desktop_config.json"

REM Create config directory if it doesn't exist
if not exist "%CLAUDE_CONFIG_DIR%" mkdir "%CLAUDE_CONFIG_DIR%"

REM Check if config file exists
if exist "%CLAUDE_CONFIG_FILE%" (
    echo Existing Claude Desktop config found
    copy "%CLAUDE_CONFIG_FILE%" "%CLAUDE_CONFIG_FILE%.backup.%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%" >nul
    echo Backup created
)

REM Generate configuration
echo {> "%CLAUDE_CONFIG_FILE%"
echo   "mcpServers": {>> "%CLAUDE_CONFIG_FILE%"
echo     "wazuh": {>> "%CLAUDE_CONFIG_FILE%"
echo       "command": "docker",>> "%CLAUDE_CONFIG_FILE%"
echo       "args": ["exec", "-i", "wazuh-mcp-server", "./wazuh-mcp-server", "--stdio"],>> "%CLAUDE_CONFIG_FILE%"
echo       "env": {}>> "%CLAUDE_CONFIG_FILE%"
echo     }>> "%CLAUDE_CONFIG_FILE%"
echo   }>> "%CLAUDE_CONFIG_FILE%"
echo }>> "%CLAUDE_CONFIG_FILE%"

echo Claude Desktop configuration created
echo Location: %CLAUDE_CONFIG_FILE%
echo.
echo Please restart Claude Desktop for changes to take effect
echo Make sure your Wazuh MCP Server container is running: docker compose up -d
pause
'@
    
    $claudeScriptPath = "$env:USERPROFILE\wazuh-mcp-server\setup-claude-desktop.bat"
    $claudeScript | Set-Content $claudeScriptPath
    
    Write-Success "Claude Desktop helper created: $claudeScriptPath"
}

# Show final instructions
function Show-FinalInstructions {
    Write-Host ""
    Write-Host "==================================================================" -ForegroundColor Cyan
    Write-Host "🎉 Docker Installation Complete!" -ForegroundColor Green
    Write-Host "==================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Success "Docker Desktop: Installed and running"
    Write-Success "Docker Compose: Available"
    Write-Success "Wazuh MCP Server: Ready for deployment"
    Write-Host ""
    Write-Info "Project location: $env:USERPROFILE\wazuh-mcp-server"
    Write-Host ""
    Write-Host "🔧 Next steps:" -ForegroundColor Yellow
    Write-Host "1. Configure your Wazuh connection:"
    Write-Host "   cd $env:USERPROFILE\wazuh-mcp-server"
    Write-Host "   python configure.py"
    Write-Host ""
    Write-Host "2. Deploy the server:"
    Write-Host "   .\deploy.bat"
    Write-Host ""
    Write-Host "3. Setup Claude Desktop integration:"
    Write-Host "   .\setup-claude-desktop.bat"
    Write-Host ""
    Write-Host "4. Or manually deploy:"
    Write-Host "   docker compose up -d"
    Write-Host ""
    Write-Host "📖 For detailed configuration, see:" -ForegroundColor Blue
    Write-Host "   - README.md"
    Write-Host "   - PRODUCTION_DEPLOYMENT.md"
    Write-Host ""
    Write-Host "🔍 Verify installation:" -ForegroundColor Blue
    Write-Host "   docker --version"
    Write-Host "   docker compose version"
    Write-Host "   docker run hello-world"
    Write-Host ""
    Write-Host "💡 Windows specific notes:" -ForegroundColor Cyan
    Write-Host "   - Docker Desktop will start automatically on boot"
    Write-Host "   - You can manage Docker from the system tray"
    Write-Host "   - Claude Desktop config: %APPDATA%\Claude\"
    Write-Host "==================================================================" -ForegroundColor Cyan
}

# Main execution
function Main {
    Show-Banner
    
    # Check administrator privileges
    if (-not (Test-AdminPrivileges)) {
        Write-Error "This script must be run as Administrator"
        Write-Info "Right-click PowerShell and select 'Run as Administrator'"
        exit 1
    }
    
    # Check system compatibility
    $systemInfo = Test-WindowsCompatibility
    Test-SystemRequirements
    
    # Check for existing Docker
    $hasExistingDocker = Test-ExistingDocker
    
    if (-not $hasExistingDocker -or $Force) {
        # Remove existing installations if force is specified
        if ($Force) {
            Remove-ExistingDocker
        }
        
        # Enable required features
        Enable-RequiredFeatures -UseWSL2 $UseWSL2
        
        # Install Docker Desktop
        Install-DockerDesktop -UseWSL2 $UseWSL2
        
        # Configure Docker
        Set-DockerConfiguration
    }
    
    # Install additional tools
    Install-AdditionalTools
    
    # Verify installation
    if (Test-DockerInstallation) {
        if (Set-WazuhMCPServer) {
            New-DeploymentScript
            New-ClaudeDesktopHelper
            Show-FinalInstructions
        }
    } else {
        Write-Error "Docker verification failed"
        exit 1
    }
    
    # Check if restart is required
    $restartRequired = $false
    $features = @("Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform", "Microsoft-Hyper-V-All")
    
    foreach ($feature in $features) {
        $featureInfo = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
        if ($featureInfo -and $featureInfo.RestartRequired) {
            $restartRequired = $true
            break
        }
    }
    
    if ($restartRequired) {
        Write-Warning "A system restart is required to complete the installation."
        $response = Read-Host "Do you want to restart now? (y/N)"
        if ($response -match '^[Yy]') {
            Restart-Computer -Force
        } else {
            Write-Info "Please restart your computer manually to complete the installation."
        }
    }
}

# Error handling
trap {
    Write-Error "Installation failed: $_"
    Write-Info "Common troubleshooting steps:"
    Write-Info "- Ensure you're running as Administrator"
    Write-Info "- Check Windows version compatibility"
    Write-Info "- Verify virtualization is enabled in BIOS"
    Write-Info "- Try running with -UseWSL2 `$false for Hyper-V backend"
    exit 1
}

# Run main function
Main