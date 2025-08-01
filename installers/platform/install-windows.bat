@echo off
setlocal
REM Windows Installation Script for Wazuh MCP Server
REM ================================================

echo ================================================================================
echo    WAZUH MCP SERVER - WINDOWS INSTALLATION
echo ================================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo [INFO] Python version:
python --version

REM Check Python version (basic check)
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [INFO] Python version detected: %PYTHON_VERSION%

REM Create virtual environment
echo.
echo [INFO] Creating virtual environment...
if exist venv (
    echo [WARN] Virtual environment already exists
    choice /C YN /M "Do you want to recreate it? This will delete existing packages"
    if errorlevel 2 goto skip_venv_creation
    echo [INFO] Removing existing virtual environment...
    rmdir /s /q venv
)

python -m venv venv
if errorlevel 1 (
    echo [ERROR] Failed to create virtual environment
    pause
    exit /b 1
)

:skip_venv_creation

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment
    pause
    exit /b 1
)

REM Upgrade pip
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip

REM Install package in development mode
echo [INFO] Installing Wazuh MCP Server...
pip install -e .
if errorlevel 1 (
    echo [ERROR] Failed to install Wazuh MCP Server
    pause
    exit /b 1
)

REM Install additional Windows-specific dependencies
echo [INFO] Installing Windows-specific dependencies...
pip install colorama psutil
pip install python-dotenv --upgrade

REM Create .env file if it doesn't exist
if not exist .env (
    echo [INFO] Creating .env file from template...
    copy .env.example .env
    if errorlevel 1 (
        echo [WARN] Could not copy .env.example to .env
        echo Please manually copy .env.example to .env and configure it
    ) else (
        echo [INFO] .env file created. Please edit it with your Wazuh configuration.
    )
) else (
    echo [INFO] .env file already exists
)

REM Create logs directory
if not exist logs (
    echo [INFO] Creating logs directory...
    mkdir logs
)

REM Set console encoding to UTF-8 for better Unicode support
echo [INFO] Configuring console for UTF-8...
chcp 65001 >nul 2>&1
if errorlevel 1 (
    echo [WARN] Could not set UTF-8 encoding. Unicode characters may not display correctly.
    echo [INFO] Consider using Windows Terminal for better Unicode support.
)

REM Run validation to check installation
echo [INFO] Running installation validation...
echo.
python validate_setup.py
if errorlevel 1 (
    echo.
    echo [WARN] Validation found issues. Installation may be incomplete.
    echo Please check the validation output above for details.
    echo.
    echo You can try to auto-fix issues by running:
    echo   python validate_setup.py --fix
    echo.
    echo Note: Auto-fix is not supported on Windows. Manual fixes may be required.
) else (
    echo.
    echo [SUCCESS] Validation passed! Installation is complete and ready to use.
)

echo.
echo ================================================================================
echo    INSTALLATION COMPLETED
echo ================================================================================
echo.
echo Next steps:
echo 1. Edit .env file with your Wazuh server configuration
echo 2. If validation failed, fix the reported issues
echo 3. Re-run validation: python validate_setup.py
echo 4. If validation passes, add to Claude Desktop configuration
echo.
echo Configuration file: .env
echo Validation command: python validate_setup.py
echo Test connection: python src\wazuh_mcp_server\scripts\test_connection.py
echo.
echo Common Windows issues and solutions:
echo - Character encoding errors: Already configured (chcp 65001)
echo - Unicode display issues: Use Windows Terminal or PowerShell
echo - Permission errors: Run as Administrator or check antivirus settings
echo - Python not found: Ensure Python is in PATH and restart terminal
echo - Pip upgrade fails: Try: python -m pip install --upgrade --force-reinstall pip
echo.
echo For additional help, see: README.md or docs/windows-troubleshooting.md
echo.
pause