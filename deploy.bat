@echo off
REM Wazuh MCP Server - Windows Deployment Script
REM Calls the Python deployment script for OS-agnostic deployment

SETLOCAL EnableDelayedExpansion

REM Check if Python is available
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.9+ from https://www.python.org/downloads/
    exit /b 1
)

REM Check if Docker is available
docker --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: Docker is not installed or not in PATH
    echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop
    exit /b 1
)

REM Run the Python deployment script with all arguments
python deploy.py %*

exit /b %ERRORLEVEL%
