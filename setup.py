#!/usr/bin/env python3
"""Setup script for Wazuh MCP Server package."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

# Read version from __version__.py
version_file = this_directory / "src" / "wazuh_mcp_server" / "__version__.py"
version_dict = {}
exec(version_file.read_text(), version_dict)

setup(
    name="wazuh-mcp-server",
    version=version_dict["__version__"],
    author=version_dict["__author__"],
    author_email=version_dict["__email__"],
    description="Production-grade Model Context Protocol server for Wazuh security platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/socfortress/Wazuh-MCP-Server",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Framework :: AsyncIO",
    ],
    python_requires=">=3.9",
    install_requires=[
        "mcp>=0.9.0",
        "aiohttp>=3.9.0",
        "aiohttp-cors>=0.7.0",
        "websockets>=11.0.0",
        "pyjwt>=2.8.0",
        "urllib3>=2.0.0",
        "python-dateutil>=2.8.2",
        "python-dotenv>=1.0.0",
        "pydantic>=2.0.0",
        "packaging>=21.0",
        "psutil>=5.9.0",
        "certifi>=2023.5.7",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "ruff>=0.1.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.3.0",
        ],
        "docker": [
            "docker>=6.0.0",
            "docker-compose>=1.29.0",
        ],
        "testing": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "coverage>=7.0.0",
            "httpx>=0.24.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "wazuh-mcp-server=wazuh_mcp_server.main:main",
            "wazuh-mcp-test=wazuh_mcp_server.scripts.test_connection:main",
        ],
    },
    include_package_data=True,
    package_data={
        "wazuh_mcp_server": ["*.json", "*.yml", "*.yaml", "*.md", "*.txt"],
    },
    keywords="wazuh security mcp api monitoring siem",
    project_urls={
        "Documentation": "https://github.com/gensecaihq/Wazuh-MCP-Server/blob/main/README.md",
        "Bug Tracker": "https://github.com/gensecaihq/Wazuh-MCP-Server/issues",
        "Source Code": "https://github.com/gensecaihq/Wazuh-MCP-Server",
        "Changelog": "https://github.com/gensecaihq/Wazuh-MCP-Server/blob/main/CHANGELOG.md",
    },
)
