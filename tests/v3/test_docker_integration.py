"""Integration tests for v3.0.0 Docker deployment."""

import pytest
import asyncio
import subprocess
import time
import requests
import tempfile
import os
from pathlib import Path
from typing import Dict, Any, Optional

import docker
from docker.errors import ContainerError, ImageNotFound


class TestDockerIntegration:
    """Test Docker integration and deployment."""
    
    @classmethod
    def setup_class(cls):
        """Setup Docker client for tests."""
        try:
            cls.docker_client = docker.from_env()
            cls.docker_client.ping()
        except Exception as e:
            pytest.skip(f"Docker not available: {e}")
    
    @classmethod
    def teardown_class(cls):
        """Cleanup Docker resources."""
        if hasattr(cls, 'docker_client'):
            cls.docker_client.close()
    
    def test_dockerfile_exists_and_valid(self):
        """Test that Dockerfile exists and has required content."""
        dockerfile_path = Path(__file__).parent.parent.parent / "Dockerfile"
        assert dockerfile_path.exists(), "Dockerfile not found"
        
        content = dockerfile_path.read_text()
        
        # Check for multi-stage build
        assert "FROM python:3.11-slim-bullseye as builder" in content
        assert "FROM python:3.11-slim-bullseye as production" in content
        
        # Check for security best practices
        assert "useradd" in content  # Non-root user
        assert "HEALTHCHECK" in content  # Health check
        assert "EXPOSE" in content  # Port exposure
        
        # Check for proper labels
        assert "LABEL maintainer=" in content
        assert "LABEL version=" in content
        assert "org.opencontainers.image" in content
    
    def test_dockerignore_exists(self):
        """Test that .dockerignore exists and excludes appropriate files."""
        dockerignore_path = Path(__file__).parent.parent.parent / ".dockerignore"
        assert dockerignore_path.exists(), ".dockerignore not found"
        
        content = dockerignore_path.read_text()
        
        # Check for common exclusions
        assert ".git" in content
        assert "__pycache__" in content
        assert "*.pyc" in content
        assert "venv/" in content
        assert ".env" in content
        assert "logs/" in content
    
    def test_docker_compose_file_exists_and_valid(self):
        """Test that docker-compose.yml exists and is valid."""
        compose_path = Path(__file__).parent.parent.parent / "docker-compose.yml"
        assert compose_path.exists(), "docker-compose.yml not found"
        
        content = compose_path.read_text()
        
        # Check for required services
        assert "wazuh-mcp-server:" in content
        assert "redis:" in content
        assert "prometheus:" in content
        
        # Check for security settings
        assert "no-new-privileges:true" in content
        assert "cap_drop:" in content
        assert "read_only: true" in content
        
        # Check for health checks
        assert "healthcheck:" in content
        
        # Check for proper networking
        assert "networks:" in content
        assert "wazuh-mcp-network:" in content
    
    def test_entrypoint_script_exists_and_executable(self):
        """Test that entrypoint script exists and is executable."""
        entrypoint_path = Path(__file__).parent.parent.parent / "docker" / "entrypoint.sh"
        assert entrypoint_path.exists(), "entrypoint.sh not found"
        
        # Check if file is executable
        assert os.access(entrypoint_path, os.X_OK), "entrypoint.sh is not executable"
        
        content = entrypoint_path.read_text()
        
        # Check for proper shell settings
        assert "set -euo pipefail" in content
        
        # Check for signal handling
        assert "trap" in content
        assert "SIGTERM" in content
        
        # Check for configuration validation
        assert "validate_config" in content
        assert "WAZUH_API_URL" in content
    
    @pytest.mark.slow
    @pytest.mark.docker
    def test_docker_image_build(self):
        """Test building Docker image."""
        project_root = Path(__file__).parent.parent.parent
        
        try:
            # Build the image
            image, logs = self.docker_client.images.build(
                path=str(project_root),
                tag="wazuh-mcp-server:test",
                rm=True,
                pull=True,
                timeout=300  # 5 minutes timeout
            )
            
            assert image is not None
            assert "wazuh-mcp-server:test" in [tag for tag in image.tags]
            
            # Check image labels
            labels = image.labels or {}
            assert "version" in labels
            assert "description" in labels
            assert "org.opencontainers.image.title" in labels
            
        except Exception as e:
            pytest.fail(f"Docker build failed: {e}")
        finally:
            # Cleanup
            try:
                self.docker_client.images.remove("wazuh-mcp-server:test", force=True)
            except:
                pass
    
    @pytest.mark.slow
    @pytest.mark.docker 
    def test_docker_container_health_check(self):
        """Test Docker container health check."""
        project_root = Path(__file__).parent.parent.parent
        
        # Create temporary config
        with tempfile.TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir) / "config"
            config_dir.mkdir()
            
            env_file = config_dir / "server.env"
            env_file.write_text("""
WAZUH_API_URL=https://localhost:55000
WAZUH_API_USERNAME=test
WAZUH_API_PASSWORD=test
JWT_SECRET_KEY=test_secret_key_123456789
MCP_SERVER_MODE=remote
MCP_TRANSPORT=sse
""")
            
            try:
                # Build image first
                image, _ = self.docker_client.images.build(
                    path=str(project_root),
                    tag="wazuh-mcp-server:health-test",
                    rm=True
                )
                
                # Run container
                container = self.docker_client.containers.run(
                    "wazuh-mcp-server:health-test",
                    detach=True,
                    ports={'8443/tcp': None},
                    volumes={str(config_dir): {'bind': '/app/config', 'mode': 'ro'}},
                    environment={
                        'WAZUH_API_URL': 'https://localhost:55000',
                        'WAZUH_API_USERNAME': 'test',
                        'WAZUH_API_PASSWORD': 'test',
                        'JWT_SECRET_KEY': 'test_secret_key_123456789'
                    },
                    name="wazuh-mcp-test-health"
                )
                
                # Wait for container to start
                time.sleep(10)
                
                # Check container status
                container.reload()
                assert container.status == "running"
                
                # Check health status (may take time to become healthy)
                max_attempts = 6
                for attempt in range(max_attempts):
                    container.reload()
                    health = container.attrs.get('State', {}).get('Health', {})
                    
                    if health.get('Status') == 'healthy':
                        break
                    elif health.get('Status') == 'unhealthy':
                        pytest.fail("Container health check failed")
                    
                    time.sleep(10)
                
                # Get container logs for debugging
                logs = container.logs().decode('utf-8')
                assert "Starting Wazuh MCP Server" in logs or "Server started" in logs
                
            except Exception as e:
                pytest.fail(f"Container health check failed: {e}")
            finally:
                # Cleanup
                try:
                    container = self.docker_client.containers.get("wazuh-mcp-test-health")
                    container.stop(timeout=5)
                    container.remove()
                except:
                    pass
                try:
                    self.docker_client.images.remove("wazuh-mcp-server:health-test", force=True)
                except:
                    pass
    
    @pytest.mark.slow
    @pytest.mark.docker
    def test_docker_container_environment_variables(self):
        """Test Docker container with environment variables."""
        project_root = Path(__file__).parent.parent.parent
        
        try:
            # Build image
            image, _ = self.docker_client.images.build(
                path=str(project_root),
                tag="wazuh-mcp-server:env-test",
                rm=True
            )
            
            # Test environment variables
            env_vars = {
                'WAZUH_API_URL': 'https://test.example.com:55000',
                'WAZUH_API_USERNAME': 'testuser',
                'WAZUH_API_PASSWORD': 'testpass',
                'JWT_SECRET_KEY': 'test_jwt_secret_key_123456789',
                'MCP_SERVER_HOST': '0.0.0.0',
                'MCP_SERVER_PORT': '8443',
                'MCP_SERVER_MODE': 'remote',
                'MCP_TRANSPORT': 'sse',
                'LOG_LEVEL': 'DEBUG'
            }
            
            # Run container with environment variables
            container = self.docker_client.containers.run(
                "wazuh-mcp-server:env-test",
                detach=True,
                environment=env_vars,
                name="wazuh-mcp-test-env"
            )
            
            # Wait for startup
            time.sleep(5)
            
            # Check that container started
            container.reload()
            assert container.status == "running"
            
            # Check logs for environment variable usage
            logs = container.logs().decode('utf-8')
            
            # Should contain configuration information
            assert "test.example.com" in logs or "testuser" in logs or "Configuration validation" in logs
            
        except Exception as e:
            pytest.fail(f"Environment variable test failed: {e}")
        finally:
            # Cleanup
            try:
                container = self.docker_client.containers.get("wazuh-mcp-test-env")
                container.stop(timeout=5)
                container.remove()
            except:
                pass
            try:
                self.docker_client.images.remove("wazuh-mcp-server:env-test", force=True)
            except:
                pass
    
    def test_docker_security_configuration(self):
        """Test Docker security configuration in compose file."""
        compose_path = Path(__file__).parent.parent.parent / "docker-compose.yml"
        content = compose_path.read_text()
        
        # Check security options
        assert "no-new-privileges:true" in content
        assert "cap_drop:" in content
        assert "cap_add:" in content
        
        # Check user configuration
        assert 'user: "1000:1000"' in content
        
        # Check read-only filesystem
        assert "read_only: true" in content
        
        # Check resource limits
        assert "limits:" in content
        assert "cpus:" in content
        assert "memory:" in content
    
    def test_docker_volumes_configuration(self):
        """Test Docker volumes configuration."""
        compose_path = Path(__file__).parent.parent.parent / "docker-compose.yml"
        content = compose_path.read_text()
        
        # Check volume mounts
        assert "./config:/app/config:ro" in content  # Read-only config
        assert "./logs:/app/logs:rw" in content      # Read-write logs
        assert "./data:/app/data:rw" in content      # Read-write data
        
        # Check named volumes
        assert "redis-data:" in content
        assert "prometheus-data:" in content
        assert "grafana-data:" in content
    
    def test_docker_network_configuration(self):
        """Test Docker network configuration."""
        compose_path = Path(__file__).parent.parent.parent / "docker-compose.yml"
        content = compose_path.read_text()
        
        # Check network configuration
        assert "networks:" in content
        assert "wazuh-mcp-network:" in content
        assert "driver: bridge" in content
        assert "subnet: 172.20.0.0/16" in content
    
    @pytest.mark.slow
    @pytest.mark.docker
    @pytest.mark.skipif("CI" in os.environ, reason="Skip integration test in CI")
    def test_docker_compose_up(self):
        """Test Docker Compose deployment."""
        project_root = Path(__file__).parent.parent.parent
        
        # Create temporary environment file
        env_content = """
WAZUH_API_URL=https://localhost:55000
WAZUH_API_USERNAME=test
WAZUH_API_PASSWORD=test
JWT_SECRET_KEY=test_secret_key_for_compose_123456789
REDIS_PASSWORD=redis_test_password
GRAFANA_PASSWORD=grafana_test_password
"""
        
        env_file = project_root / ".env.test"
        env_file.write_text(env_content)
        
        try:
            # Run docker-compose up
            result = subprocess.run([
                "docker", "compose", 
                "--env-file", str(env_file),
                "-p", "wazuh-mcp-test",
                "up", "-d", "--build"
            ], 
            cwd=project_root, 
            capture_output=True, 
            text=True,
            timeout=300  # 5 minutes timeout
            )
            
            if result.returncode != 0:
                pytest.fail(f"Docker compose up failed: {result.stderr}")
            
            # Wait for services to start
            time.sleep(30)
            
            # Check service health
            services_result = subprocess.run([
                "docker", "compose", 
                "-p", "wazuh-mcp-test",
                "ps"
            ], 
            cwd=project_root, 
            capture_output=True, 
            text=True
            )
            
            assert "wazuh-mcp-test_wazuh-mcp-server_1" in services_result.stdout or \
                   "wazuh-mcp-test-wazuh-mcp-server-1" in services_result.stdout
            
        except subprocess.TimeoutExpired:
            pytest.fail("Docker compose deployment timed out")
        except Exception as e:
            pytest.fail(f"Docker compose test failed: {e}")
        finally:
            # Cleanup
            try:
                subprocess.run([
                    "docker", "compose", 
                    "-p", "wazuh-mcp-test",
                    "down", "-v"
                ], 
                cwd=project_root,
                timeout=60
                )
            except:
                pass
            
            # Remove test env file
            try:
                env_file.unlink()
            except:
                pass


class TestDockerImageProperties:
    """Test Docker image properties and metadata."""
    
    def test_requirements_file_exists(self):
        """Test that requirements-v3.txt exists and has required packages."""
        requirements_path = Path(__file__).parent.parent.parent / "requirements-v3.txt"
        assert requirements_path.exists(), "requirements-v3.txt not found"
        
        content = requirements_path.read_text()
        
        # Check for core packages
        assert "fastapi==" in content
        assert "uvicorn==" in content
        assert "aiohttp==" in content
        assert "sse-starlette==" in content
        assert "authlib==" in content
        assert "python-jose" in content
        assert "prometheus-client==" in content
    
    def test_docker_entrypoint_functions(self):
        """Test specific functions in Docker entrypoint script."""
        entrypoint_path = Path(__file__).parent.parent.parent / "docker" / "entrypoint.sh"
        content = entrypoint_path.read_text()
        
        # Check for required functions
        assert "validate_config()" in content
        assert "init_directories()" in content
        assert "generate_config()" in content
        assert "health_check()" in content
        assert "start_monitoring()" in content
        
        # Check for error handling
        assert "error_exit()" in content
        assert "shutdown_handler()" in content
        
        # Check for logging functions
        assert "log_info()" in content
        assert "log_error()" in content
        assert "log_warn()" in content
    
    def test_docker_image_size_optimization(self):
        """Test that Dockerfile includes size optimization techniques."""
        dockerfile_path = Path(__file__).parent.parent.parent / "Dockerfile"
        content = dockerfile_path.read_text()
        
        # Check for multi-stage build
        assert content.count("FROM ") >= 2
        
        # Check for cleanup commands
        assert "rm -rf /var/lib/apt/lists/*" in content
        assert "apt-get clean" in content
        
        # Check for no-cache pip installs
        assert "--no-cache-dir" in content
        
        # Check for proper layer optimization
        assert "&&" in content  # Command chaining
    
    def test_docker_monitoring_configuration(self):
        """Test monitoring configuration in docker-compose.yml."""
        compose_path = Path(__file__).parent.parent.parent / "docker-compose.yml"
        content = compose_path.read_text()
        
        # Check for Prometheus service
        assert "prometheus:" in content
        assert "prom/prometheus:latest" in content
        assert "9091:9090" in content  # Prometheus port mapping
        
        # Check for Grafana service  
        assert "grafana:" in content
        assert "grafana/grafana:latest" in content
        assert "3000:3000" in content  # Grafana port mapping
        
        # Check for monitoring volumes
        assert "prometheus-data:" in content
        assert "grafana-data:" in content


class TestDockerProductionReadiness:
    """Test Docker configuration for production readiness."""
    
    def test_health_check_configuration(self):
        """Test health check configuration."""
        dockerfile_path = Path(__file__).parent.parent.parent / "Dockerfile"
        content = dockerfile_path.read_text()
        
        # Check health check exists
        assert "HEALTHCHECK" in content
        assert "--interval=" in content
        assert "--timeout=" in content
        assert "--retries=" in content
        assert "curl -f" in content
    
    def test_signal_handling(self):
        """Test signal handling in entrypoint script."""
        entrypoint_path = Path(__file__).parent.parent.parent / "docker" / "entrypoint.sh"
        content = entrypoint_path.read_text()
        
        # Check for signal handling
        assert "trap shutdown_handler" in content
        assert "SIGTERM" in content
        assert "SIGINT" in content
        assert "graceful" in content.lower()
    
    def test_logging_configuration(self):
        """Test logging configuration in docker-compose.yml."""
        compose_path = Path(__file__).parent.parent.parent / "docker-compose.yml"
        content = compose_path.read_text()
        
        # Check logging configuration
        assert "logging:" in content
        assert "driver: json-file" in content
        assert "max-size:" in content
        assert "max-file:" in content
    
    def test_resource_limits(self):
        """Test resource limits in docker-compose.yml."""
        compose_path = Path(__file__).parent.parent.parent / "docker-compose.yml"
        content = compose_path.read_text()
        
        # Check resource limits
        assert "deploy:" in content
        assert "resources:" in content
        assert "limits:" in content
        assert "reservations:" in content
        assert "cpus:" in content
        assert "memory:" in content
    
    def test_init_system_usage(self):
        """Test proper init system usage in Dockerfile."""
        dockerfile_path = Path(__file__).parent.parent.parent / "Dockerfile"
        content = dockerfile_path.read_text()
        
        # Check for tini usage
        assert "tini" in content
        assert "ENTRYPOINT" in content
        assert "/usr/bin/tini" in content or "tini --" in content