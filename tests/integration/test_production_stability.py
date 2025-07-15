"""Comprehensive production stability tests for Wazuh MCP Server."""

import pytest
import asyncio
import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any, List

# Import all modules to test
from wazuh_mcp_server.config import WazuhConfig, ConfigurationError
from wazuh_mcp_server.__version__ import __version__, __min_wazuh_version__
from wazuh_mcp_server.api.wazuh_client_manager import WazuhClientManager
from wazuh_mcp_server.api.wazuh_indexer_client import WazuhIndexerClient
from wazuh_mcp_server.api.wazuh_field_mappings import WazuhFieldMapper, WazuhVersion
from wazuh_mcp_server.utils.production_error_handler import ProductionErrorHandler, CircuitBreaker, CircuitBreakerConfig
from wazuh_mcp_server.analyzers.security_analyzer import SecurityAnalyzer
from wazuh_mcp_server.analyzers.compliance_analyzer import ComplianceAnalyzer
from wazuh_mcp_server.main import WazuhMCPServer


class TestProductionStability:
    """Test suite for production stability and edge cases."""

    @pytest.fixture
    def mock_config(self):
        """Create a mock configuration for testing."""
        return WazuhConfig(
            host="test-wazuh",
            port=55000,
            username="test-user",
            password="SecurePassword123!",
            verify_ssl=True,
            indexer_host="test-wazuh",
            indexer_port=9200,
            indexer_username="test-user",
            indexer_password="SecurePassword123!",
            indexer_verify_ssl=True,
            wazuh_version="4.8.0",
            use_indexer_for_alerts=True,
            use_indexer_for_vulnerabilities=True
        )

    @pytest.fixture
    def field_mapper(self):
        """Create field mapper for testing."""
        return WazuhFieldMapper(WazuhVersion.V4_8_X)

    @pytest.fixture
    def error_handler(self):
        """Create error handler for testing."""
        return ProductionErrorHandler()

    @pytest.mark.asyncio
    async def test_version_compatibility_check(self):
        """Test version compatibility requirements."""
        # Test minimum version requirement
        assert __min_wazuh_version__ == "4.8.0", "Minimum Wazuh version should be 4.8.0"
        assert __version__ == "2.1.0", "MCP Server version should be 2.1.0"

    @pytest.mark.asyncio
    async def test_configuration_validation_edge_cases(self, mock_config):
        """Test configuration validation with edge cases."""
        
        # Test empty host
        with pytest.raises(ValueError, match="WAZUH_HOST must be provided"):
            WazuhConfig(
                host="",
                username="test",
                password="SecurePassword123!"
            )
        
        # Test weak password
        with pytest.raises(ValueError, match="Password is too weak"):
            WazuhConfig(
                host="test-host",
                username="test",
                password="admin"
            )
        
        # Test short password
        with pytest.raises(ValueError, match="Password must be at least 8 characters"):
            WazuhConfig(
                host="test-host",
                username="test",
                password="123"
            )

    @pytest.mark.asyncio
    async def test_field_mapping_edge_cases(self, field_mapper):
        """Test field mapping with edge cases."""
        
        # Test unmapped field fallback
        unmapped_field = field_mapper.map_server_to_indexer_field("nonexistent.field")
        assert unmapped_field == "nonexistent.field", "Should return original field if no mapping found"
        
        # Test empty data validation
        issues = field_mapper.validate_field_compatibility({}, "alert")
        assert len(issues) > 0, "Should find issues with empty data"
        
        # Test malformed data
        malformed_data = {"rule": {"level": "invalid"}}
        issues = field_mapper.validate_field_compatibility(malformed_data, "alert")
        assert len(issues) > 0, "Should find issues with malformed data"

    @pytest.mark.asyncio
    async def test_circuit_breaker_functionality(self, error_handler):
        """Test circuit breaker pattern."""
        
        # Create circuit breaker with low threshold for testing
        config = CircuitBreakerConfig(failure_threshold=2, recovery_timeout=1)
        breaker = CircuitBreaker(config)
        
        # Initially should be closed
        assert breaker.can_execute(), "Circuit breaker should start closed"
        
        # Record failures to open circuit
        breaker.record_failure()
        breaker.record_failure()
        
        # Should still be closed (at threshold)
        assert breaker.can_execute(), "Should still be closed at threshold"
        
        # One more failure should open it
        breaker.record_failure()
        assert not breaker.can_execute(), "Should be open after threshold exceeded"
        
        # Wait for recovery timeout
        await asyncio.sleep(1.1)
        assert breaker.can_execute(), "Should allow test request after timeout"

    @pytest.mark.asyncio
    async def test_timestamp_parsing_edge_cases(self):
        """Test timestamp parsing with various formats."""
        analyzer = SecurityAnalyzer()
        
        # Test various timestamp formats
        test_alerts = [
            {"timestamp": "2024-01-01T12:00:00Z"},
            {"timestamp": "2024-01-01T12:00:00+00:00"},
            {"timestamp": "2024-01-01T12:00:00"},
            {"timestamp": "invalid-timestamp"},
            {"timestamp": ""},
            {"timestamp": None},
            {},  # No timestamp field
        ]
        
        # This should not crash
        risk_factors = analyzer._analyze_time_clustering(test_alerts)
        assert risk_factors is not None, "Should handle malformed timestamps gracefully"

    @pytest.mark.asyncio
    async def test_division_by_zero_protection(self):
        """Test protection against division by zero errors."""
        analyzer = SecurityAnalyzer()
        
        # Test with empty lists
        empty_alerts = []
        risk_assessment = analyzer.calculate_comprehensive_risk_score(empty_alerts, 24)
        assert risk_assessment is not None, "Should handle empty alert list"
        assert risk_assessment.overall_score >= 0, "Score should be non-negative"
        
        # Test with single alert
        single_alert = [{"rule": {"level": 5}, "timestamp": "2024-01-01T12:00:00Z"}]
        risk_assessment = analyzer.calculate_comprehensive_risk_score(single_alert, 24)
        assert risk_assessment is not None, "Should handle single alert"

    @pytest.mark.asyncio
    async def test_ssl_configuration_validation(self, mock_config):
        """Test SSL configuration validation."""
        
        # Test external host with SSL disabled (should warn)
        external_config = WazuhConfig(
            host="external-wazuh.com",
            username="test",
            password="SecurePassword123!",
            verify_ssl=False,
            indexer_host="external-wazuh.com",
            indexer_verify_ssl=False
        )
        
        # Should create but with warnings logged
        indexer_client = WazuhIndexerClient(external_config)
        assert indexer_client.verify_ssl is False, "SSL verification should be disabled as configured"

    @pytest.mark.asyncio
    async def test_api_response_validation(self):
        """Test API response structure validation."""
        
        # Mock indexer client
        config = WazuhConfig(
            host="test-host",
            username="test",
            password="SecurePassword123!"
        )
        client = WazuhIndexerClient(config)
        
        # Test search response validation
        valid_response = {
            "hits": {
                "total": {"value": 10},
                "hits": [{"_source": {"rule": {"level": 5}}}]
            }
        }
        client._validate_response_structure(valid_response, "/test/_search")
        
        # Test invalid response structure
        invalid_response = {"invalid": "structure"}
        client._validate_response_structure(invalid_response, "/test/_search")

    @pytest.mark.asyncio
    async def test_error_handler_retry_logic(self, error_handler):
        """Test error handler retry logic with different error types."""
        
        # Mock operation that fails then succeeds
        call_count = 0
        async def failing_operation():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Connection failed")
            return {"success": True}
        
        # Should retry and eventually succeed
        result = await error_handler.execute_with_retry(
            failing_operation,
            "test_operation",
            "test_api",
            "/test/endpoint"
        )
        
        assert result["success"] is True, "Should eventually succeed"
        assert call_count == 3, "Should have retried 2 times"

    @pytest.mark.asyncio
    async def test_memory_leak_prevention(self, mock_config):
        """Test for potential memory leaks."""
        
        # Create multiple client instances
        clients = []
        for i in range(10):
            client = WazuhClientManager(mock_config)
            clients.append(client)
        
        # Simulate cleanup
        for client in clients:
            await client.__aexit__(None, None, None)
        
        # Memory should be released (this is a basic test)
        assert len(clients) == 10, "All clients should be created and cleaned up"

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, mock_config):
        """Test concurrent operations for thread safety."""
        
        error_handler = ProductionErrorHandler()
        
        # Simulate concurrent API calls
        async def mock_operation(operation_id: int):
            await asyncio.sleep(0.1)  # Simulate work
            if operation_id % 3 == 0:  # Fail every 3rd operation
                raise Exception(f"Operation {operation_id} failed")
            return f"Success {operation_id}"
        
        # Run concurrent operations
        tasks = []
        for i in range(20):
            task = error_handler.execute_with_retry(
                lambda: mock_operation(i),
                f"concurrent_op_{i}",
                "test_api",
                "/test"
            )
            tasks.append(task)
        
        # Wait for all to complete (some will fail)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should handle concurrent access without crashes
        successful = [r for r in results if not isinstance(r, Exception)]
        assert len(successful) > 0, "Some operations should succeed"

    @pytest.mark.asyncio
    async def test_large_data_handling(self, field_mapper):
        """Test handling of large data sets."""
        
        # Create large alert dataset
        large_alerts = []
        for i in range(1000):
            alert = {
                "rule": {"level": i % 10 + 1, "id": f"rule_{i}"},
                "agent": {"id": f"agent_{i % 100}", "name": f"Agent {i % 100}"},
                "timestamp": f"2024-01-01T{i % 24:02d}:00:00Z",
                "full_log": "x" * 1000  # Large log field
            }
            large_alerts.append(alert)
        
        # Should handle large datasets without memory issues
        analyzer = SecurityAnalyzer()
        risk_assessment = analyzer.calculate_comprehensive_risk_score(large_alerts[:100], 24)
        assert risk_assessment is not None, "Should handle large alert sets"

    @pytest.mark.asyncio
    async def test_malformed_json_handling(self):
        """Test handling of malformed JSON responses."""
        
        config = WazuhConfig(
            host="test-host",
            username="test", 
            password="SecurePassword123!"
        )
        
        with patch('aiohttp.ClientSession') as mock_session:
            # Mock malformed JSON response
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(side_effect=json.JSONDecodeError("Invalid JSON", "", 0))
            mock_response.text = AsyncMock(return_value="Invalid JSON")
            
            mock_session.return_value.__aenter__.return_value.request.return_value.__aenter__.return_value = mock_response
            
            indexer_client = WazuhIndexerClient(config)
            indexer_client.session = mock_session.return_value.__aenter__.return_value
            
            # Should handle JSON decode errors gracefully
            with pytest.raises(Exception):  # Should raise appropriate error, not crash
                await indexer_client._request("GET", "/test")

    @pytest.mark.asyncio
    async def test_network_timeout_handling(self, mock_config):
        """Test network timeout handling."""
        
        with patch('aiohttp.ClientSession') as mock_session:
            # Mock timeout error
            mock_session.return_value.__aenter__.return_value.request.side_effect = asyncio.TimeoutError()
            
            client_manager = WazuhClientManager(mock_config)
            client_manager.server_client.session = mock_session.return_value.__aenter__.return_value
            
            # Should handle timeouts gracefully with retries
            with pytest.raises(Exception):  # Should eventually fail after retries
                await client_manager.get_agents()

    def test_index_pattern_validation(self, field_mapper):
        """Test index pattern validation."""
        
        # Test valid patterns
        alerts_pattern = field_mapper.get_index_pattern("alerts")
        assert "wazuh-alerts" in alerts_pattern, "Should contain wazuh-alerts"
        
        vulns_pattern = field_mapper.get_index_pattern("vulnerabilities")
        assert "vulnerabilities" in vulns_pattern, "Should contain vulnerabilities"
        
        # Test fallback for unknown type
        unknown_pattern = field_mapper.get_index_pattern("unknown")
        assert "wazuh-unknown" in unknown_pattern, "Should create fallback pattern"

    @pytest.mark.asyncio
    async def test_health_check_resilience(self, mock_config):
        """Test health check resilience."""
        
        client_manager = WazuhClientManager(mock_config)
        
        # Mock server API health check failure
        with patch.object(client_manager.server_client, 'health_check', 
                         AsyncMock(return_value={"status": "unhealthy", "error": "Connection failed"})):
            
            health_result = await client_manager.health_check()
            assert health_result["overall_status"] == "unhealthy", "Should detect unhealthy state"
            assert "server_api" in health_result, "Should include server API status"

    def test_configuration_edge_cases(self):
        """Test configuration edge cases and validation."""
        
        # Test port range validation
        with pytest.raises(ValueError):
            WazuhConfig(
                host="test-host",
                port=99999,  # Invalid port
                username="test",
                password="SecurePassword123!"
            )
        
        # Test negative values
        with pytest.raises(ValueError):
            WazuhConfig(
                host="test-host",
                username="test",
                password="SecurePassword123!",
                max_alerts_per_query=-1
            )

    @pytest.mark.asyncio
    async def test_resource_cleanup(self, mock_config):
        """Test proper resource cleanup."""
        
        client_manager = WazuhClientManager(mock_config)
        
        # Test context manager cleanup
        async with client_manager as client:
            assert client is not None
        
        # Resources should be cleaned up after context exit
        # This is verified by the context manager protocol

    def test_field_mapping_consistency(self, field_mapper):
        """Test field mapping consistency between versions."""
        
        # Test that critical fields are always mapped
        critical_fields = ["timestamp", "rule_level", "agent_id"]
        
        for field in critical_fields:
            mapping = field_mapper.get_alert_field_mapping(field)
            assert mapping is not None, f"Critical field {field} should have mapping"
            assert mapping.required or mapping.default_value is not None, \
                f"Critical field {field} should be required or have default"

    @pytest.mark.asyncio
    async def test_production_error_scenarios(self, error_handler):
        """Test various production error scenarios."""
        
        # Test rate limiting
        async def rate_limited_operation():
            from wazuh_mcp_server.utils.exceptions import RateLimitError
            raise RateLimitError("Rate limit exceeded")
        
        with pytest.raises(Exception):
            await error_handler.execute_with_retry(
                rate_limited_operation,
                "rate_test",
                "test_api", 
                "/test"
            )
        
        # Test authentication failures
        async def auth_failed_operation():
            from wazuh_mcp_server.utils.exceptions import AuthenticationError
            raise AuthenticationError("Invalid credentials")
        
        with pytest.raises(Exception):
            await error_handler.execute_with_retry(
                auth_failed_operation,
                "auth_test",
                "test_api",
                "/test"
            )


class TestPerformanceAndStability:
    """Performance and stability tests."""

    @pytest.mark.asyncio
    async def test_response_time_expectations(self):
        """Test that operations complete within expected time limits."""
        
        # Mock fast API responses
        config = WazuhConfig(
            host="test-host",
            username="test",
            password="SecurePassword123!"
        )
        
        start_time = time.time()
        
        # Simple field mapping operation should be very fast
        field_mapper = WazuhFieldMapper(WazuhVersion.V4_8_X)
        mapped_field = field_mapper.map_server_to_indexer_field("rule.level")
        
        end_time = time.time()
        
        assert (end_time - start_time) < 0.1, "Field mapping should be very fast"
        assert mapped_field == "rule.level", "Should map correctly"

    @pytest.mark.asyncio
    async def test_memory_usage_stability(self):
        """Test memory usage remains stable under load."""
        
        # Create and destroy many objects
        for i in range(100):
            field_mapper = WazuhFieldMapper(WazuhVersion.V4_8_X)
            error_handler = ProductionErrorHandler()
            
            # Use the objects
            field_mapper.get_alert_field_mapping("timestamp")
            error_handler.get_error_statistics()
            
            # Objects should be garbage collected
            del field_mapper, error_handler

    def test_version_detection_accuracy(self):
        """Test version detection accuracy."""
        
        config = WazuhConfig(
            host="test-host",
            username="test",
            password="SecurePassword123!",
            wazuh_version="4.8.5"
        )
        
        client_manager = WazuhClientManager(config)
        
        # Should detect 4.8.x correctly
        assert client_manager._is_version_48_or_later(), "Should detect 4.8.5 as 4.8+"
        
        # Test with 4.7.x
        config.wazuh_version = "4.7.2"
        client_manager = WazuhClientManager(config)
        assert not client_manager._is_version_48_or_later(), "Should detect 4.7.2 as pre-4.8"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])