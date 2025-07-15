"""Integration tests for Wazuh 4.8.0+ API compatibility."""

import pytest
import asyncio
import json
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.api.wazuh_client_manager import WazuhClientManager
from wazuh_mcp_server.api.wazuh_indexer_client import WazuhIndexerClient
from wazuh_mcp_server.api.wazuh_field_mappings import WazuhFieldMapper, WazuhVersion


class TestWazuh48Integration:
    """Integration tests for Wazuh 4.8.0+ compatibility."""

    @pytest.fixture
    def wazuh_config(self):
        """Production-like Wazuh 4.8.0+ configuration."""
        return WazuhConfig(
            host="wazuh-test.local",
            port=55000,
            username="wazuh-mcp",
            password="SecureTestPassword123!",
            verify_ssl=True,
            api_version="v4",
            indexer_host="wazuh-test.local",
            indexer_port=9200,
            indexer_username="admin",
            indexer_password="SecureTestPassword123!",
            indexer_verify_ssl=True,
            wazuh_version="4.8.2",
            use_indexer_for_alerts=True,
            use_indexer_for_vulnerabilities=True
        )

    @pytest.fixture
    def mock_server_api_responses(self):
        """Mock responses for Wazuh Server API."""
        return {
            "version_info": {
                "data": {
                    "title": "Wazuh API",
                    "api_version": "v4.8.2",
                    "revision": "40815",
                    "license_name": "GPL 2.0",
                    "license_url": "https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html",
                    "hostname": "wazuh-manager",
                    "timestamp": "2024-01-15T10:30:00Z"
                }
            },
            "agents": {
                "data": {
                    "affected_items": [
                        {
                            "id": "000",
                            "name": "wazuh-manager",
                            "ip": "127.0.0.1",
                            "status": "active",
                            "os": {"platform": "ubuntu", "version": "20.04"},
                            "version": "v4.8.2",
                            "manager": "wazuh-manager",
                            "lastKeepAlive": "9999-12-31T23:59:59Z",
                            "registerIP": "127.0.0.1"
                        },
                        {
                            "id": "001",
                            "name": "web-server-01",
                            "ip": "192.168.1.100",
                            "status": "active",
                            "os": {"platform": "centos", "version": "8"},
                            "version": "v4.8.2",
                            "manager": "wazuh-manager",
                            "lastKeepAlive": "2024-01-15T10:29:30Z",
                            "registerIP": "192.168.1.100"
                        }
                    ],
                    "total_affected_items": 2,
                    "total_failed_items": 0,
                    "failed_items": []
                }
            },
            "cluster_status": {
                "data": {
                    "enabled": "yes",
                    "running": "yes",
                    "name": "wazuh-cluster",
                    "node_name": "wazuh-manager",
                    "node_type": "master"
                }
            }
        }

    @pytest.fixture
    def mock_indexer_api_responses(self):
        """Mock responses for Wazuh Indexer API."""
        return {
            "cluster_health": {
                "cluster_name": "wazuh-cluster",
                "status": "green",
                "timed_out": False,
                "number_of_nodes": 3,
                "number_of_data_nodes": 3,
                "active_primary_shards": 10,
                "active_shards": 20,
                "relocating_shards": 0,
                "initializing_shards": 0,
                "unassigned_shards": 0
            },
            "alerts_search": {
                "took": 15,
                "timed_out": False,
                "hits": {
                    "total": {"value": 150, "relation": "eq"},
                    "max_score": 1.0,
                    "hits": [
                        {
                            "_index": "wazuh-alerts-4.x-2024.01.15",
                            "_id": "alert_001",
                            "_score": 1.0,
                            "_source": {
                                "@timestamp": "2024-01-15T10:25:00.000Z",
                                "rule": {
                                    "id": 1002,
                                    "level": 5,
                                    "description": "Unknown user attempted to login",
                                    "groups": ["authentication_failed", "syslog", "ssh"]
                                },
                                "agent": {
                                    "id": "001",
                                    "name": "web-server-01",
                                    "ip": "192.168.1.100"
                                },
                                "manager": {"name": "wazuh-manager"},
                                "location": "/var/log/auth.log",
                                "full_log": "Jan 15 10:25:00 web-server-01 sshd[1234]: Failed password for invalid user test from 192.168.1.50 port 22 ssh2"
                            }
                        },
                        {
                            "_index": "wazuh-alerts-4.x-2024.01.15",
                            "_id": "alert_002",
                            "_score": 1.0,
                            "_source": {
                                "@timestamp": "2024-01-15T10:26:00.000Z",
                                "rule": {
                                    "id": 5716,
                                    "level": 12,
                                    "description": "Multiple SSH login failures",
                                    "groups": ["authentication_failures", "syslog", "ssh"]
                                },
                                "agent": {
                                    "id": "001",
                                    "name": "web-server-01",
                                    "ip": "192.168.1.100"
                                },
                                "manager": {"name": "wazuh-manager"},
                                "location": "/var/log/auth.log"
                            }
                        }
                    ]
                },
                "aggregations": {
                    "rule_levels": {
                        "buckets": [
                            {"key": 5, "doc_count": 80},
                            {"key": 12, "doc_count": 50},
                            {"key": 3, "doc_count": 20}
                        ]
                    },
                    "top_agents": {
                        "buckets": [
                            {"key": "web-server-01", "doc_count": 100},
                            {"key": "db-server-01", "doc_count": 50}
                        ]
                    }
                }
            },
            "vulnerabilities_search": {
                "took": 25,
                "timed_out": False,
                "hits": {
                    "total": {"value": 45, "relation": "eq"},
                    "max_score": 1.0,
                    "hits": [
                        {
                            "_index": "wazuh-states-vulnerabilities-2024.01.15",
                            "_id": "vuln_001",
                            "_score": 1.0,
                            "_source": {
                                "@timestamp": "2024-01-15T10:00:00.000Z",
                                "agent": {
                                    "id": "001",
                                    "name": "web-server-01",
                                    "ip": "192.168.1.100"
                                },
                                "vulnerability": {
                                    "id": "CVE-2023-12345",
                                    "cve": "CVE-2023-12345",
                                    "title": "Critical vulnerability in OpenSSL",
                                    "severity": "Critical",
                                    "published": "2023-12-01T00:00:00Z",
                                    "cvss3": {"score": 9.8}
                                },
                                "package": {
                                    "name": "openssl",
                                    "version": "1.1.1-vulnerable",
                                    "architecture": "amd64",
                                    "format": "deb"
                                },
                                "state": "vulnerable"
                            }
                        }
                    ]
                }
            }
        }

    @pytest.mark.asyncio
    async def test_version_detection_and_routing(self, wazuh_config, mock_server_api_responses):
        """Test automatic version detection and API routing."""
        
        with patch('aiohttp.ClientSession') as mock_session:
            # Mock server API responses
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_server_api_responses["version_info"])
            
            mock_session.return_value.__aenter__.return_value.request.return_value.__aenter__.return_value = mock_response
            
            client_manager = WazuhClientManager(wazuh_config)
            await client_manager.__aenter__()
            
            # Test version detection
            version = await client_manager.detect_wazuh_version()
            assert version == "v4.8.2", "Should detect Wazuh 4.8.2"
            
            # Test API routing decisions
            assert client_manager._should_use_indexer_for_alerts(), "Should use Indexer for alerts in 4.8+"
            assert client_manager._should_use_indexer_for_vulnerabilities(), "Should use Indexer for vulnerabilities in 4.8+"
            
            await client_manager.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_indexer_alerts_query_compatibility(self, wazuh_config, mock_indexer_api_responses):
        """Test Indexer API alerts query compatibility."""
        
        with patch('aiohttp.ClientSession') as mock_session:
            # Mock Indexer API responses
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_indexer_api_responses["alerts_search"])
            
            mock_session.return_value.__aenter__.return_value.request.return_value.__aenter__.return_value = mock_response
            
            indexer_client = WazuhIndexerClient(wazuh_config)
            await indexer_client.__aenter__()
            
            # Test alerts search
            result = await indexer_client.search_alerts(
                limit=100,
                level=5,
                time_range=3600
            )
            
            # Verify response format compatibility
            assert "data" in result, "Should have data field for compatibility"
            assert "affected_items" in result["data"], "Should have affected_items for compatibility"
            assert result["data"]["total_affected_items"] == 150, "Should preserve total count"
            
            # Verify alert structure
            alerts = result["data"]["affected_items"]
            assert len(alerts) == 2, "Should return correct number of alerts"
            
            first_alert = alerts[0]
            assert "@timestamp" in first_alert, "Should preserve @timestamp field"
            assert "rule" in first_alert, "Should have rule information"
            assert "agent" in first_alert, "Should have agent information"
            assert first_alert["rule"]["level"] == 5, "Should preserve rule level"
            
            await indexer_client.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_indexer_vulnerabilities_query_compatibility(self, wazuh_config, mock_indexer_api_responses):
        """Test Indexer API vulnerabilities query compatibility."""
        
        with patch('aiohttp.ClientSession') as mock_session:
            # Mock Indexer API responses
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_indexer_api_responses["vulnerabilities_search"])
            
            mock_session.return_value.__aenter__.return_value.request.return_value.__aenter__.return_value = mock_response
            
            indexer_client = WazuhIndexerClient(wazuh_config)
            await indexer_client.__aenter__()
            
            # Test vulnerabilities search
            result = await indexer_client.search_vulnerabilities(
                agent_id="001",
                limit=50
            )
            
            # Verify response format compatibility
            assert "data" in result, "Should have data field for compatibility"
            assert "affected_items" in result["data"], "Should have affected_items for compatibility"
            assert result["data"]["total_affected_items"] == 45, "Should preserve total count"
            
            # Verify vulnerability structure
            vulns = result["data"]["affected_items"]
            assert len(vulns) == 1, "Should return correct number of vulnerabilities"
            
            vuln = vulns[0]
            assert "vulnerability" in vuln, "Should have vulnerability information"
            assert "agent" in vuln, "Should have agent information"
            assert vuln["vulnerability"]["cve"] == "CVE-2023-12345", "Should preserve CVE information"
            assert vuln["vulnerability"]["severity"] == "Critical", "Should preserve severity"
            
            await indexer_client.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_field_mapping_accuracy(self):
        """Test field mapping accuracy for 4.8.0+ compatibility."""
        
        field_mapper = WazuhFieldMapper(WazuhVersion.V4_8_X)
        
        # Test critical field mappings
        timestamp_field = field_mapper.map_server_to_indexer_field("timestamp", "alert")
        assert timestamp_field == "@timestamp", "Timestamp should map to @timestamp"
        
        rule_level_field = field_mapper.map_server_to_indexer_field("rule.level", "alert")
        assert rule_level_field == "rule.level", "Rule level should map consistently"
        
        agent_id_field = field_mapper.map_server_to_indexer_field("agent.id", "alert")
        assert agent_id_field == "agent.id", "Agent ID should map consistently"
        
        # Test reverse mapping
        server_timestamp = field_mapper.map_indexer_to_server_field("@timestamp", "alert")
        assert server_timestamp == "timestamp", "Should reverse map @timestamp to timestamp"
        
        # Test index patterns
        alerts_pattern = field_mapper.get_index_pattern("alerts")
        assert alerts_pattern == "wazuh-alerts-4.x-*", "Should use correct alerts index pattern"
        
        vulns_pattern = field_mapper.get_index_pattern("vulnerabilities")
        assert vulns_pattern == "wazuh-states-vulnerabilities-*", "Should use correct vulnerabilities index pattern"

    @pytest.mark.asyncio
    async def test_api_fallback_mechanism(self, wazuh_config, mock_server_api_responses, mock_indexer_api_responses):
        """Test API fallback mechanism when one API is unavailable."""
        
        with patch('aiohttp.ClientSession') as mock_session:
            # Mock scenario: Indexer API fails, Server API works
            def side_effect(*args, **kwargs):
                url = kwargs.get('url', str(args[1]) if len(args) > 1 else '')
                
                mock_response = AsyncMock()
                
                if ':9200' in url:  # Indexer API call
                    mock_response.status = 503  # Service unavailable
                    mock_response.json = AsyncMock(return_value={"error": "Service unavailable"})
                else:  # Server API call
                    mock_response.status = 200
                    if '/alerts' in url:
                        # In 4.8+, Server API alerts should return 404
                        mock_response.status = 404
                        mock_response.json = AsyncMock(return_value={"error": "Not found"})
                    else:
                        mock_response.json = AsyncMock(return_value=mock_server_api_responses["agents"])
                
                return mock_response
            
            mock_session.return_value.__aenter__.return_value.request.return_value.__aenter__ = AsyncMock(side_effect=side_effect)
            
            client_manager = WazuhClientManager(wazuh_config)
            await client_manager.__aenter__()
            
            # Test agents query (should work via Server API)
            agents_result = await client_manager.get_agents()
            assert "data" in agents_result, "Should get agents via Server API"
            assert agents_result["data"]["total_affected_items"] == 2, "Should return correct agent count"
            
            # Test alerts query (should fail gracefully)
            try:
                await client_manager.get_alerts(limit=10)
                assert False, "Should raise exception when both APIs fail for alerts"
            except Exception as e:
                assert "404" in str(e) or "Service unavailable" in str(e), "Should provide meaningful error"
            
            await client_manager.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_ssl_configuration_enforcement(self, wazuh_config):
        """Test SSL configuration enforcement in production."""
        
        # Test production SSL enforcement
        prod_config = wazuh_config.copy()
        prod_config.verify_ssl = True
        prod_config.indexer_verify_ssl = True
        
        with patch('aiohttp.ClientSession') as mock_session:
            # Verify SSL context is properly configured
            mock_connector = Mock()
            mock_session.return_value = Mock()
            
            indexer_client = WazuhIndexerClient(prod_config)
            await indexer_client._create_session()
            
            # SSL should be enforced
            assert indexer_client.verify_ssl is True, "SSL should be enforced"

    @pytest.mark.asyncio
    async def test_health_check_comprehensive(self, wazuh_config, mock_server_api_responses, mock_indexer_api_responses):
        """Test comprehensive health check for both APIs."""
        
        with patch('aiohttp.ClientSession') as mock_session:
            def side_effect(*args, **kwargs):
                url = kwargs.get('url', str(args[1]) if len(args) > 1 else '')
                mock_response = AsyncMock()
                mock_response.status = 200
                
                if ':9200' in url:  # Indexer API
                    if '_cluster/health' in url:
                        mock_response.json = AsyncMock(return_value=mock_indexer_api_responses["cluster_health"])
                else:  # Server API
                    if url.endswith('/'):  # Root endpoint
                        mock_response.json = AsyncMock(return_value=mock_server_api_responses["version_info"])
                
                return mock_response
            
            mock_session.return_value.__aenter__.return_value.request.return_value.__aenter__ = AsyncMock(side_effect=side_effect)
            
            client_manager = WazuhClientManager(wazuh_config)
            await client_manager.__aenter__()
            
            # Test comprehensive health check
            health_result = await client_manager.health_check()
            
            # Verify health check structure
            assert "server_api" in health_result, "Should include Server API health"
            assert "indexer_api" in health_result, "Should include Indexer API health"
            assert "overall_status" in health_result, "Should include overall status"
            assert "wazuh_version" in health_result, "Should include version info"
            assert "using_indexer_for_alerts" in health_result, "Should include API routing info"
            
            # Verify individual API health
            assert health_result["server_api"]["status"] == "healthy", "Server API should be healthy"
            assert health_result["indexer_api"]["status"] in ["healthy", "green"], "Indexer API should be healthy"
            
            await client_manager.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_query_optimization_and_performance(self, wazuh_config, mock_indexer_api_responses):
        """Test query optimization features for performance."""
        
        with patch('aiohttp.ClientSession') as mock_session:
            # Track query parameters
            captured_queries = []
            
            async def capture_request(*args, **kwargs):
                if 'json' in kwargs:
                    captured_queries.append(kwargs['json'])
                
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.json = AsyncMock(return_value=mock_indexer_api_responses["alerts_search"])
                return mock_response
            
            mock_session.return_value.__aenter__.return_value.request = AsyncMock(side_effect=capture_request)
            
            indexer_client = WazuhIndexerClient(wazuh_config)
            await indexer_client.__aenter__()
            
            # Test optimized query
            await indexer_client.search_alerts(
                limit=100,
                level=5,
                sort="-timestamp",
                agent_id="001"
            )
            
            # Verify query optimization
            query = captured_queries[0]
            
            # Should use bool query with filters for performance
            assert "bool" in query["query"], "Should use bool query"
            assert "filter" in query["query"]["bool"], "Should use filters for performance"
            
            # Should exclude large fields
            assert "_source" in query, "Should have source filtering"
            assert "excludes" in query["_source"], "Should exclude large fields"
            assert "full_log" in query["_source"]["excludes"], "Should exclude full_log field"
            
            # Should use proper sort field
            assert "sort" in query, "Should have sort configuration"
            sort_field = list(query["sort"][0].keys())[0]
            assert "@timestamp" in sort_field, "Should sort by @timestamp"
            
            # Should have aggregations for monitoring
            assert "aggs" in query, "Should include aggregations"
            assert "rule_levels" in query["aggs"], "Should have rule levels aggregation"
            
            await indexer_client.__aexit__(None, None, None)

    def test_version_compatibility_matrix(self):
        """Test version compatibility matrix."""
        
        # Test 4.8.0+ compatibility
        config_48 = WazuhConfig(
            host="test-host",
            username="test",
            password="SecurePassword123!",
            wazuh_version="4.8.0"
        )
        
        client_manager = WazuhClientManager(config_48)
        assert client_manager._is_version_48_or_later(), "4.8.0 should be considered 4.8+"
        
        # Test 4.9.x compatibility
        config_49 = WazuhConfig(
            host="test-host",
            username="test",
            password="SecurePassword123!",
            wazuh_version="4.9.1"
        )
        
        client_manager = WazuhClientManager(config_49)
        assert client_manager._is_version_48_or_later(), "4.9.1 should be considered 4.8+"
        
        # Test 4.7.x compatibility (should not use Indexer by default)
        config_47 = WazuhConfig(
            host="test-host",
            username="test",
            password="SecurePassword123!",
            wazuh_version="4.7.2",
            use_indexer_for_alerts=False
        )
        
        client_manager = WazuhClientManager(config_47)
        assert not client_manager._is_version_48_or_later(), "4.7.2 should not be considered 4.8+"

    @pytest.mark.asyncio
    async def test_production_error_recovery(self, wazuh_config):
        """Test production error recovery scenarios."""
        
        from wazuh_mcp_server.utils.production_error_handler import production_error_handler
        
        # Test network error recovery
        retry_count = 0
        async def flaky_operation():
            nonlocal retry_count
            retry_count += 1
            if retry_count < 3:
                raise ConnectionError("Network error")
            return {"success": True, "attempt": retry_count}
        
        result = await production_error_handler.execute_with_retry(
            flaky_operation,
            "test_recovery",
            "indexer",
            "/test"
        )
        
        assert result["success"] is True, "Should recover from network errors"
        assert result["attempt"] == 3, "Should retry correct number of times"

    def test_minimum_version_enforcement(self):
        """Test that minimum Wazuh version is properly enforced."""
        from wazuh_mcp_server.__version__ import __min_wazuh_version__
        
        # Verify minimum version is set correctly
        assert __min_wazuh_version__ == "4.8.0", "Minimum version should be 4.8.0"
        
        # Test version comparison logic
        config = WazuhConfig(
            host="test-host",
            username="test",
            password="SecurePassword123!",
            wazuh_version="4.7.5"
        )
        
        client_manager = WazuhClientManager(config)
        # With explicit configuration, it should still work but not use Indexer by default
        assert not client_manager._should_use_indexer_for_alerts(), "Should not use Indexer for pre-4.8"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])