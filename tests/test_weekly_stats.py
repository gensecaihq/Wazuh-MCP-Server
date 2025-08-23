"""Tests for the get_wazuh_weekly_stats tool."""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

# Updated imports for FastMCP architecture
from wazuh_mcp_server.server import mcp, initialize_server
from wazuh_mcp_server.config import WazuhConfig


@pytest.fixture
def mock_alerts_weekly():
    """Mock weekly alerts data."""
    base_time = datetime.utcnow()
    alerts = []
    
    # Generate alerts for different days and severity levels
    for day in range(14):  # 2 weeks of data
        timestamp = base_time - timedelta(days=day)
        
        # Critical alerts
        for i in range(2):
            alerts.append({
                "id": f"alert_{day}_{i}_critical",
                "timestamp": timestamp.isoformat() + "Z",
                "rule": {
                    "id": 40101,
                    "description": "Critical security event",
                    "level": 15,
                    "groups": ["attack", "critical"]
                },
                "agent": {
                    "id": "001",
                    "name": "web-server-01"
                },
                "data": {
                    "srcip": "192.168.1.100"
                }
            })
        
        # Medium alerts
        for i in range(5):
            alerts.append({
                "id": f"alert_{day}_{i}_medium",
                "timestamp": timestamp.isoformat() + "Z",
                "rule": {
                    "id": 5501,
                    "description": "Authentication success",
                    "level": 5,
                    "groups": ["authentication"]
                },
                "agent": {
                    "id": "002",
                    "name": "db-server-01"
                },
                "data": {
                    "srcip": "10.0.0.50",
                    "srcuser": "admin"
                }
            })
    
    return alerts


@pytest.fixture
def mock_agents_weekly():
    """Mock agent data for weekly analysis."""
    base_time = datetime.utcnow()
    
    return [
        {
            "id": "001",
            "name": "web-server-01",
            "status": "active",
            "dateAdd": (base_time - timedelta(days=20)).isoformat() + "Z",
            "os": {"platform": "ubuntu", "version": "20.04"},
            "version": "4.8.0"
        },
        {
            "id": "002",
            "name": "db-server-01",
            "status": "active",
            "dateAdd": (base_time - timedelta(days=5)).isoformat() + "Z",  # New this week
            "os": {"platform": "centos", "version": "8"},
            "version": "4.8.0"
        },
        {
            "id": "003",
            "name": "win-server-01",
            "status": "disconnected",
            "dateAdd": (base_time - timedelta(days=30)).isoformat() + "Z",
            "os": {"platform": "windows", "version": "2019"},
            "version": "4.7.5"
        }
    ]


@pytest.fixture
def mock_vulnerabilities_weekly():
    """Mock vulnerability data for weekly analysis."""
    return {
        "001": [
            {
                "cve": "CVE-2024-0001",
                "name": "openssl",
                "cvss3_score": 9.8,
                "severity": "critical",
                "published_date": "2024-01-01T00:00:00Z"
            },
            {
                "cve": "CVE-2024-0002",
                "name": "apache2",
                "cvss3_score": 7.5,
                "severity": "high",
                "published_date": "2024-01-02T00:00:00Z"
            }
        ],
        "002": [
            {
                "cve": "CVE-2024-0003",
                "name": "mysql",
                "cvss3_score": 8.8,
                "severity": "high",
                "published_date": "2024-01-03T00:00:00Z"
            }
        ]
    }


@pytest.fixture
def mock_auth_alerts():
    """Mock authentication alerts for weekly analysis."""
    base_time = datetime.utcnow()
    auth_alerts = []
    
    # Successful logins
    for i in range(20):
        auth_alerts.append({
            "timestamp": (base_time - timedelta(hours=i)).isoformat() + "Z",
            "rule": {
                "id": 5501,
                "description": "Successful login",
                "groups": ["authentication", "success"]
            },
            "data": {
                "srcip": "192.168.1.100",
                "srcuser": "user1"
            }
        })
    
    # Failed logins from suspicious source
    for i in range(15):
        auth_alerts.append({
            "timestamp": (base_time - timedelta(hours=i)).isoformat() + "Z",
            "rule": {
                "id": 5502,
                "description": "Failed login attempt",
                "groups": ["authentication", "failed"]
            },
            "data": {
                "srcip": "10.0.0.99",
                "srcuser": "admin"
            }
        })
    
    return auth_alerts


class TestWeeklyStatsValidation:
    """Test validation of weekly stats query parameters."""
    
    def test_valid_basic_query(self):
        """Test validation with basic valid parameters."""
        params = {"weeks": 1}
        result = validate_weekly_stats_query(params)
        
        assert result.weeks == 1
        assert result.include_trends is True
        assert result.include_comparison is True
        assert result.group_by == "day"
        assert result.output_format == "detailed"
    
    def test_valid_complete_query(self):
        """Test validation with all parameters."""
        params = {
            "weeks": 4,
            "start_date": "2024-01-01",
            "metrics": ["alerts", "vulnerabilities"],
            "include_trends": False,
            "include_comparison": False,
            "include_forecasting": True,
            "group_by": "week",
            "agent_filter": ["001", "002"],
            "rule_filter": ["5501", "5502"],
            "output_format": "summary"
        }
        result = validate_weekly_stats_query(params)
        
        assert result.weeks == 4
        assert result.start_date == "2024-01-01"
        assert result.metrics == ["alerts", "vulnerabilities"]
        assert result.include_forecasting is True
        assert result.group_by == "week"
        assert result.output_format == "summary"
    
    def test_invalid_weeks(self):
        """Test validation with invalid weeks value."""
        # Test below minimum
        params = {"weeks": 0}
        with pytest.raises(ValidationError):
            validate_weekly_stats_query(params)
        
        # Test above maximum
        params = {"weeks": 13}
        with pytest.raises(ValidationError):
            validate_weekly_stats_query(params)
    
    def test_invalid_start_date_format(self):
        """Test validation with invalid date format."""
        params = {"start_date": "01-01-2024"}  # Wrong format
        
        with pytest.raises(ValidationError):
            validate_weekly_stats_query(params)
    
    def test_invalid_metrics(self):
        """Test validation with invalid metrics."""
        params = {"metrics": ["invalid_metric"]}
        
        with pytest.raises(ValidationError):
            validate_weekly_stats_query(params)
    
    def test_invalid_group_by(self):
        """Test validation with invalid group_by."""
        params = {"group_by": "invalid"}
        
        with pytest.raises(ValidationError):
            validate_weekly_stats_query(params)
    
    def test_invalid_output_format(self):
        """Test validation with invalid output format."""
        params = {"output_format": "invalid"}
        
        with pytest.raises(ValidationError):
            validate_weekly_stats_query(params)


@pytest.mark.asyncio
class TestWeeklyStatsTool:
    """Test the weekly stats tool functionality."""
    
    @pytest.fixture
    async def wazuh_server(self):
        """Create a mock Wazuh MCP server."""
        with patch('wazuh_mcp_server.main.WazuhConfig') as mock_config:
            mock_config.from_env.return_value = MagicMock()
            mock_config.from_env.return_value.log_level = "INFO"
            mock_config.from_env.return_value.debug = False
            mock_config.from_env.return_value.request_timeout_seconds = 30
            
            server = WazuhMCPServer()
            server.api_client = AsyncMock()
            return server
    
    async def test_basic_weekly_stats(self, wazuh_server, mock_alerts_weekly, mock_agents_weekly):
        """Test basic weekly stats functionality."""
        # Mock API responses
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_weekly}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_weekly}
        }
        wazuh_server.api_client.get_agent_vulnerabilities.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"weeks": 1}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        assert len(result) == 1
        response_data = json.loads(result[0].text)
        
        # Check basic structure
        assert "query_parameters" in response_data
        assert "summary" in response_data
        assert "weekly_metrics" in response_data
        assert "trends" in response_data
        assert "insights" in response_data
        assert "recommendations" in response_data
        assert "analysis_metadata" in response_data
        
        # Check that we have metrics for one week
        assert len(response_data["weekly_metrics"]) == 1
        
        # Check summary exists
        assert response_data["summary"]["total_weeks_analyzed"] == 1
    
    async def test_multi_week_analysis(self, wazuh_server, mock_alerts_weekly, mock_agents_weekly):
        """Test analysis across multiple weeks."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_weekly}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_weekly}
        }
        wazuh_server.api_client.get_agent_vulnerabilities.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"weeks": 2, "include_comparison": True}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have metrics for 2 weeks
        assert len(response_data["weekly_metrics"]) == 2
        
        # Should have comparisons
        assert "comparisons" in response_data
        if response_data["comparisons"]:
            assert "week_over_week_changes" in response_data["comparisons"]
    
    async def test_specific_metrics_collection(self, wazuh_server, mock_alerts_weekly, 
                                              mock_agents_weekly, mock_vulnerabilities_weekly):
        """Test collection of specific metrics."""
        # Mock different metric responses
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_weekly}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_weekly}
        }
        
        def mock_get_vulns(agent_id):
            return {
                "data": {"affected_items": mock_vulnerabilities_weekly.get(agent_id, [])}
            }
        
        wazuh_server.api_client.get_agent_vulnerabilities.side_effect = mock_get_vulns
        
        arguments = {
            "weeks": 1,
            "metrics": ["alerts", "agents", "vulnerabilities"]
        }
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check that requested metrics are present
        week_metrics = list(response_data["weekly_metrics"].values())[0]
        assert "alerts" in week_metrics["metrics"]
        assert "agents" in week_metrics["metrics"]
        assert "vulnerabilities" in week_metrics["metrics"]
        
        # Check alert metrics
        alert_metrics = week_metrics["metrics"]["alerts"]
        assert "total" in alert_metrics
        assert "daily_average" in alert_metrics
        assert "severity_breakdown" in alert_metrics
        
        # Check agent metrics
        agent_metrics = week_metrics["metrics"]["agents"]
        assert "total" in agent_metrics
        assert "active" in agent_metrics
        assert "health_percentage" in agent_metrics
        
        # Check vulnerability metrics
        vuln_metrics = week_metrics["metrics"]["vulnerabilities"]
        assert "total" in vuln_metrics
        assert "critical" in vuln_metrics
        assert "affected_agents" in vuln_metrics
    
    async def test_authentication_analysis(self, wazuh_server, mock_auth_alerts):
        """Test authentication metrics analysis."""
        wazuh_server.api_client.get_alerts.side_effect = lambda **kwargs: {
            "data": {"affected_items": mock_auth_alerts if "authentication" in kwargs.get("q", "") else []}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {
            "weeks": 1,
            "metrics": ["authentication"]
        }
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check authentication metrics
        week_metrics = list(response_data["weekly_metrics"].values())[0]
        auth_metrics = week_metrics["metrics"]["authentication"]
        
        assert "total_events" in auth_metrics
        assert "success_rate" in auth_metrics
        assert "failed_attempts" in auth_metrics
        assert "suspicious_sources" in auth_metrics
        
        # Should detect suspicious activity (15 failed attempts from same IP)
        assert auth_metrics["suspicious_sources"] > 0
    
    async def test_trend_analysis(self, wazuh_server, mock_alerts_weekly):
        """Test trend analysis functionality."""
        # Create increasing alert trend
        increasing_alerts = []
        base_time = datetime.utcnow()
        
        # Week 1: 10 alerts
        for i in range(10):
            increasing_alerts.append({
                "timestamp": (base_time - timedelta(days=13, hours=i)).isoformat() + "Z",
                "rule": {"id": 5501, "level": 5},
                "agent": {"name": "test-agent"}
            })
        
        # Week 2: 20 alerts (increasing trend)
        for i in range(20):
            increasing_alerts.append({
                "timestamp": (base_time - timedelta(days=6, hours=i)).isoformat() + "Z",
                "rule": {"id": 5501, "level": 5},
                "agent": {"name": "test-agent"}
            })
        
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": increasing_alerts}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"weeks": 2, "include_trends": True}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check trend analysis
        assert "trends" in response_data
        trends = response_data["trends"]
        assert "alert_trend" in trends
        assert "overall_direction" in trends
        
        # Should detect increasing trend
        assert trends["overall_direction"] == "increasing"
        
        # Should have corresponding insight
        insights = response_data["insights"]
        trend_insights = [i for i in insights if i["category"] == "trends"]
        assert len(trend_insights) > 0
    
    async def test_forecasting(self, wazuh_server, mock_alerts_weekly):
        """Test forecasting functionality."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_weekly}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"weeks": 4, "include_forecasting": True}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check forecasting
        assert "forecasting" in response_data
        forecast = response_data["forecasting"]
        assert "next_week_estimates" in forecast
        assert "confidence" in forecast
        assert "method" in forecast
        
        # Should have some estimates
        if forecast["next_week_estimates"]:
            assert len(forecast["next_week_estimates"]) > 0
    
    async def test_output_formats(self, wazuh_server, mock_alerts_weekly):
        """Test different output formats."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_weekly}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        
        # Test minimal format
        arguments = {"weeks": 1, "output_format": "minimal"}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Minimal format should only have summary and top insights
        assert "summary" in response_data
        assert "insights" in response_data
        assert len(response_data["insights"]) <= 3
        assert "weekly_metrics" not in response_data
        
        # Test summary format
        arguments = {"weeks": 1, "output_format": "summary"}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Summary format should have weekly totals
        assert "summary" in response_data
        assert "weekly_totals" in response_data
        assert "insights" in response_data
        assert "trends" not in response_data
    
    async def test_agent_filtering(self, wazuh_server, mock_alerts_weekly):
        """Test filtering by specific agents."""
        # Filter alerts to only include specific agent
        filtered_alerts = [a for a in mock_alerts_weekly if a["agent"]["id"] == "001"]
        
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": filtered_alerts}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"weeks": 1, "agent_filter": ["001"]}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check that agent filter was applied
        assert response_data["query_parameters"]["agent_filter"] == ["001"]
        
        # Should only have alerts from agent 001
        week_metrics = list(response_data["weekly_metrics"].values())[0]
        if "alerts" in week_metrics["metrics"]:
            # All alerts should be from filtered agent
            assert week_metrics["metrics"]["alerts"]["total"] == len(filtered_alerts)
    
    async def test_custom_start_date(self, wazuh_server):
        """Test custom start date functionality."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {
            "weeks": 2,
            "start_date": "2024-01-01"
        }
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check that custom start date was used
        assert response_data["query_parameters"]["start_date"] == "2024-01-01"
        
        # Check date ranges
        first_week = list(response_data["weekly_metrics"].values())[0]
        assert "2024-01-01" in first_week["date_range"]
    
    async def test_recommendations_generation(self, wazuh_server, mock_alerts_weekly):
        """Test recommendations generation."""
        # Create high alert volume
        many_alerts = mock_alerts_weekly * 100  # Multiply to create high volume
        
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": many_alerts}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"weeks": 1}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have recommendations
        assert len(response_data["recommendations"]) > 0
        
        # Check recommendation structure
        for rec in response_data["recommendations"]:
            assert "priority" in rec
            assert "category" in rec
            assert "title" in rec
            assert "description" in rec
            assert "action" in rec
            assert "impact" in rec
        
        # Should have optimization recommendation for high alert volume
        opt_recs = [r for r in response_data["recommendations"] if r["category"] == "optimization"]
        assert len(opt_recs) > 0
    
    async def test_error_handling(self, wazuh_server):
        """Test error handling in weekly stats analysis."""
        # Mock API error
        wazuh_server.api_client.get_alerts.side_effect = Exception("API Error")
        
        arguments = {"weeks": 1}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        # Should return error response
        response_data = json.loads(result[0].text)
        assert "error" in response_data


class TestWeeklyStatsHelperMethods:
    """Test helper methods for weekly stats analysis."""
    
    @pytest.fixture
    def wazuh_server(self):
        """Create a minimal server instance for testing helper methods."""
        with patch('wazuh_mcp_server.main.WazuhConfig') as mock_config:
            mock_config.from_env.return_value = MagicMock()
            mock_config.from_env.return_value.log_level = "INFO"
            mock_config.from_env.return_value.debug = False
            
            server = WazuhMCPServer()
            return server
    
    def test_calculate_weekly_date_ranges(self, wazuh_server):
        """Test date range calculation."""
        from wazuh_mcp_server.utils.validation import WeeklyStatsQuery
        
        # Test with default (current date)
        query = WeeklyStatsQuery(weeks=2)
        ranges = wazuh_server._calculate_weekly_date_ranges(query)
        
        assert len(ranges) == 2
        for i, range_data in enumerate(ranges):
            assert range_data["week_number"] == i + 1
            assert "start_date" in range_data
            assert "end_date" in range_data
            assert "label" in range_data
            
            # Each week should be 7 days
            duration = range_data["end_date"] - range_data["start_date"]
            assert duration.days == 7
        
        # Test with custom start date
        query = WeeklyStatsQuery(weeks=1, start_date="2024-01-01")
        ranges = wazuh_server._calculate_weekly_date_ranges(query)
        
        assert len(ranges) == 1
        assert "2024-01-01" in ranges[0]["label"]
    
    def test_find_peak_hour(self, wazuh_server):
        """Test peak hour detection."""
        # Test with normal distribution
        hourly_dist = [0] * 24
        hourly_dist[14] = 100  # Peak at 2 PM
        
        peak = wazuh_server._find_peak_hour(hourly_dist)
        assert peak == 14
        
        # Test with empty distribution
        peak = wazuh_server._find_peak_hour([])
        assert peak == 0
    
    def test_find_most_active_day(self, wazuh_server):
        """Test most active day detection."""
        daily_dist = {
            "2024-01-01": 50,
            "2024-01-02": 100,
            "2024-01-03": 75
        }
        
        most_active = wazuh_server._find_most_active_day(daily_dist)
        assert most_active == "2024-01-02"
        
        # Test with empty distribution
        most_active = wazuh_server._find_most_active_day({})
        assert most_active == "N/A"
    
    def test_calculate_weekly_summary(self, wazuh_server):
        """Test weekly summary calculation."""
        weekly_metrics = {
            "Week 1": {
                "metrics": {
                    "alerts": {"total": 100, "critical": 10},
                    "agents": {"total": 50, "active": 45}
                }
            },
            "Week 2": {
                "metrics": {
                    "alerts": {"total": 150, "critical": 15},
                    "agents": {"total": 50, "active": 48}
                }
            }
        }
        
        summary = wazuh_server._calculate_weekly_summary(weekly_metrics)
        
        assert summary["total_weeks_analyzed"] == 2
        assert "totals" in summary
        assert "averages" in summary
        
        # Check totals
        assert summary["totals"]["alerts"]["total"] == 250
        assert summary["totals"]["alerts"]["critical"] == 25
        
        # Check averages
        assert summary["averages"]["alerts"]["total"] == 125
        assert summary["averages"]["alerts"]["critical"] == 12.5
    
    def test_analyze_weekly_trends(self, wazuh_server):
        """Test trend analysis."""
        weekly_metrics = {
            "Week 1": {
                "metrics": {
                    "alerts": {"total": 100, "severity_breakdown": {"critical": 10}},
                    "vulnerabilities": {"total": 50, "critical": 5}
                }
            },
            "Week 2": {
                "metrics": {
                    "alerts": {"total": 150, "severity_breakdown": {"critical": 20}},
                    "vulnerabilities": {"total": 60, "critical": 8}
                }
            }
        }
        
        trends = wazuh_server._analyze_weekly_trends(weekly_metrics)
        
        assert "alert_trend" in trends
        assert "vulnerability_trend" in trends
        assert "overall_direction" in trends
        
        # Should detect increasing trend (150 > 100 * 1.2)
        assert trends["overall_direction"] == "increasing"
        
        # Check trend data
        assert len(trends["alert_trend"]) == 2
        assert trends["alert_trend"][0]["total"] == 100
        assert trends["alert_trend"][1]["total"] == 150
    
    def test_forecast_next_week(self, wazuh_server):
        """Test forecasting functionality."""
        weekly_metrics = {
            "Week 1": {"metrics": {"alerts": {"total": 100}}},
            "Week 2": {"metrics": {"alerts": {"total": 120}}},
            "Week 3": {"metrics": {"alerts": {"total": 110}}},
            "Week 4": {"metrics": {"alerts": {"total": 130}}}
        }
        
        forecast = wazuh_server._forecast_next_week(weekly_metrics)
        
        assert "next_week_estimates" in forecast
        assert "confidence" in forecast
        assert "method" in forecast
        
        # Should use last 3 weeks for forecast
        if "alerts" in forecast["next_week_estimates"]:
            # Average of last 3 weeks: (120 + 110 + 130) / 3 = 120
            assert forecast["next_week_estimates"]["alerts"]["total"] == 120
        
        # With 4 weeks of data, confidence should be medium
        assert forecast["confidence"] == "medium"


@pytest.mark.asyncio
class TestWeeklyStatsEdgeCases:
    """Test edge cases for weekly stats analysis."""
    
    @pytest.fixture
    async def wazuh_server(self):
        """Create a mock server for edge case testing."""
        with patch('wazuh_mcp_server.main.WazuhConfig') as mock_config:
            mock_config.from_env.return_value = MagicMock()
            mock_config.from_env.return_value.log_level = "INFO"
            mock_config.from_env.return_value.debug = False
            mock_config.from_env.return_value.request_timeout_seconds = 30
            
            server = WazuhMCPServer()
            server.api_client = AsyncMock()
            return server
    
    async def test_no_data_available(self, wazuh_server):
        """Test handling when no data is available."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        wazuh_server.api_client.get_agent_vulnerabilities.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"weeks": 1}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle empty data gracefully
        assert "summary" in response_data
        assert "weekly_metrics" in response_data
        
        # Metrics should show zeros
        week_metrics = list(response_data["weekly_metrics"].values())[0]
        if "alerts" in week_metrics["metrics"]:
            assert week_metrics["metrics"]["alerts"]["total"] == 0
    
    async def test_partial_metric_failures(self, wazuh_server):
        """Test handling when some metrics fail to collect."""
        # Alerts succeed
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": [{"rule": {"level": 5}, "timestamp": datetime.utcnow().isoformat() + "Z"}]}
        }
        
        # Agents fail
        wazuh_server.api_client.get_agents.side_effect = Exception("Agent API Error")
        
        # Vulnerabilities succeed but return empty
        wazuh_server.api_client.get_agent_vulnerabilities.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"weeks": 1, "metrics": ["alerts", "agents", "vulnerabilities"]}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have collection errors
        assert response_data["analysis_metadata"]["collection_errors"] > 0
        
        # Should still have successful metrics
        week_metrics = list(response_data["weekly_metrics"].values())[0]
        assert "alerts" in week_metrics["metrics"]
        
        # Failed metrics should be handled
        if "agents" in week_metrics["metrics"]:
            # Should have error indicator or zero values
            assert week_metrics["metrics"]["agents"].get("total", 0) == 0
    
    async def test_maximum_weeks_analysis(self, wazuh_server):
        """Test analysis with maximum number of weeks."""
        # Create data for 12 weeks
        alerts = []
        base_time = datetime.utcnow()
        
        for week in range(12):
            for day in range(7):
                for i in range(10):
                    alerts.append({
                        "timestamp": (base_time - timedelta(weeks=week, days=day, hours=i)).isoformat() + "Z",
                        "rule": {"id": 5501, "level": 5},
                        "agent": {"name": "test-agent"}
                    })
        
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": alerts}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"weeks": 12}  # Maximum allowed
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have 12 weeks of data
        assert len(response_data["weekly_metrics"]) == 12
        assert response_data["summary"]["total_weeks_analyzed"] == 12
    
    async def test_invalid_date_ranges(self, wazuh_server):
        """Test handling of invalid date ranges."""
        # Future start date
        future_date = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d")
        
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"weeks": 1, "start_date": future_date}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle future dates (might have no data)
        assert "weekly_metrics" in response_data
        week_metrics = list(response_data["weekly_metrics"].values())[0]
        assert week_metrics["date_range"] is not None
    
    async def test_large_dataset_performance(self, wazuh_server):
        """Test handling of large datasets."""
        # Create large alert dataset
        large_alerts = []
        base_time = datetime.utcnow()
        
        for i in range(10000):  # 10k alerts
            large_alerts.append({
                "timestamp": (base_time - timedelta(hours=i % 168)).isoformat() + "Z",  # Spread over week
                "rule": {"id": 5501 + (i % 10), "level": 3 + (i % 12)},
                "agent": {"name": f"agent-{i % 20}"},
                "data": {"srcip": f"192.168.1.{i % 254}"}
            })
        
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": large_alerts}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"weeks": 1}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle large dataset
        assert "summary" in response_data
        assert "analysis_metadata" in response_data
        assert "processing_time_seconds" in response_data["analysis_metadata"]
        
        # Should have processed all alerts
        week_metrics = list(response_data["weekly_metrics"].values())[0]
        if "alerts" in week_metrics["metrics"]:
            assert week_metrics["metrics"]["alerts"]["total"] == 10000
    
    async def test_malformed_alert_data(self, wazuh_server):
        """Test handling of malformed alert data."""
        malformed_alerts = [
            {"timestamp": "invalid-date", "rule": {"level": "not-a-number"}},
            {"no_timestamp": True},
            {"timestamp": datetime.utcnow().isoformat() + "Z"},  # Missing rule
            {}  # Empty alert
        ]
        
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": malformed_alerts}
        }
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"weeks": 1}
        result = await wazuh_server._handle_get_wazuh_weekly_stats(arguments)
        
        # Should not crash
        response_data = json.loads(result[0].text)
        assert "summary" in response_data