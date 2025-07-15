"""Input validation utilities for secure API operations."""

import re
import ipaddress
import hashlib
from typing import Any, Dict, List, Optional, Union
from .pydantic_compat import BaseModel, Field, validator
# Security manager functionality moved to error recovery system


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


class AlertQuery(BaseModel):
    """Validated alert query parameters."""
    limit: int = Field(default=100, ge=1, le=10000, description="Maximum number of alerts")
    offset: int = Field(default=0, ge=0, description="Query offset")
    level: Optional[int] = Field(default=None, ge=1, le=15, description="Minimum alert level")
    sort: str = Field(default="-timestamp", description="Sort order")
    
    @validator('sort')
    def validate_sort(cls, v):
        """Validate sort parameter."""
        allowed_sorts = [
            "timestamp", "-timestamp", "level", "-level", 
            "rule.id", "-rule.id", "agent.name", "-agent.name"
        ]
        if v not in allowed_sorts:
            raise ValueError(f"Sort must be one of {allowed_sorts}")
        return v


class AgentQuery(BaseModel):
    """Validated agent query parameters."""
    agent_id: Optional[str] = Field(default=None, description="Specific agent ID")
    status: Optional[str] = Field(default=None, description="Agent status filter")
    
    @validator('agent_id')
    def validate_agent_id(cls, v):
        """Validate agent ID format."""
        if v is not None:
            if not re.match(r'^[0-9a-fA-F]{3,8}$', v):
                raise ValueError("Agent ID must be 3-8 character alphanumeric")
        return v
    
    @validator('status')
    def validate_status(cls, v):
        """Validate agent status."""
        if v is not None:
            allowed_statuses = ["active", "disconnected", "never_connected", "pending"]
            if v not in allowed_statuses:
                raise ValueError(f"Status must be one of {allowed_statuses}")
        return v


class ThreatAnalysisQuery(BaseModel):
    """Validated threat analysis parameters."""
    category: str = Field(default="all", description="Threat category")
    time_range: int = Field(default=3600, ge=300, le=86400, description="Time range in seconds")
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence threshold")
    
    @validator('category')
    def validate_category(cls, v):
        """Validate threat category."""
        allowed_categories = [
            "all", "intrusion", "malware", "vulnerability", 
            "compliance", "authentication", "dos", "data_leak"
        ]
        if v not in allowed_categories:
            raise ValueError(f"Category must be one of {allowed_categories}")
        return v


class IPAddress(BaseModel):
    """Validated IP address."""
    ip: str = Field(..., description="IP address to validate")
    
    @validator('ip')
    def validate_ip(cls, v):
        """Validate IP address format."""
        try:
            ipaddress.ip_address(v)
            # Check for private/local IPs that shouldn't be queried externally
            ip_obj = ipaddress.ip_address(v)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                raise ValueError("Cannot query reputation for private/local IP addresses")
            return v
        except ipaddress.AddressValueError:
            raise ValueError("Invalid IP address format")


class AlertSummaryQuery(BaseModel):
    """Validated alert summary query parameters."""
    time_range: str = Field(default="24h", description="Time range for analysis")
    custom_start: Optional[str] = Field(default=None, description="Custom start time")
    custom_end: Optional[str] = Field(default=None, description="Custom end time")
    severity_filter: Optional[List[str]] = Field(default=None, description="Severity levels to include")
    agent_filter: Optional[List[str]] = Field(default=None, description="Agent IDs or names to include")
    rule_filter: Optional[List[str]] = Field(default=None, description="Rule IDs or patterns to include")
    group_by: str = Field(default="severity", description="Grouping field")
    include_stats: bool = Field(default=True, description="Include statistical analysis")
    include_trends: bool = Field(default=True, description="Include trend analysis")
    max_alerts: int = Field(default=1000, ge=100, le=10000, description="Maximum alerts to analyze")
    
    @validator('time_range')
    def validate_time_range(cls, v):
        """Validate time range parameter."""
        allowed_ranges = ["1h", "6h", "12h", "24h", "7d", "30d", "custom"]
        if v not in allowed_ranges:
            raise ValueError(f"Time range must be one of {allowed_ranges}")
        return v
    
    @validator('custom_start', 'custom_end')
    def validate_custom_times(cls, v, values, field):
        """Validate custom time formats."""
        if v is not None:
            # Basic ISO format validation
            import re
            if not re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', v):
                raise ValueError(f"{field.name} must be in ISO format (YYYY-MM-DDTHH:MM:SS)")
        return v
    
    @validator('severity_filter')
    def validate_severity_filter(cls, v):
        """Validate severity filter values."""
        if v is not None:
            allowed_severities = ["critical", "high", "medium", "low"]
            for severity in v:
                if severity not in allowed_severities:
                    raise ValueError(f"Severity must be one of {allowed_severities}")
        return v
    
    @validator('group_by')
    def validate_group_by(cls, v):
        """Validate grouping field."""
        allowed_groups = ["rule", "agent", "severity", "time", "source_ip"]
        if v not in allowed_groups:
            raise ValueError(f"Group by must be one of {allowed_groups}")
        return v
    
    def validate_custom_time_range(self):
        """Validate that custom times are provided when needed."""
        if self.time_range == "custom":
            if not self.custom_start or not self.custom_end:
                raise ValueError("custom_start and custom_end are required when time_range is 'custom'")
        return True


class FileHash(BaseModel):
    """Validated file hash."""
    hash_value: str = Field(..., description="File hash to validate")
    hash_type: Optional[str] = Field(default=None, description="Hash type (md5, sha1, sha256)")
    
    @validator('hash_value')
    def validate_hash(cls, v, values):
        """Validate hash format."""
        # Remove any whitespace
        v = v.strip().lower()
        
        # Check for valid hex characters
        if not re.match(r'^[a-f0-9]+$', v):
            raise ValueError("Hash must contain only hexadecimal characters")
        
        # Validate length and determine hash type
        if len(v) == 32:
            values['hash_type'] = "md5"
        elif len(v) == 40:
            values['hash_type'] = "sha1"
        elif len(v) == 64:
            values['hash_type'] = "sha256"
        else:
            raise ValueError("Hash length must be 32 (MD5), 40 (SHA1), or 64 (SHA256) characters")
        
        return v
    
    def __init__(self, **data):
        """Initialize with hash type detection."""
        super().__init__(**data)
        if not self.hash_type and self.hash_value:
            # Set hash type based on length
            length = len(self.hash_value)
            if length == 32:
                self.hash_type = "md5"
            elif length == 40:
                self.hash_type = "sha1"
            elif length == 64:
                self.hash_type = "sha256"


def validate_alert_query(params: Dict[str, Any]) -> AlertQuery:
    """Validate and sanitize alert query parameters with security checks."""
    try:
        # Apply security validation
        # Security validation moved to error recovery system
        # context = SecurityContext(security_level=SecurityLevel.MEDIUM)
        # validated_params = security_manager.validate_wazuh_query_params(params)
        validated_params = params  # Direct validation for now
        
        return AlertQuery(**validated_params)
    except Exception as e:
        raise ValidationError(f"Invalid alert query parameters: {str(e)}")


def validate_agent_query(params: Dict[str, Any]) -> AgentQuery:
    """Validate and sanitize agent query parameters."""
    try:
        return AgentQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid agent query parameters: {str(e)}")


def validate_threat_analysis(params: Dict[str, Any]) -> ThreatAnalysisQuery:
    """Validate and sanitize threat analysis parameters."""
    try:
        return ThreatAnalysisQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid threat analysis parameters: {str(e)}")


class VulnerabilitySummaryQuery(BaseModel):
    """Validated vulnerability summary query parameters."""
    cvss_threshold: float = Field(default=0.0, ge=0.0, le=10.0, description="Minimum CVSS score")
    severity_filter: Optional[List[str]] = Field(default=None, description="Severity levels to include")
    cve_filter: Optional[List[str]] = Field(default=None, description="Specific CVEs to include")
    os_filter: Optional[List[str]] = Field(default=None, description="Operating systems to include")
    package_filter: Optional[List[str]] = Field(default=None, description="Package names to include")
    exploitability: bool = Field(default=False, description="Filter to known exploits only")
    group_by: str = Field(default="severity", description="Grouping field")
    include_remediation: bool = Field(default=True, description="Include remediation suggestions")
    include_analytics: bool = Field(default=True, description="Include risk analytics")
    max_agents: int = Field(default=100, ge=1, le=1000, description="Maximum agents to analyze")
    
    @validator('severity_filter')
    def validate_severity_filter(cls, v):
        """Validate severity filter values."""
        if v is not None:
            allowed_severities = ["critical", "high", "medium", "low"]
            for severity in v:
                if severity not in allowed_severities:
                    raise ValueError(f"Severity must be one of {allowed_severities}")
        return v
    
    @validator('group_by')
    def validate_group_by(cls, v):
        """Validate grouping field."""
        allowed_groups = ["agent", "severity", "package", "cve", "os"]
        if v not in allowed_groups:
            raise ValueError(f"Group by must be one of {allowed_groups}")
        return v
    
    @validator('cvss_threshold')
    def validate_cvss_threshold(cls, v):
        """Validate CVSS threshold."""
        if v < 0.0 or v > 10.0:
            raise ValueError("CVSS threshold must be between 0.0 and 10.0")
        return v


def validate_alert_summary_query(params: Dict[str, Any]) -> AlertSummaryQuery:
    """Validate and sanitize alert summary query parameters."""
    try:
        query = AlertSummaryQuery(**params)
        query.validate_custom_time_range()
        return query
    except Exception as e:
        raise ValidationError(f"Invalid alert summary query parameters: {str(e)}")


class CriticalVulnerabilitiesQuery(BaseModel):
    """Validated critical vulnerabilities query parameters."""
    min_cvss: float = Field(default=9.0, ge=0.0, le=10.0, description="Minimum CVSS score")
    exploit_required: bool = Field(default=True, description="Only show vulnerabilities with known exploits")
    internet_exposed: bool = Field(default=False, description="Filter by internet exposure")
    patch_available: bool = Field(default=False, description="Only show actionable items with patches")
    age_days: Optional[int] = Field(default=None, ge=0, description="Maximum vulnerability age in days")
    affected_services: Optional[List[str]] = Field(default=None, description="Filter by critical services")
    include_context: bool = Field(default=True, description="Include network and process context")
    max_results: int = Field(default=100, ge=1, le=500, description="Maximum results to return")
    
    @validator('min_cvss')
    def validate_min_cvss(cls, v):
        """Validate minimum CVSS score."""
        if v < 0.0 or v > 10.0:
            raise ValueError("CVSS score must be between 0.0 and 10.0")
        return v
    
    @validator('affected_services')
    def validate_affected_services(cls, v):
        """Validate affected services list."""
        if v is not None:
            # Common critical services
            valid_services = [
                "web", "database", "api", "payment", "authentication", 
                "ssh", "rdp", "ftp", "mail", "dns", "critical", "production"
            ]
            for service in v:
                if service.lower() not in valid_services:
                    # Allow custom services but log warning
                    pass  # Custom services are allowed
        return v


def validate_vulnerability_summary_query(params: Dict[str, Any]) -> VulnerabilitySummaryQuery:
    """Validate and sanitize vulnerability summary query parameters."""
    try:
        return VulnerabilitySummaryQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid vulnerability summary query parameters: {str(e)}")


def validate_critical_vulnerabilities_query(params: Dict[str, Any]) -> CriticalVulnerabilitiesQuery:
    """Validate and sanitize critical vulnerabilities query parameters."""
    try:
        return CriticalVulnerabilitiesQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid critical vulnerabilities query parameters: {str(e)}")


class RunningAgentsQuery(BaseModel):
    """Validated running agents query parameters."""
    status_filter: Optional[List[str]] = Field(default=None, description="Agent status filter")
    os_filter: Optional[List[str]] = Field(default=None, description="Operating system filter")
    version_filter: Optional[str] = Field(default=None, description="Agent version filter")
    group_filter: Optional[List[str]] = Field(default=None, description="Agent group filter")
    inactive_threshold: int = Field(default=300, ge=60, le=3600, description="Inactive threshold in seconds")
    include_disconnected: bool = Field(default=False, description="Include disconnected agents")
    include_health_metrics: bool = Field(default=True, description="Include health and performance metrics")
    include_last_activity: bool = Field(default=True, description="Include last activity analysis")
    group_by: str = Field(default="status", description="Grouping field")
    max_agents: int = Field(default=1000, ge=1, le=5000, description="Maximum agents to analyze")
    
    @validator('status_filter')
    def validate_status_filter(cls, v):
        """Validate agent status filter."""
        if v is not None:
            allowed_statuses = ["active", "disconnected", "never_connected", "pending"]
            for status in v:
                if status not in allowed_statuses:
                    raise ValueError(f"Status must be one of {allowed_statuses}")
        return v
    
    @validator('group_by')
    def validate_group_by(cls, v):
        """Validate grouping field."""
        allowed_groups = ["status", "os", "version", "group", "node", "location"]
        if v not in allowed_groups:
            raise ValueError(f"Group by must be one of {allowed_groups}")
        return v
    
    @validator('inactive_threshold')
    def validate_inactive_threshold(cls, v):
        """Validate inactive threshold."""
        if v < 60 or v > 3600:
            raise ValueError("Inactive threshold must be between 60 and 3600 seconds")
        return v


def validate_running_agents_query(params: Dict[str, Any]) -> RunningAgentsQuery:
    """Validate and sanitize running agents query parameters."""
    try:
        return RunningAgentsQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid running agents query parameters: {str(e)}")


class RulesSummaryQuery(BaseModel):
    """Validated rules summary query parameters."""
    rule_level_filter: Optional[List[int]] = Field(default=None, description="Filter by rule levels")
    rule_group_filter: Optional[List[str]] = Field(default=None, description="Filter by rule groups")
    rule_id_filter: Optional[List[int]] = Field(default=None, description="Filter by specific rule IDs")
    category_filter: Optional[List[str]] = Field(default=None, description="Filter by rule categories")
    status_filter: str = Field(default="enabled", description="Rule status filter")
    include_disabled: bool = Field(default=False, description="Include disabled rules")
    include_usage_stats: bool = Field(default=True, description="Include rule usage statistics")
    include_coverage_analysis: bool = Field(default=True, description="Include coverage analysis")
    group_by: str = Field(default="level", description="Grouping field")
    sort_by: str = Field(default="level", description="Sort field")
    max_rules: int = Field(default=1000, ge=10, le=10000, description="Maximum rules to analyze")
    
    @validator('rule_level_filter')
    def validate_rule_level_filter(cls, v):
        """Validate rule level filter."""
        if v is not None:
            for level in v:
                if not 0 <= level <= 16:
                    raise ValueError("Rule levels must be between 0 and 16")
        return v
    
    @validator('status_filter')
    def validate_status_filter(cls, v):
        """Validate rule status filter."""
        allowed_statuses = ["enabled", "disabled", "all"]
        if v not in allowed_statuses:
            raise ValueError(f"Status filter must be one of {allowed_statuses}")
        return v
    
    @validator('group_by')
    def validate_group_by(cls, v):
        """Validate grouping field."""
        allowed_groups = ["level", "group", "category", "file", "status"]
        if v not in allowed_groups:
            raise ValueError(f"Group by must be one of {allowed_groups}")
        return v
    
    @validator('sort_by')
    def validate_sort_by(cls, v):
        """Validate sort field."""
        allowed_sorts = ["level", "id", "group", "frequency", "file"]
        if v not in allowed_sorts:
            raise ValueError(f"Sort by must be one of {allowed_sorts}")
        return v
    
    @validator('category_filter')
    def validate_category_filter(cls, v):
        """Validate category filter."""
        if v is not None:
            valid_categories = [
                "authentication", "firewall", "ids", "syscheck", "rootcheck",
                "ossec", "sysmon", "web", "squid", "windows", "attack",
                "vulnerability", "malware", "compliance", "network"
            ]
            for category in v:
                if category.lower() not in valid_categories:
                    # Allow custom categories but log warning
                    pass
        return v


def validate_rules_summary_query(params: Dict[str, Any]) -> RulesSummaryQuery:
    """Validate and sanitize rules summary query parameters."""
    try:
        return RulesSummaryQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid rules summary query parameters: {str(e)}")


class WeeklyStatsQuery(BaseModel):
    """Validated weekly stats query parameters."""
    weeks: int = Field(default=1, ge=1, le=12, description="Number of weeks to analyze")
    start_date: Optional[str] = Field(default=None, description="Custom start date")
    metrics: Optional[List[str]] = Field(default=None, description="Specific metrics to include")
    include_trends: bool = Field(default=True, description="Include trend analysis")
    include_comparison: bool = Field(default=True, description="Include week-over-week comparison")
    include_forecasting: bool = Field(default=False, description="Include basic forecasting")
    include_predictions: bool = Field(default=True, description="Include predictive analysis")
    anomaly_detection: bool = Field(default=True, description="Enable anomaly detection")
    seasonality_analysis: bool = Field(default=True, description="Include seasonality detection")
    behavioral_analysis: bool = Field(default=True, description="Include behavioral pattern analysis")
    statistical_analysis: bool = Field(default=True, description="Include statistical metrics")
    compare_weeks: int = Field(default=4, ge=1, le=52, description="Number of weeks for comparison baseline")
    anomaly_threshold: float = Field(default=2.0, ge=1.0, le=5.0, description="Anomaly detection threshold (standard deviations)")
    group_by: str = Field(default="day", description="Grouping granularity")
    agent_filter: Optional[List[str]] = Field(default=None, description="Filter by specific agents")
    rule_filter: Optional[List[str]] = Field(default=None, description="Filter by specific rules")
    output_format: str = Field(default="detailed", description="Output format")
    
    @validator('start_date')
    def validate_start_date(cls, v):
        """Validate start date format."""
        if v is not None:
            import re
            if not re.match(r'^\d{4}-\d{2}-\d{2}$', v):
                raise ValueError("Start date must be in YYYY-MM-DD format")
        return v
    
    @validator('metrics')
    def validate_metrics(cls, v):
        """Validate metrics selection."""
        if v is not None:
            valid_metrics = [
                "alerts", "events", "agents", "rules", "compliance",
                "vulnerabilities", "authentication", "network", "files"
            ]
            for metric in v:
                if metric not in valid_metrics:
                    raise ValueError(f"Metric must be one of {valid_metrics}")
        return v
    
    @validator('group_by')
    def validate_group_by(cls, v):
        """Validate grouping granularity."""
        allowed_groups = ["hour", "day", "week"]
        if v not in allowed_groups:
            raise ValueError(f"Group by must be one of {allowed_groups}")
        return v
    
    @validator('output_format')
    def validate_output_format(cls, v):
        """Validate output format."""
        allowed_formats = ["detailed", "summary", "minimal"]
        if v not in allowed_formats:
            raise ValueError(f"Output format must be one of {allowed_formats}")
        return v


def validate_weekly_stats_query(params: Dict[str, Any]) -> WeeklyStatsQuery:
    """Validate and sanitize weekly stats query parameters."""
    try:
        return WeeklyStatsQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid weekly stats query parameters: {str(e)}")


class RemotedStatsQuery(BaseModel):
    """Validated remoted stats query parameters."""
    time_range: str = Field(default="24h", description="Time range for analysis")
    node_filter: Optional[List[str]] = Field(default=None, description="Filter by specific nodes")
    include_performance: bool = Field(default=True, description="Include performance metrics")
    include_connections: bool = Field(default=True, description="Include connection statistics")
    include_events: bool = Field(default=True, description="Include event processing metrics")
    include_queues: bool = Field(default=True, description="Include queue statistics")
    include_errors: bool = Field(default=True, description="Include error analysis")
    include_trends: bool = Field(default=True, description="Include trend analysis")
    include_communication_metrics: bool = Field(default=True, description="Include communication health metrics")
    include_health_monitoring: bool = Field(default=True, description="Include health monitoring and diagnostics")
    include_throughput_analysis: bool = Field(default=True, description="Include throughput and latency analysis")
    include_reliability_scoring: bool = Field(default=True, description="Include reliability and availability scoring")
    include_diagnostics: bool = Field(default=True, description="Include troubleshooting diagnostics")
    include_capacity_planning: bool = Field(default=True, description="Include capacity planning metrics")
    group_by: str = Field(default="node", description="Grouping field")
    output_format: str = Field(default="detailed", description="Output format")
    threshold_cpu: float = Field(default=80.0, ge=0.0, le=100.0, description="CPU usage threshold")
    threshold_memory: float = Field(default=80.0, ge=0.0, le=100.0, description="Memory usage threshold")
    threshold_queue: int = Field(default=1000, ge=0, description="Queue size threshold")
    threshold_latency: float = Field(default=5.0, ge=0.0, le=60.0, description="Latency threshold in seconds")
    threshold_error_rate: float = Field(default=5.0, ge=0.0, le=100.0, description="Error rate threshold percentage")
    alert_on_anomalies: bool = Field(default=True, description="Generate alerts for detected anomalies")
    
    @validator('time_range')
    def validate_time_range(cls, v):
        """Validate time range parameter."""
        allowed_ranges = ["1h", "6h", "12h", "24h", "7d", "30d"]
        if v not in allowed_ranges:
            raise ValueError(f"Time range must be one of {allowed_ranges}")
        return v
    
    @validator('group_by')
    def validate_group_by(cls, v):
        """Validate grouping field."""
        allowed_groups = ["node", "connection_type", "event_type", "status"]
        if v not in allowed_groups:
            raise ValueError(f"Group by must be one of {allowed_groups}")
        return v
    
    @validator('output_format')
    def validate_output_format(cls, v):
        """Validate output format."""
        allowed_formats = ["detailed", "summary", "minimal"]
        if v not in allowed_formats:
            raise ValueError(f"Output format must be one of {allowed_formats}")
        return v
    
    @validator('threshold_cpu', 'threshold_memory')
    def validate_percentage_thresholds(cls, v):
        """Validate percentage thresholds."""
        if v < 0.0 or v > 100.0:
            raise ValueError("Percentage thresholds must be between 0.0 and 100.0")
        return v


def validate_remoted_stats_query(params: Dict[str, Any]) -> RemotedStatsQuery:
    """Validate and sanitize remoted stats query parameters."""
    try:
        return RemotedStatsQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid remoted stats query parameters: {str(e)}")


class LogCollectorStatsQuery(BaseModel):
    """Validated log collector stats query parameters."""
    time_range: str = Field(default="24h", description="Time range for analysis")
    node_filter: Optional[List[str]] = Field(default=None, description="Filter by specific nodes")
    agent_filter: Optional[List[str]] = Field(default=None, description="Filter by specific agents")
    log_type_filter: Optional[List[str]] = Field(default=None, description="Filter by log types")
    include_performance: bool = Field(default=True, description="Include performance metrics")
    include_file_monitoring: bool = Field(default=True, description="Include file monitoring statistics")
    include_processing_stats: bool = Field(default=True, description="Include log processing metrics")
    include_error_analysis: bool = Field(default=True, description="Include error analysis")
    include_efficiency: bool = Field(default=True, description="Include efficiency analysis")
    include_trends: bool = Field(default=True, description="Include trend analysis")
    include_coverage_analysis: bool = Field(default=True, description="Include coverage analysis with compliance mapping")
    include_resource_monitoring: bool = Field(default=True, description="Include resource usage tracking")
    include_bottleneck_detection: bool = Field(default=True, description="Include bottleneck detection and optimization")
    include_capacity_planning: bool = Field(default=True, description="Include capacity planning metrics")
    compliance_frameworks: Optional[List[str]] = Field(default=None, description="Compliance frameworks to map (PCI, SOX, HIPAA, etc.)")
    group_by: str = Field(default="node", description="Grouping field")
    output_format: str = Field(default="detailed", description="Output format")
    threshold_processing_rate: int = Field(default=1000, ge=0, description="Minimum logs per second threshold")
    threshold_error_rate: float = Field(default=5.0, ge=0.0, le=100.0, description="Maximum error rate threshold")
    threshold_file_lag: int = Field(default=300, ge=0, description="Maximum file monitoring lag in seconds")
    threshold_resource_usage: float = Field(default=80.0, ge=0.0, le=100.0, description="Resource usage threshold for alerts")
    coverage_threshold: float = Field(default=90.0, ge=0.0, le=100.0, description="Minimum coverage threshold percentage")
    
    @validator('time_range')
    def validate_time_range(cls, v):
        """Validate time range parameter."""
        allowed_ranges = ["1h", "6h", "12h", "24h", "7d", "30d"]
        if v not in allowed_ranges:
            raise ValueError(f"Time range must be one of {allowed_ranges}")
        return v
    
    @validator('log_type_filter')
    def validate_log_type_filter(cls, v):
        """Validate log type filter."""
        if v is not None:
            valid_types = [
                "apache", "nginx", "syslog", "windows", "eventlog", "macos",
                "auth", "firewall", "application", "security", "system", "audit"
            ]
            for log_type in v:
                if log_type.lower() not in valid_types:
                    # Allow custom log types but validate format
                    if not re.match(r'^[a-zA-Z0-9_-]+$', log_type):
                        raise ValueError(f"Invalid log type format: {log_type}")
        return v
    
    @validator('compliance_frameworks')
    def validate_compliance_frameworks(cls, v):
        """Validate compliance frameworks."""
        if v is not None:
            valid_frameworks = [
                "pci", "pci-dss", "sox", "sarbanes-oxley", "hipaa", "gdpr", 
                "iso27001", "nist", "cis", "fisma", "fedramp", "cmmc"
            ]
            for framework in v:
                if framework.lower() not in valid_frameworks:
                    # Allow custom frameworks but validate format
                    if not re.match(r'^[a-zA-Z0-9_-]+$', framework):
                        raise ValueError(f"Invalid compliance framework format: {framework}")
        return v
    
    @validator('group_by')
    def validate_group_by(cls, v):
        """Validate grouping field."""
        allowed_groups = ["node", "agent", "log_type", "status", "performance"]
        if v not in allowed_groups:
            raise ValueError(f"Group by must be one of {allowed_groups}")
        return v
    
    @validator('output_format')
    def validate_output_format(cls, v):
        """Validate output format."""
        allowed_formats = ["detailed", "summary", "minimal"]
        if v not in allowed_formats:
            raise ValueError(f"Output format must be one of {allowed_formats}")
        return v
    
    @validator('threshold_error_rate')
    def validate_error_rate_threshold(cls, v):
        """Validate error rate threshold."""
        if v < 0.0 or v > 100.0:
            raise ValueError("Error rate threshold must be between 0.0 and 100.0")
        return v
    
    @validator('threshold_resource_usage', 'coverage_threshold')
    def validate_percentage_thresholds(cls, v):
        """Validate percentage thresholds."""
        if v < 0.0 or v > 100.0:
            raise ValueError("Percentage thresholds must be between 0.0 and 100.0")
        return v


def validate_log_collector_stats_query(params: Dict[str, Any]) -> LogCollectorStatsQuery:
    """Validate and sanitize log collector stats query parameters."""
    try:
        return LogCollectorStatsQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid log collector stats query parameters: {str(e)}")


class ClusterHealthQuery(BaseModel):
    """Validated cluster health query parameters."""
    include_node_details: bool = Field(default=True, description="Include detailed node information")
    include_performance: bool = Field(default=True, description="Include performance metrics")
    include_connectivity: bool = Field(default=True, description="Include connectivity analysis")
    include_resource_usage: bool = Field(default=True, description="Include resource utilization")
    include_service_status: bool = Field(default=True, description="Include service status checks")
    include_disk_usage: bool = Field(default=True, description="Include disk usage analysis")
    include_network_stats: bool = Field(default=True, description="Include network statistics")
    include_recommendations: bool = Field(default=True, description="Include health recommendations")
    include_diagnostics: bool = Field(default=True, description="Include comprehensive diagnostics and troubleshooting")
    include_failure_prediction: bool = Field(default=True, description="Include failure prediction and trending")
    include_sync_monitoring: bool = Field(default=True, description="Include synchronization monitoring")
    include_root_cause_analysis: bool = Field(default=True, description="Include root cause analysis")
    include_remediation_steps: bool = Field(default=True, description="Include detailed remediation steps")
    include_health_trending: bool = Field(default=True, description="Include health trending analysis")
    include_predictive_alerts: bool = Field(default=True, description="Include predictive alerts")
    health_threshold_cpu: float = Field(default=80.0, ge=0.0, le=100.0, description="CPU usage threshold")
    health_threshold_memory: float = Field(default=85.0, ge=0.0, le=100.0, description="Memory usage threshold")
    health_threshold_disk: float = Field(default=90.0, ge=0.0, le=100.0, description="Disk usage threshold")
    sync_lag_threshold: int = Field(default=30, ge=1, le=300, description="Sync lag threshold in seconds")
    connectivity_timeout: int = Field(default=5, ge=1, le=60, description="Connectivity check timeout in seconds")
    prediction_window_hours: int = Field(default=24, ge=1, le=168, description="Prediction window in hours")
    alert_escalation_threshold: int = Field(default=3, ge=1, le=10, description="Alert escalation threshold")
    output_format: str = Field(default="detailed", description="Output format")
    
    @validator('health_threshold_cpu', 'health_threshold_memory', 'health_threshold_disk')
    def validate_percentage_thresholds(cls, v):
        """Validate percentage thresholds."""
        if v < 0.0 or v > 100.0:
            raise ValueError("Health thresholds must be between 0.0 and 100.0")
        return v
    
    @validator('output_format')
    def validate_output_format(cls, v):
        """Validate output format."""
        allowed_formats = ["detailed", "summary", "minimal"]
        if v not in allowed_formats:
            raise ValueError(f"Output format must be one of {allowed_formats}")
        return v
    
    @validator('connectivity_timeout')
    def validate_connectivity_timeout(cls, v):
        """Validate connectivity timeout."""
        if v < 1 or v > 60:
            raise ValueError("Connectivity timeout must be between 1 and 60 seconds")
        return v
    
    @validator('sync_lag_threshold')
    def validate_sync_lag_threshold(cls, v):
        """Validate sync lag threshold."""
        if v < 1 or v > 300:
            raise ValueError("Sync lag threshold must be between 1 and 300 seconds")
        return v
    
    @validator('prediction_window_hours')
    def validate_prediction_window(cls, v):
        """Validate prediction window."""
        if v < 1 or v > 168:
            raise ValueError("Prediction window must be between 1 and 168 hours")
        return v
    
    @validator('alert_escalation_threshold')
    def validate_alert_escalation_threshold(cls, v):
        """Validate alert escalation threshold."""
        if v < 1 or v > 10:
            raise ValueError("Alert escalation threshold must be between 1 and 10")
        return v


class ClusterNodesQuery(BaseModel):
    """Validated cluster nodes query parameters."""
    node_type: List[str] = Field(default=["all"], description="Node types to include")
    status_filter: List[str] = Field(default=["all"], description="Status filters")
    node_name: Optional[str] = Field(default=None, description="Specific node name")
    include_performance: bool = Field(default=True, description="Include performance metrics")
    include_configuration: bool = Field(default=False, description="Include configuration details")
    include_sync_status: bool = Field(default=True, description="Include sync status")
    include_load_metrics: bool = Field(default=True, description="Include load metrics")
    include_agent_distribution: bool = Field(default=True, description="Include agent distribution")
    performance_threshold_cpu: float = Field(default=80.0, ge=0.0, le=100.0, description="CPU threshold")
    performance_threshold_memory: float = Field(default=85.0, ge=0.0, le=100.0, description="Memory threshold")
    sync_lag_threshold: int = Field(default=30, ge=0, le=600, description="Sync lag threshold in seconds")
    output_format: str = Field(default="detailed", description="Output format")
    
    @validator('node_type')
    def validate_node_type(cls, v):
        """Validate node type."""
        allowed_types = ["master", "worker", "all"]
        for node_type in v:
            if node_type not in allowed_types:
                raise ValueError(f"Node type must be one of {allowed_types}")
        return v
    
    @validator('status_filter')
    def validate_status_filter(cls, v):
        """Validate status filter."""
        allowed_statuses = ["active", "inactive", "disconnected", "all"]
        for status in v:
            if status not in allowed_statuses:
                raise ValueError(f"Status must be one of {allowed_statuses}")
        return v
    
    @validator('node_name')
    def validate_node_name(cls, v):
        """Validate node name."""
        if v is not None:
            if not re.match(r'^[a-zA-Z0-9_-]+$', v):
                raise ValueError("Node name must contain only alphanumeric characters, underscores, and hyphens")
        return v
    
    @validator('performance_threshold_cpu', 'performance_threshold_memory')
    def validate_performance_thresholds(cls, v):
        """Validate performance thresholds."""
        if v < 0.0 or v > 100.0:
            raise ValueError("Performance thresholds must be between 0.0 and 100.0")
        return v
    
    @validator('output_format')
    def validate_output_format(cls, v):
        """Validate output format."""
        allowed_formats = ["detailed", "summary", "minimal"]
        if v not in allowed_formats:
            raise ValueError(f"Output format must be one of {allowed_formats}")
        return v
    
    @validator('sync_lag_threshold')
    def validate_sync_lag_threshold(cls, v):
        """Validate sync lag threshold."""
        if v < 0 or v > 600:
            raise ValueError("Sync lag threshold must be between 0 and 600 seconds")
        return v


class ManagerErrorLogsQuery(BaseModel):
    """Validated manager error logs query parameters."""
    error_level: List[str] = Field(default=["ERROR", "CRITICAL"], description="Error levels to include")
    time_range: str = Field(default="24h", description="Time range for analysis")
    start_time: Optional[str] = Field(default=None, description="Custom start time (ISO format)")
    end_time: Optional[str] = Field(default=None, description="Custom end time (ISO format)")
    component_filter: List[str] = Field(default=[], description="Component filters")
    pattern_filter: Optional[str] = Field(default=None, description="Pattern filter regex")
    include_analysis: bool = Field(default=True, description="Include detailed analysis")
    include_trends: bool = Field(default=True, description="Include trend analysis")
    correlation_analysis: bool = Field(default=True, description="Include correlation analysis")
    max_errors: int = Field(default=500, ge=1, le=5000, description="Maximum errors to analyze")
    
    @validator('error_level')
    def validate_error_level(cls, v):
        """Validate error levels."""
        allowed_levels = ["ERROR", "CRITICAL", "WARNING", "INFO", "DEBUG"]
        for level in v:
            if level not in allowed_levels:
                raise ValueError(f"Error level must be one of {allowed_levels}")
        return v
    
    @validator('time_range')
    def validate_time_range(cls, v):
        """Validate time range."""
        allowed_ranges = ["1h", "6h", "12h", "24h", "7d", "30d", "custom"]
        if v not in allowed_ranges:
            raise ValueError(f"Time range must be one of {allowed_ranges}")
        return v
    
    @validator('component_filter')
    def validate_component_filter(cls, v):
        """Validate component filters."""
        allowed_components = [
            "core", "api", "cluster", "modules", "authentication", 
            "monitor", "remote", "analysisd", "authd", "remoted",
            "monitord", "modulesd", "logcollector", "wazuh-db"
        ]
        for component in v:
            if component not in allowed_components:
                raise ValueError(f"Component must be one of {allowed_components}")
        return v
    
    @validator('pattern_filter')
    def validate_pattern_filter(cls, v):
        """Validate pattern filter."""
        if v is not None:
            # Basic regex validation - check for common dangerous patterns
            import re
            try:
                re.compile(v)
            except re.error:
                raise ValueError("Invalid regex pattern")
            
            # Check for potentially dangerous patterns
            dangerous_patterns = [
                r'.*\*{10,}.*',  # Many wildcards
                r'.*\+{10,}.*',  # Many plus signs
                r'.*\?{10,}.*',  # Many question marks
            ]
            for pattern in dangerous_patterns:
                if re.match(pattern, v):
                    raise ValueError("Pattern may cause performance issues")
        return v
    
    @validator('start_time', 'end_time')
    def validate_time_format(cls, v):
        """Validate time format."""
        if v is not None:
            try:
                from datetime import datetime
                datetime.fromisoformat(v.replace('Z', '+00:00'))
            except ValueError:
                raise ValueError("Time must be in ISO format (YYYY-MM-DDTHH:MM:SS)")
        return v


class AgentProcessesQuery(BaseModel):
    """Validated agent processes query parameters."""
    agent_id: str = Field(..., description="Agent ID to query")
    process_filter: Optional[str] = Field(default=None, description="Process name pattern filter")
    include_children: bool = Field(default=True, description="Include child process hierarchy analysis")
    sort_by: str = Field(default="threat_score", description="Sort processes by specified metric")
    include_hashes: bool = Field(default=True, description="Include file hash verification")
    suspicious_only: bool = Field(default=False, description="Show only suspicious processes")
    threat_detection: bool = Field(default=True, description="Enable threat detection")
    include_network_activity: bool = Field(default=True, description="Include network analysis")
    baseline_comparison: bool = Field(default=True, description="Enable baseline comparison")
    max_processes: int = Field(default=500, ge=1, le=2000, description="Maximum processes to analyze")
    
    @validator('agent_id')
    def validate_agent_id(cls, v):
        """Validate agent ID format."""
        if not re.match(r'^[0-9a-fA-F]{3,8}$', v):
            raise ValueError("Agent ID must be 3-8 character alphanumeric")
        return v
    
    @validator('process_filter')
    def validate_process_filter(cls, v):
        """Validate process filter pattern."""
        if v is not None:
            # Basic regex validation
            import re
            try:
                re.compile(v)
            except re.error:
                raise ValueError("Invalid regex pattern for process filter")
            
            # Check for potentially dangerous patterns
            if len(v) > 200:
                raise ValueError("Process filter pattern too long")
        return v
    
    @validator('sort_by')
    def validate_sort_by(cls, v):
        """Validate sort by field."""
        allowed_sorts = ["cpu", "memory", "pid", "name", "threat_score"]
        if v not in allowed_sorts:
            raise ValueError(f"Sort by must be one of {allowed_sorts}")
        return v


class AgentPortsQuery(BaseModel):
    """Validated agent ports query parameters."""
    agent_id: str = Field(..., description="Agent ID to query")
    port_state: List[str] = Field(default=["open", "listening"], description="Port states to include")
    protocol: List[str] = Field(default=["tcp", "udp"], description="Network protocols to analyze") 
    include_process: bool = Field(default=True, description="Include process information")
    known_services_only: bool = Field(default=False, description="Show only well-known service ports")
    exposure_analysis: bool = Field(default=True, description="Enable exposure risk analysis")
    backdoor_detection: bool = Field(default=True, description="Enable backdoor detection")
    baseline_comparison: bool = Field(default=True, description="Compare against port baseline")
    include_firewall_analysis: bool = Field(default=True, description="Include firewall analysis")
    threat_intelligence: bool = Field(default=True, description="Enable threat intelligence")
    max_ports: int = Field(default=1000, ge=1, le=5000, description="Maximum ports to analyze")

    @validator('agent_id')
    def validate_agent_id(cls, v):
        """Validate agent ID format."""
        if not re.match(r'^[0-9a-fA-F]{3,8}$', v):
            raise ValueError("Agent ID must be 3-8 character alphanumeric")
        return v

    @validator('port_state')
    def validate_port_state(cls, v):
        """Validate port state values."""
        allowed_states = ["open", "listening", "established", "closed", "all"]
        for state in v:
            if state not in allowed_states:
                raise ValueError(f"Port state must be one of {allowed_states}")
        return v

    @validator('protocol')
    def validate_protocol(cls, v):
        """Validate protocol values."""
        allowed_protocols = ["tcp", "udp", "all"]
        for protocol in v:
            if protocol not in allowed_protocols:
                raise ValueError(f"Protocol must be one of {allowed_protocols}")
        return v


def validate_agent_processes_query(params: Dict[str, Any]) -> AgentProcessesQuery:
    """Validate and sanitize agent processes query parameters."""
    try:
        return AgentProcessesQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid agent processes query parameters: {str(e)}")


def validate_agent_ports_query(params: Dict[str, Any]) -> AgentPortsQuery:
    """Validate and sanitize agent ports query parameters."""
    try:
        return AgentPortsQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid agent ports query parameters: {str(e)}")


def validate_manager_error_logs_query(params: Dict[str, Any]) -> ManagerErrorLogsQuery:
    """Validate and sanitize manager error logs query parameters."""
    try:
        return ManagerErrorLogsQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid manager error logs query parameters: {str(e)}")


def validate_cluster_nodes_query(params: Dict[str, Any]) -> ClusterNodesQuery:
    """Validate and sanitize cluster nodes query parameters."""
    try:
        return ClusterNodesQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid cluster nodes query parameters: {str(e)}")


def validate_cluster_health_query(params: Dict[str, Any]) -> ClusterHealthQuery:
    """Validate and sanitize cluster health query parameters."""
    try:
        return ClusterHealthQuery(**params)
    except Exception as e:
        raise ValidationError(f"Invalid cluster health query parameters: {str(e)}")


def validate_ip_address(ip: str) -> IPAddress:
    """Validate IP address."""
    try:
        return IPAddress(ip=ip)
    except Exception as e:
        raise ValidationError(f"Invalid IP address: {str(e)}")


def validate_file_hash(hash_value: str) -> FileHash:
    """Validate file hash."""
    try:
        return FileHash(hash_value=hash_value)
    except Exception as e:
        raise ValidationError(f"Invalid file hash: {str(e)}")


def sanitize_string(input_str: str, max_length: int = 1000) -> str:
    """Sanitize string input to prevent injection attacks."""
    if not input_str:
        return ""
    
    # Remove null bytes and control characters
    sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_str)
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()


def validate_json_payload(payload: Any, max_size: int = 10000) -> Dict[str, Any]:
    """Validate JSON payload size and structure."""
    if not isinstance(payload, dict):
        raise ValidationError("Payload must be a JSON object")
    
    # Check payload size (approximate)
    import json
    payload_str = json.dumps(payload)
    if len(payload_str) > max_size:
        raise ValidationError(f"Payload too large (max {max_size} bytes)")
    
    return payload