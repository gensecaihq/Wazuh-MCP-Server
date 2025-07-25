"""
Production-grade Pydantic models for FastMCP compliance and validation.
Implements comprehensive data models following FastMCP standards.
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional, Union, Literal, Set
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
import re

try:
    from pydantic import BaseModel, Field, validator, root_validator
    from pydantic.types import StrictStr, StrictInt, StrictBool
except ImportError:
    # Fallback for different Pydantic versions
    from pydantic.v1 import BaseModel, Field, validator, root_validator
    from pydantic.v1.types import StrictStr, StrictInt, StrictBool


# ============================================================================
# ENUMS AND CONSTANTS
# ============================================================================

class SecurityLevel(str, Enum):
    """Security classification levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertCategory(str, Enum):
    """Alert categorization following security standards."""
    AUTHENTICATION = "authentication"
    MALWARE = "malware"
    INTRUSION = "intrusion"
    POLICY_VIOLATION = "policy_violation"
    VULNERABILITY = "vulnerability"
    DATA_BREACH = "data_breach"
    COMPLIANCE = "compliance"
    SYSTEM_ERROR = "system_error"
    OTHER = "other"


class AgentStatus(str, Enum):
    """Wazuh agent status enumeration."""
    ACTIVE = "active"
    DISCONNECTED = "disconnected"
    PENDING = "pending"
    NEVER_CONNECTED = "never_connected"


class ThreatLevel(str, Enum):
    """Threat assessment levels."""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST = "nist"
    ISO27001 = "iso27001"
    SOX = "sox"
    FISMA = "fisma"


class AnalysisType(str, Enum):
    """Types of security analysis."""
    THREAT_HUNTING = "threat_hunting"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE_CHECK = "compliance_check"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"


# ============================================================================
# FASTMCP TOOL REQUEST/RESPONSE MODELS
# ============================================================================

class WazuhAlertRequest(BaseModel):
    """Request model for Wazuh alert retrieval with comprehensive validation."""
    
    limit: StrictInt = Field(
        default=100,
        ge=1,
        le=10000,
        description="Maximum number of alerts to retrieve"
    )
    level: Optional[StrictInt] = Field(
        default=None,
        ge=1,
        le=15,
        description="Minimum alert level (1-15)"
    )
    time_range: Optional[StrictInt] = Field(
        default=3600,
        ge=300,
        le=86400,
        description="Time range in seconds"
    )
    agent_id: Optional[StrictStr] = Field(
        default=None,
        description="Filter alerts by specific agent ID"
    )
    rule_id: Optional[StrictStr] = Field(
        default=None,
        description="Filter by specific rule ID"
    )
    category: Optional[AlertCategory] = Field(
        default=None,
        description="Filter by alert category"
    )
    severity: Optional[SecurityLevel] = Field(
        default=None,
        description="Filter by security level"
    )
    include_full_log: StrictBool = Field(
        default=True,
        description="Include full log data in response"
    )
    
    @validator('agent_id', 'rule_id')
    def validate_ids(cls, v):
        """Validate ID formats."""
        if v is None:
            return v
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('IDs must contain only alphanumeric characters, hyphens, and underscores')
        return v


class WazuhAlert(BaseModel):
    """Enhanced Wazuh alert model with enriched data."""
    
    id: StrictStr = Field(description="Unique alert identifier")
    timestamp: datetime = Field(description="Alert timestamp")
    agent: Optional[Dict[str, Any]] = Field(default=None, description="Agent information")
    rule: Dict[str, Any] = Field(description="Rule information")
    location: Optional[StrictStr] = Field(default=None, description="Alert location")
    full_log: Optional[StrictStr] = Field(default=None, description="Full log entry")
    
    # Enriched fields
    risk_score: StrictInt = Field(ge=0, le=100, description="Calculated risk score")
    category: AlertCategory = Field(description="Alert category")
    severity: SecurityLevel = Field(description="Security severity level")
    threat_level: ThreatLevel = Field(description="Threat assessment")
    
    # Analysis fields
    mitre_attack: Optional[Dict[str, Any]] = Field(default=None, description="MITRE ATT&CK mapping")
    indicators: List[Dict[str, Any]] = Field(default_factory=list, description="Threat indicators")
    recommendations: List[StrictStr] = Field(default_factory=list, description="Security recommendations")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + 'Z'
        }


class AgentHealthRequest(BaseModel):
    """Request model for agent health checks."""
    
    agent_id: Optional[StrictStr] = Field(
        default=None,
        description="Specific agent ID to check"
    )
    include_disconnected: StrictBool = Field(
        default=False,
        description="Include disconnected agents"
    )
    include_metrics: StrictBool = Field(
        default=True,
        description="Include performance metrics"
    )
    health_threshold: StrictInt = Field(
        default=70,
        ge=0,
        le=100,
        description="Health score threshold"
    )


class AgentHealth(BaseModel):
    """Comprehensive agent health information."""
    
    id: StrictStr = Field(description="Agent ID")
    name: StrictStr = Field(description="Agent name")
    ip: Optional[StrictStr] = Field(default=None, description="Agent IP address")
    status: AgentStatus = Field(description="Agent status")
    last_keep_alive: Optional[datetime] = Field(default=None, description="Last keep alive")
    os: Optional[Dict[str, Any]] = Field(default=None, description="Operating system info")
    version: Optional[StrictStr] = Field(default=None, description="Agent version")
    
    # Health metrics
    health_score: StrictInt = Field(ge=0, le=100, description="Overall health score")
    uptime: Optional[StrictInt] = Field(default=None, description="Uptime in seconds")
    cpu_usage: Optional[float] = Field(default=None, ge=0, le=100, description="CPU usage percentage")
    memory_usage: Optional[float] = Field(default=None, ge=0, le=100, description="Memory usage percentage")
    
    # Issues and recommendations
    issues: List[StrictStr] = Field(default_factory=list, description="Identified issues")
    recommendations: List[StrictStr] = Field(default_factory=list, description="Health recommendations")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + 'Z' if v else None
        }


class ThreatAnalysisRequest(BaseModel):
    """Request model for AI-powered threat analysis."""
    
    time_range: StrictInt = Field(
        default=3600,
        ge=300,
        le=86400,
        description="Analysis time range in seconds"
    )
    min_severity: StrictInt = Field(
        default=5,
        ge=1,
        le=15,
        description="Minimum threat severity level"
    )
    analysis_type: AnalysisType = Field(
        default=AnalysisType.THREAT_HUNTING,
        description="Type of security analysis to perform"
    )
    include_mitre: StrictBool = Field(
        default=True,
        description="Include MITRE ATT&CK mapping"
    )
    include_iocs: StrictBool = Field(
        default=True,
        description="Include Indicators of Compromise"
    )
    focus_areas: List[AlertCategory] = Field(
        default_factory=list,
        description="Specific focus areas for analysis"
    )


class ThreatAnalysis(BaseModel):
    """Comprehensive threat analysis results."""
    
    analysis_id: StrictStr = Field(description="Unique analysis identifier")
    timestamp: datetime = Field(description="Analysis timestamp")
    time_range: StrictInt = Field(description="Analysis time range in seconds")
    
    # Summary statistics
    total_alerts_analyzed: StrictInt = Field(description="Total alerts analyzed")
    high_risk_alerts: StrictInt = Field(description="High risk alerts found")
    critical_threats: StrictInt = Field(description="Critical threats identified")
    
    # Threat intelligence
    threat_summary: Dict[str, Any] = Field(description="Threat pattern summary")
    top_threats: List[Dict[str, Any]] = Field(description="Top identified threats")
    attack_vectors: List[Dict[str, Any]] = Field(description="Attack vectors identified")
    
    # Asset analysis
    affected_assets: Dict[str, Any] = Field(description="Affected asset analysis")
    critical_assets: List[Dict[str, Any]] = Field(description="Critical assets at risk")
    
    # Timeline and patterns
    attack_timeline: List[Dict[str, Any]] = Field(description="Chronological attack timeline")
    behavioral_patterns: List[Dict[str, Any]] = Field(description="Behavioral pattern analysis")
    
    # Intelligence and recommendations
    mitre_mapping: Optional[Dict[str, Any]] = Field(default=None, description="MITRE ATT&CK mapping")
    iocs: List[Dict[str, Any]] = Field(default_factory=list, description="Indicators of Compromise")
    recommendations: List[Dict[str, Any]] = Field(description="Actionable security recommendations")
    
    # Confidence and metadata
    confidence_score: float = Field(ge=0, le=1, description="Analysis confidence score")
    analyst_notes: Optional[StrictStr] = Field(default=None, description="Additional analyst notes")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + 'Z'
        }


# ============================================================================
# FASTMCP ELICITATION MODELS
# ============================================================================

class SecurityConfirmation(BaseModel):
    """Model for security action confirmations."""
    
    action: StrictStr = Field(description="Action to confirm")
    risk_level: SecurityLevel = Field(description="Risk level of action")
    confirmation: StrictBool = Field(description="User confirmation")
    reason: Optional[StrictStr] = Field(default=None, description="Reason for decision")


class IncidentDetails(BaseModel):
    """Model for incident response details."""
    
    incident_type: AlertCategory = Field(description="Type of security incident")
    severity: SecurityLevel = Field(description="Incident severity")
    affected_systems: List[StrictStr] = Field(description="List of affected systems")
    description: StrictStr = Field(description="Incident description")
    
    # Response details
    immediate_actions: List[StrictStr] = Field(default_factory=list, description="Immediate response actions")
    investigation_notes: Optional[StrictStr] = Field(default=None, description="Investigation notes")
    containment_status: Optional[StrictStr] = Field(default=None, description="Containment status")


class ComplianceAssessment(BaseModel):
    """Model for compliance assessment requests."""
    
    framework: ComplianceFramework = Field(description="Compliance framework to assess")
    scope: List[StrictStr] = Field(description="Assessment scope")
    assessment_period: StrictInt = Field(
        default=86400,
        ge=3600,
        le=2592000,
        description="Assessment period in seconds"
    )
    include_remediation: StrictBool = Field(
        default=True,
        description="Include remediation recommendations"
    )


# ============================================================================
# FASTMCP RESOURCE MODELS
# ============================================================================

class SecurityDashboard(BaseModel):
    """Real-time security dashboard data."""
    
    timestamp: datetime = Field(description="Dashboard timestamp")
    
    # Alert statistics
    total_alerts_24h: StrictInt = Field(description="Total alerts in last 24 hours")
    critical_alerts_24h: StrictInt = Field(description="Critical alerts in last 24 hours")
    new_threats_24h: StrictInt = Field(description="New threats in last 24 hours")
    
    # Agent statistics
    total_agents: StrictInt = Field(description="Total number of agents")
    active_agents: StrictInt = Field(description="Number of active agents")
    disconnected_agents: StrictInt = Field(description="Number of disconnected agents")
    
    # Top threats
    top_threat_categories: List[Dict[str, Union[str, int]]] = Field(description="Top threat categories")
    most_targeted_assets: List[Dict[str, Any]] = Field(description="Most targeted assets")
    
    # Security posture
    overall_security_score: StrictInt = Field(ge=0, le=100, description="Overall security posture score")
    risk_level: SecurityLevel = Field(description="Current risk level")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + 'Z'
        }


class ClusterStatus(BaseModel):
    """Wazuh cluster status information."""
    
    cluster_name: StrictStr = Field(description="Cluster name")
    status: StrictStr = Field(description="Cluster status")
    nodes: List[Dict[str, Any]] = Field(description="Cluster nodes")
    
    # Health metrics
    total_nodes: StrictInt = Field(description="Total number of nodes")
    active_nodes: StrictInt = Field(description="Number of active nodes")
    master_node: Optional[StrictStr] = Field(default=None, description="Master node identifier")
    
    # Performance metrics
    sync_status: Optional[StrictStr] = Field(default=None, description="Synchronization status")
    last_sync: Optional[datetime] = Field(default=None, description="Last synchronization time")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + 'Z' if v else None
        }


# ============================================================================
# FASTMCP CONTEXT AND STATE MODELS
# ============================================================================

class SessionState(BaseModel):
    """Session state management for FastMCP context."""
    
    session_id: StrictStr = Field(description="Unique session identifier")
    created_at: datetime = Field(description="Session creation time")
    last_activity: datetime = Field(description="Last activity timestamp")
    
    # User context
    user_id: Optional[StrictStr] = Field(default=None, description="User identifier")
    permissions: Set[StrictStr] = Field(default_factory=set, description="User permissions")
    
    # Analysis context
    active_analysis: Optional[StrictStr] = Field(default=None, description="Active analysis ID")
    cached_results: Dict[str, Any] = Field(default_factory=dict, description="Cached analysis results")
    
    # Preferences
    alert_filters: Dict[str, Any] = Field(default_factory=dict, description="User alert filters")
    dashboard_config: Dict[str, Any] = Field(default_factory=dict, description="Dashboard configuration")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + 'Z'
        }


class ProgressUpdate(BaseModel):
    """Progress update model for long-running operations."""
    
    operation_id: StrictStr = Field(description="Operation identifier")
    operation_type: StrictStr = Field(description="Type of operation")
    current_step: StrictStr = Field(description="Current operation step")
    
    # Progress metrics
    progress_percentage: float = Field(ge=0, le=100, description="Progress percentage")
    completed_items: StrictInt = Field(description="Number of completed items")
    total_items: StrictInt = Field(description="Total number of items")
    
    # Status information
    status: Literal["running", "paused", "completed", "failed"] = Field(description="Operation status")
    estimated_completion: Optional[datetime] = Field(default=None, description="Estimated completion time")
    
    # Optional details
    current_item: Optional[StrictStr] = Field(default=None, description="Currently processing item")
    error_message: Optional[StrictStr] = Field(default=None, description="Error message if failed")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + 'Z' if v else None
        }


# ============================================================================
# RESPONSE WRAPPER MODELS
# ============================================================================

class FastMCPResponse(BaseModel):
    """Standard FastMCP response wrapper."""
    
    success: StrictBool = Field(description="Operation success status")
    timestamp: datetime = Field(description="Response timestamp")
    request_id: Optional[StrictStr] = Field(default=None, description="Request identifier")
    
    # Response data
    data: Optional[Any] = Field(default=None, description="Response data")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Response metadata")
    
    # Error information
    error: Optional[Dict[str, Any]] = Field(default=None, description="Error details")
    warnings: List[StrictStr] = Field(default_factory=list, description="Warning messages")
    
    # Performance metrics
    execution_time_ms: Optional[float] = Field(default=None, description="Execution time in milliseconds")
    cache_hit: StrictBool = Field(default=False, description="Whether response was cached")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + 'Z'
        }