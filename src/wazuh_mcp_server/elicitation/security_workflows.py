"""
FastMCP elicitation system for interactive security workflows.
Implements user interaction patterns for advanced security operations.
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional, Union, Literal
from enum import Enum
from dataclasses import dataclass
import uuid
from datetime import datetime

from fastmcp import Context
from ..models.fastmcp_models import (
    SecurityConfirmation, IncidentDetails, ComplianceAssessment,
    SecurityLevel, AlertCategory, ComplianceFramework, ThreatLevel
)
from ..utils.fastmcp_exceptions import ElicitationError, ValidationError


class ElicitationAction(str, Enum):
    """FastMCP elicitation response actions."""
    ACCEPT = "accept"
    DECLINE = "decline"
    CANCEL = "cancel"


class WorkflowStage(str, Enum):
    """Security workflow stages."""
    DETECTION = "detection"
    ANALYSIS = "analysis"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"


@dataclass
class ElicitationResult:
    """Result of an elicitation operation."""
    action: ElicitationAction
    data: Optional[Any] = None
    message: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class SecurityElicitation:
    """
    Advanced security workflow elicitation system using FastMCP context.
    
    Provides interactive capabilities for:
    - Incident response workflows
    - Threat hunting confirmation
    - Security action approvals
    - Compliance assessments
    - Risk analysis interactions
    """
    
    def __init__(self, context: Context):
        """Initialize with FastMCP context."""
        self.context = context
        self.session_id = str(uuid.uuid4())
        self.workflow_history: List[Dict[str, Any]] = []
    
    async def confirm_security_action(
        self,
        action_description: str,
        risk_level: SecurityLevel,
        affected_systems: List[str],
        impact_description: str,
        auto_approve_low_risk: bool = True
    ) -> ElicitationResult:
        """
        Request confirmation for security actions with risk assessment.
        
        Args:
            action_description: Description of the security action
            risk_level: Risk level of the action
            affected_systems: List of systems that will be affected
            impact_description: Description of potential impact
            auto_approve_low_risk: Auto-approve low risk actions
        
        Returns:
            ElicitationResult with user confirmation
        """
        try:
            # Auto-approve low risk actions if configured
            if auto_approve_low_risk and risk_level == SecurityLevel.LOW:
                await self.context.info(f"Auto-approving low risk action: {action_description}")
                return ElicitationResult(
                    action=ElicitationAction.ACCEPT,
                    data={"auto_approved": True, "reason": "Low risk auto-approval"},
                    message="Action auto-approved due to low risk level"
                )
            
            # Build detailed confirmation message
            confirmation_message = f"""
🔐 SECURITY ACTION CONFIRMATION REQUIRED

Action: {action_description}
Risk Level: {risk_level.value.upper()}
Affected Systems: {', '.join(affected_systems)}
Potential Impact: {impact_description}

⚠️  This action requires your explicit confirmation before proceeding.
Do you want to proceed with this security action?
"""
            
            # Use FastMCP elicitation
            result = await self.context.elicit(
                message=confirmation_message,
                response_type=SecurityConfirmation
            )
            
            # Log the elicitation attempt
            self._log_workflow_step(
                "security_action_confirmation",
                {
                    "action": action_description,
                    "risk_level": risk_level.value,
                    "affected_systems": affected_systems,
                    "user_response": result.action
                }
            )
            
            if result.action == "accept":
                await self.context.info(f"Security action approved: {action_description}")
                confirmation_data = result.data if hasattr(result, 'data') else {}
                return ElicitationResult(
                    action=ElicitationAction.ACCEPT,
                    data=confirmation_data,
                    message="Security action approved by user"
                )
            elif result.action == "decline":
                await self.context.warning(f"Security action declined: {action_description}")
                return ElicitationResult(
                    action=ElicitationAction.DECLINE,
                    message="Security action declined by user"
                )
            else:
                await self.context.info(f"Security action cancelled: {action_description}")
                return ElicitationResult(
                    action=ElicitationAction.CANCEL,
                    message="Security action cancelled by user"
                )
                
        except Exception as e:
            raise ElicitationError(
                message=f"Failed to elicit security action confirmation: {str(e)}",
                elicitation_type="security_action_confirmation",
                context=self.context
            )
    
    async def collect_incident_details(
        self,
        initial_alert: Dict[str, Any],
        suggested_severity: SecurityLevel
    ) -> ElicitationResult:
        """
        Collect detailed incident information through interactive workflow.
        
        Args:
            initial_alert: The triggering alert information
            suggested_severity: AI-suggested severity level
        
        Returns:
            ElicitationResult with incident details
        """
        try:
            incident_message = f"""
🚨 SECURITY INCIDENT DETECTED

Initial Alert: {initial_alert.get('rule', {}).get('description', 'Unknown')}
Affected Agent: {initial_alert.get('agent', 'Unknown')}
Suggested Severity: {suggested_severity.value.upper()}
Timestamp: {initial_alert.get('timestamp', 'Unknown')}

Please provide detailed incident information to initiate proper response procedures.
"""
            
            result = await self.context.elicit(
                message=incident_message,
                response_type=IncidentDetails
            )
            
            self._log_workflow_step(
                "incident_details_collection",
                {
                    "initial_alert_id": initial_alert.get('id'),
                    "suggested_severity": suggested_severity.value,
                    "user_response": result.action
                }
            )
            
            if result.action == "accept":
                incident_data = result.data if hasattr(result, 'data') else {}
                await self.context.info("Incident details collected successfully")
                
                # Validate incident details
                if isinstance(incident_data, dict):
                    return ElicitationResult(
                        action=ElicitationAction.ACCEPT,
                        data=incident_data,
                        message="Incident details collected and validated"
                    )
                else:
                    raise ValidationError(
                        message="Invalid incident details format",
                        details={"received_data": incident_data}
                    )
                    
            elif result.action == "decline":
                await self.context.warning("Incident details collection declined")
                return ElicitationResult(
                    action=ElicitationAction.DECLINE,
                    message="User declined to provide incident details"
                )
            else:
                await self.context.info("Incident details collection cancelled")
                return ElicitationResult(
                    action=ElicitationAction.CANCEL,
                    message="Incident details collection cancelled"
                )
                
        except Exception as e:
            raise ElicitationError(
                message=f"Failed to collect incident details: {str(e)}",
                elicitation_type="incident_details_collection",
                context=self.context
            )
    
    async def request_threat_hunting_parameters(
        self,
        threat_indicators: List[str],
        recommended_timeframe: int,
        confidence_level: float
    ) -> ElicitationResult:
        """
        Request parameters for advanced threat hunting operations.
        
        Args:
            threat_indicators: List of identified threat indicators
            recommended_timeframe: Recommended hunting timeframe in hours
            confidence_level: AI confidence in threat assessment (0-1)
        
        Returns:
            ElicitationResult with hunting parameters
        """
        try:
            hunting_message = f"""
🎯 THREAT HUNTING OPERATION

Detected Indicators:
{chr(10).join(f"• {indicator}" for indicator in threat_indicators[:5])}
{'• ... and more' if len(threat_indicators) > 5 else ''}

Recommended Timeframe: {recommended_timeframe} hours
Confidence Level: {confidence_level:.2%}

Please specify hunting parameters for comprehensive threat analysis.
"""
            
            # Define hunting parameters schema
            hunting_params_schema = {
                "timeframe_hours": {"type": "integer", "minimum": 1, "maximum": 168},
                "scope": {"type": "string", "enum": ["targeted", "broad", "comprehensive"]},
                "priority": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                "include_historical": {"type": "boolean"},
                "focus_areas": {
                    "type": "array",
                    "items": {"type": "string"},
                    "enum": ["authentication", "network", "files", "processes", "registry"]
                }
            }
            
            result = await self.context.elicit(
                message=hunting_message,
                response_type=dict  # Use dict with schema validation
            )
            
            self._log_workflow_step(
                "threat_hunting_parameters",
                {
                    "threat_indicators_count": len(threat_indicators),
                    "confidence_level": confidence_level,
                    "user_response": result.action
                }
            )
            
            if result.action == "accept":
                hunting_data = result.data if hasattr(result, 'data') else {}
                await self.context.info("Threat hunting parameters collected")
                
                return ElicitationResult(
                    action=ElicitationAction.ACCEPT,
                    data=hunting_data,
                    message="Threat hunting parameters configured"
                )
            else:
                return ElicitationResult(
                    action=ElicitationAction(result.action),
                    message=f"Threat hunting parameters {result.action}"
                )
                
        except Exception as e:
            raise ElicitationError(
                message=f"Failed to collect threat hunting parameters: {str(e)}",
                elicitation_type="threat_hunting_parameters",
                context=self.context
            )
    
    async def request_compliance_assessment_scope(
        self,
        framework: ComplianceFramework,
        available_controls: List[str],
        last_assessment_date: Optional[datetime] = None
    ) -> ElicitationResult:
        """
        Request scope for compliance assessment operations.
        
        Args:
            framework: Compliance framework to assess
            available_controls: List of available security controls
            last_assessment_date: Date of last assessment
        
        Returns:
            ElicitationResult with assessment scope
        """
        try:
            last_assessment_info = ""
            if last_assessment_date:
                days_ago = (datetime.utcnow() - last_assessment_date).days
                last_assessment_info = f"Last Assessment: {days_ago} days ago"
            
            compliance_message = f"""
📋 COMPLIANCE ASSESSMENT CONFIGURATION

Framework: {framework.value.upper()}
Available Controls: {len(available_controls)} controls
{last_assessment_info}

Please configure the scope for compliance assessment.
"""
            
            result = await self.context.elicit(
                message=compliance_message,
                response_type=ComplianceAssessment
            )
            
            self._log_workflow_step(
                "compliance_assessment_scope",
                {
                    "framework": framework.value,
                    "available_controls_count": len(available_controls),
                    "user_response": result.action
                }
            )
            
            if result.action == "accept":
                assessment_data = result.data if hasattr(result, 'data') else {}
                await self.context.info(f"Compliance assessment scope configured for {framework.value}")
                
                return ElicitationResult(
                    action=ElicitationAction.ACCEPT,
                    data=assessment_data,
                    message="Compliance assessment scope configured"
                )
            else:
                return ElicitationResult(
                    action=ElicitationAction(result.action),
                    message=f"Compliance assessment {result.action}"
                )
                
        except Exception as e:
            raise ElicitationError(
                message=f"Failed to configure compliance assessment: {str(e)}",
                elicitation_type="compliance_assessment_scope",
                context=self.context
            )
    
    async def confirm_automated_response(
        self,
        response_type: str,
        threat_level: ThreatLevel,
        affected_assets: List[str],
        response_actions: List[str]
    ) -> ElicitationResult:
        """
        Confirm automated security response actions.
        
        Args:
            response_type: Type of automated response
            threat_level: Assessed threat level
            affected_assets: List of affected assets
            response_actions: List of proposed response actions
        
        Returns:
            ElicitationResult with response confirmation
        """
        try:
            response_message = f"""
🤖 AUTOMATED SECURITY RESPONSE

Response Type: {response_type}
Threat Level: {threat_level.value.upper()}
Affected Assets: {len(affected_assets)} asset(s)

Proposed Actions:
{chr(10).join(f"• {action}" for action in response_actions)}

⚠️  These actions will be executed automatically if approved.
Do you approve this automated response?
"""
            
            result = await self.context.elicit(
                message=response_message,
                response_type=bool  # Simple boolean confirmation
            )
            
            self._log_workflow_step(
                "automated_response_confirmation",
                {
                    "response_type": response_type,
                    "threat_level": threat_level.value,
                    "actions_count": len(response_actions),
                    "user_response": result.action
                }
            )
            
            if result.action == "accept":
                confirmed = result.data if hasattr(result, 'data') else True
                if confirmed:
                    await self.context.info("Automated response approved")
                    return ElicitationResult(
                        action=ElicitationAction.ACCEPT,
                        data={"approved": True, "actions": response_actions},
                        message="Automated response approved"
                    )
                else:
                    await self.context.warning("Automated response denied")
                    return ElicitationResult(
                        action=ElicitationAction.DECLINE,
                        message="Automated response denied"
                    )
            else:
                return ElicitationResult(
                    action=ElicitationAction(result.action),
                    message=f"Automated response {result.action}"
                )
                
        except Exception as e:
            raise ElicitationError(
                message=f"Failed to confirm automated response: {str(e)}",
                elicitation_type="automated_response_confirmation",
                context=self.context
            )
    
    def _log_workflow_step(
        self,
        step_type: str,
        step_data: Dict[str, Any]
    ) -> None:
        """Log workflow step for audit and analysis."""
        workflow_entry = {
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "session_id": self.session_id,
            "step_type": step_type,
            "step_data": step_data
        }
        
        self.workflow_history.append(workflow_entry)
    
    def get_workflow_summary(self) -> Dict[str, Any]:
        """Get summary of workflow interactions."""
        return {
            "session_id": self.session_id,
            "total_interactions": len(self.workflow_history),
            "workflow_history": self.workflow_history,
            "session_start": self.workflow_history[0]["timestamp"] if self.workflow_history else None,
            "last_interaction": self.workflow_history[-1]["timestamp"] if self.workflow_history else None
        }


# ============================================================================
# WORKFLOW TEMPLATES
# ============================================================================

class IncidentResponseWorkflow:
    """Template for structured incident response using elicitation."""
    
    def __init__(self, elicitation: SecurityElicitation):
        self.elicitation = elicitation
        self.workflow_stages: List[WorkflowStage] = []
        self.current_stage = WorkflowStage.DETECTION
    
    async def execute_full_workflow(
        self,
        initial_alert: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute complete incident response workflow."""
        workflow_results = {
            "workflow_id": str(uuid.uuid4()),
            "initial_alert": initial_alert,
            "stages": {},
            "timeline": []
        }
        
        try:
            # Stage 1: Detection and Analysis
            incident_details = await self.elicitation.collect_incident_details(
                initial_alert=initial_alert,
                suggested_severity=SecurityLevel.HIGH
            )
            
            if incident_details.action != ElicitationAction.ACCEPT:
                return {"error": "Incident workflow cancelled", "reason": incident_details.message}
            
            workflow_results["stages"]["analysis"] = incident_details.data
            
            # Stage 2: Containment Confirmation
            containment_result = await self.elicitation.confirm_security_action(
                action_description="Isolate affected systems and prevent threat spread",
                risk_level=SecurityLevel.MEDIUM,
                affected_systems=incident_details.data.get("affected_systems", []),
                impact_description="Systems will be temporarily isolated from network"
            )
            
            workflow_results["stages"]["containment"] = {
                "approved": containment_result.action == ElicitationAction.ACCEPT,
                "details": containment_result.data
            }
            
            # Stage 3: Automated Response (if applicable)
            if containment_result.action == ElicitationAction.ACCEPT:
                response_result = await self.elicitation.confirm_automated_response(
                    response_type="Network Isolation",
                    threat_level=ThreatLevel.MALICIOUS,
                    affected_assets=incident_details.data.get("affected_systems", []),
                    response_actions=["Block IP addresses", "Quarantine files", "Reset passwords"]
                )
                
                workflow_results["stages"]["response"] = {
                    "approved": response_result.action == ElicitationAction.ACCEPT,
                    "actions": response_result.data
                }
            
            return workflow_results
            
        except Exception as e:
            workflow_results["error"] = str(e)
            return workflow_results