"""
FastMCP LLM sampling integration for AI-powered security analysis.
Implements comprehensive AI capabilities using FastMCP context sampling.
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional, Union, Literal
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
import json
import asyncio
import re
from pathlib import Path

from fastmcp import Context
from ..models.fastmcp_models import ThreatAnalysis, SecurityLevel, AlertCategory
from ..utils.fastmcp_exceptions import FastMCPError, ErrorCategory, fastmcp_error_handler
from ..state.session_manager import get_session_manager, StateScope


class AnalysisType(str, Enum):
    """Types of AI security analysis."""
    THREAT_ASSESSMENT = "threat_assessment"
    INCIDENT_ANALYSIS = "incident_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    COMPLIANCE_REVIEW = "compliance_review"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    FORENSIC_ANALYSIS = "forensic_analysis"
    RISK_ASSESSMENT = "risk_assessment"
    PATTERN_DETECTION = "pattern_detection"


class LLMProvider(str, Enum):
    """Supported LLM providers via FastMCP."""
    CLAUDE = "claude"
    GPT = "gpt"
    CONTEXTUAL = "contextual"  # Uses FastMCP's context.sample()


@dataclass
class AnalysisPrompt:
    """Structured prompt for AI analysis."""
    template: str
    variables: Dict[str, Any]
    analysis_type: AnalysisType
    temperature: float = 0.3
    max_tokens: int = 2000
    system_prompt: Optional[str] = None
    
    def render(self) -> str:
        """Render the prompt template with variables."""
        try:
            return self.template.format(**self.variables)
        except KeyError as e:
            raise ValueError(f"Missing template variable: {e}")


class SecurityAIAnalyzer:
    """
    AI-powered security analysis using FastMCP LLM sampling.
    
    Features:
    - Threat intelligence analysis
    - Incident response recommendations
    - Behavioral pattern detection
    - Compliance assessment
    - Risk scoring and prioritization
    - Natural language security insights
    """
    
    def __init__(self, context: Context):
        """Initialize with FastMCP context for LLM sampling."""
        self.context = context
        self.session_manager = get_session_manager()
        
        # Analysis configuration
        self.default_temperature = 0.3
        self.default_max_tokens = 2000
        
        # Prompt templates
        self.prompt_templates = self._load_prompt_templates()
        
        # Analysis cache
        self.analysis_cache: Dict[str, Any] = {}
    
    def _load_prompt_templates(self) -> Dict[str, str]:
        """Load AI prompt templates for different analysis types."""
        return {
            AnalysisType.THREAT_ASSESSMENT: """
You are a cybersecurity expert analyzing security alerts. Based on the following alert data, provide a comprehensive threat assessment.

Alert Data:
{alert_data}

Context Information:
- Total alerts in timeframe: {total_alerts}
- Critical alerts: {critical_alerts}
- Affected systems: {affected_systems}
- Time range: {time_range}

Please provide:
1. Threat severity assessment (1-10 scale)
2. Attack vector analysis
3. Potential impact assessment
4. Recommended immediate actions
5. Long-term security recommendations
6. MITRE ATT&CK technique mapping
7. Confidence level of assessment

Format your response as a structured analysis with clear sections.
""",
            
            AnalysisType.INCIDENT_ANALYSIS: """
You are an incident response expert. Analyze the following security incident and provide detailed response guidance.

Incident Details:
{incident_data}

Alert Context:
{alert_context}

System Information:
{system_info}

Provide a comprehensive incident analysis including:
1. Incident classification and severity
2. Timeline reconstruction
3. Attack methodology assessment
4. Affected systems and data
5. Containment strategy
6. Eradication steps
7. Recovery procedures
8. Lessons learned and prevention measures

Focus on actionable recommendations for the incident response team.
""",
            
            AnalysisType.BEHAVIORAL_ANALYSIS: """
You are a security analyst specializing in behavioral analysis. Examine the following user/system behavior patterns and identify anomalies or threats.

Behavioral Data:
{behavior_data}

Baseline Patterns:
{baseline_patterns}

Time Context:
{time_context}

Perform behavioral analysis covering:
1. Deviation from normal patterns
2. Anomaly significance scoring
3. Potential threat indicators
4. User/entity risk assessment
5. Recommended monitoring actions
6. False positive likelihood
7. Behavioral trend analysis

Provide insights that help distinguish between legitimate and malicious behavior.
""",
            
            AnalysisType.COMPLIANCE_REVIEW: """
You are a compliance expert reviewing security controls and configurations. Assess the following data against security standards.

System Configuration:
{config_data}

Security Controls:
{security_controls}

Compliance Framework: {framework}

Audit Findings:
{audit_findings}

Provide comprehensive compliance analysis:
1. Control effectiveness assessment
2. Gap analysis against standards
3. Risk level of non-compliance
4. Remediation priorities
5. Implementation recommendations
6. Cost-benefit analysis
7. Timeline for compliance achievement

Focus on practical, implementable recommendations.
""",
            
            AnalysisType.VULNERABILITY_ANALYSIS: """
You are a vulnerability researcher analyzing security vulnerabilities. Assess the following vulnerability data and provide risk-based recommendations.

Vulnerability Data:
{vulnerability_data}

System Context:
{system_context}

Environment Information:
{environment_info}

Threat Landscape:
{threat_landscape}

Provide detailed vulnerability analysis:
1. Vulnerability risk scoring (CVSS-based)
2. Exploitability assessment
3. Business impact analysis
4. Prioritization matrix
5. Patching recommendations
6. Compensating controls
7. Threat actor likelihood

Prioritize based on actual risk to the organization.
""",
            
            AnalysisType.FORENSIC_ANALYSIS: """
You are a digital forensics expert examining security incident artifacts. Analyze the following evidence and reconstruct the attack timeline.

Evidence Data:
{evidence_data}

System Logs:
{system_logs}

Network Data:
{network_data}

File System Changes:
{file_changes}

Conduct forensic analysis including:
1. Attack timeline reconstruction
2. Attack vector identification
3. Attacker methodology analysis
4. Evidence correlation
5. Attribution indicators
6. Data exfiltration assessment
7. Persistence mechanism analysis

Provide findings that support incident response and legal requirements.
""",
            
            AnalysisType.RISK_ASSESSMENT: """
You are a risk management expert conducting security risk assessment. Evaluate the following security data and provide risk analysis.

Asset Information:
{asset_data}

Threat Intelligence:
{threat_intel}

Vulnerability Data:
{vulnerability_data}

Control Effectiveness:
{control_data}

Business Context:
{business_context}

Perform comprehensive risk assessment:
1. Asset value and criticality
2. Threat likelihood assessment
3. Vulnerability exposure analysis
4. Control effectiveness evaluation
5. Risk calculation (likelihood × impact)
6. Risk mitigation strategies
7. Residual risk assessment

Provide business-aligned risk recommendations.
""",
            
            AnalysisType.PATTERN_DETECTION: """
You are a pattern recognition expert analyzing security data for hidden patterns and trends. Examine the following data for significant patterns.

Security Data:
{security_data}

Historical Context:
{historical_data}

Correlation Data:
{correlation_data}

Time Series Information:
{time_series}

Identify and analyze patterns:
1. Anomalous pattern detection
2. Trend analysis and projection
3. Correlation identification
4. Cyclical pattern recognition
5. Pattern significance scoring
6. Predictive insights
7. Early warning indicators

Focus on patterns that indicate emerging threats or systemic issues.
"""
        }
    
    @fastmcp_error_handler("ai_threat_assessment")
    async def analyze_threat_intelligence(
        self,
        alert_data: List[Dict[str, Any]],
        context_data: Dict[str, Any],
        analysis_depth: Literal["basic", "detailed", "comprehensive"] = "detailed"
    ) -> Dict[str, Any]:
        """
        Perform AI-powered threat intelligence analysis.
        
        Args:
            alert_data: Security alert data
            context_data: Additional context information
            analysis_depth: Depth of analysis to perform
        
        Returns:
            Comprehensive threat analysis results
        """
        try:
            await self.context.info("Starting AI threat intelligence analysis")
            
            # Prepare analysis prompt
            prompt_variables = {
                "alert_data": json.dumps(alert_data[:10], indent=2),  # Limit for token efficiency
                "total_alerts": len(alert_data),
                "critical_alerts": len([a for a in alert_data if a.get("risk_score", 0) >= 80]),
                "affected_systems": len(set(a.get("agent", "") for a in alert_data if a.get("agent"))),
                "time_range": context_data.get("time_range", "unknown")
            }
            
            analysis_prompt = AnalysisPrompt(
                template=self.prompt_templates[AnalysisType.THREAT_ASSESSMENT],
                variables=prompt_variables,
                analysis_type=AnalysisType.THREAT_ASSESSMENT,
                temperature=0.2,  # Lower temperature for security analysis
                max_tokens=3000 if analysis_depth == "comprehensive" else 2000
            )
            
            # Cache key for this analysis
            cache_key = f"threat_analysis:{hash(str(alert_data[:5]))}"
            
            # Check cache first
            cached_result = await self.session_manager.get_state(
                key=cache_key,
                scope=StateScope.GLOBAL,
                context=self.context
            )
            
            if cached_result:
                await self.context.info("Retrieved threat analysis from cache")
                return cached_result
            
            # Perform AI analysis using FastMCP sampling
            await self.context.info("Requesting AI analysis via FastMCP sampling")
            
            ai_response = await self.context.sample(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a world-class cybersecurity expert with extensive experience in threat analysis, incident response, and security operations. Provide detailed, actionable security insights."
                    },
                    {
                        "role": "user",
                        "content": analysis_prompt.render()
                    }
                ],
                temperature=analysis_prompt.temperature,
                max_tokens=analysis_prompt.max_tokens
            )
            
            # Parse and structure the AI response
            structured_analysis = await self._parse_threat_analysis(ai_response, alert_data)
            
            # Cache the result
            await self.session_manager.set_state(
                key=cache_key,
                value=structured_analysis,
                scope=StateScope.GLOBAL,
                ttl=1800,  # Cache for 30 minutes
                context=self.context
            )
            
            await self.context.info("AI threat analysis completed successfully")
            return structured_analysis
            
        except Exception as e:
            raise FastMCPError(
                message=f"AI threat analysis failed: {str(e)}",
                category=ErrorCategory.TOOL_EXECUTION,
                context=self.context
            )
    
    @fastmcp_error_handler("ai_incident_analysis")
    async def analyze_incident(
        self,
        incident_data: Dict[str, Any],
        related_alerts: List[Dict[str, Any]],
        system_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform AI-powered incident analysis and response recommendations.
        
        Args:
            incident_data: Core incident information
            related_alerts: Related security alerts
            system_context: System and environment context
        
        Returns:
            Detailed incident analysis with response recommendations
        """
        try:
            await self.context.info("Starting AI incident analysis")
            
            prompt_variables = {
                "incident_data": json.dumps(incident_data, indent=2),
                "alert_context": json.dumps(related_alerts[:5], indent=2),
                "system_info": json.dumps(system_context, indent=2)
            }
            
            analysis_prompt = AnalysisPrompt(
                template=self.prompt_templates[AnalysisType.INCIDENT_ANALYSIS],
                variables=prompt_variables,
                analysis_type=AnalysisType.INCIDENT_ANALYSIS,
                temperature=0.1,  # Very low temperature for incident response
                max_tokens=3500
            )
            
            ai_response = await self.context.sample(
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert incident response analyst with 15+ years of experience handling complex security incidents. Provide structured, actionable incident response guidance."
                    },
                    {
                        "role": "user",
                        "content": analysis_prompt.render()
                    }
                ],
                temperature=analysis_prompt.temperature,
                max_tokens=analysis_prompt.max_tokens
            )
            
            # Structure the incident analysis response
            structured_response = await self._parse_incident_analysis(ai_response, incident_data)
            
            await self.context.info("AI incident analysis completed")
            return structured_response
            
        except Exception as e:
            raise FastMCPError(
                message=f"AI incident analysis failed: {str(e)}",
                category=ErrorCategory.TOOL_EXECUTION,
                context=self.context
            )
    
    @fastmcp_error_handler("ai_behavioral_analysis")
    async def analyze_behavioral_patterns(
        self,
        behavior_data: Dict[str, Any],
        baseline_data: Dict[str, Any],
        time_window: int = 86400
    ) -> Dict[str, Any]:
        """
        Perform AI-powered behavioral analysis for anomaly detection.
        
        Args:
            behavior_data: Current behavioral data
            baseline_data: Baseline behavior patterns
            time_window: Analysis time window in seconds
        
        Returns:
            Behavioral analysis with anomaly detection results
        """
        try:
            await self.context.info("Starting AI behavioral analysis")
            
            prompt_variables = {
                "behavior_data": json.dumps(behavior_data, indent=2),
                "baseline_patterns": json.dumps(baseline_data, indent=2),
                "time_context": f"{time_window} seconds ({time_window//3600} hours)"
            }
            
            analysis_prompt = AnalysisPrompt(
                template=self.prompt_templates[AnalysisType.BEHAVIORAL_ANALYSIS],
                variables=prompt_variables,
                analysis_type=AnalysisType.BEHAVIORAL_ANALYSIS,
                temperature=0.3,
                max_tokens=2500
            )
            
            ai_response = await self.context.sample(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a behavioral analysis expert specializing in detecting anomalous user and system behaviors that may indicate security threats. Focus on statistical significance and actionable insights."
                    },
                    {
                        "role": "user",
                        "content": analysis_prompt.render()
                    }
                ],
                temperature=analysis_prompt.temperature,
                max_tokens=analysis_prompt.max_tokens
            )
            
            structured_response = await self._parse_behavioral_analysis(ai_response, behavior_data)
            
            await self.context.info("AI behavioral analysis completed")
            return structured_response
            
        except Exception as e:
            raise FastMCPError(
                message=f"AI behavioral analysis failed: {str(e)}",
                category=ErrorCategory.TOOL_EXECUTION,
                context=self.context
            )
    
    @fastmcp_error_handler("ai_compliance_review")
    async def review_compliance(
        self,
        framework: str,
        configuration_data: Dict[str, Any],
        control_data: Dict[str, Any],
        audit_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Perform AI-powered compliance review and gap analysis.
        
        Args:
            framework: Compliance framework (e.g., PCI-DSS, HIPAA)
            configuration_data: System configuration data
            control_data: Security control information
            audit_findings: Previous audit findings
        
        Returns:
            Comprehensive compliance analysis
        """
        try:
            await self.context.info(f"Starting AI compliance review for {framework}")
            
            prompt_variables = {
                "framework": framework.upper(),
                "config_data": json.dumps(configuration_data, indent=2),
                "security_controls": json.dumps(control_data, indent=2),
                "audit_findings": json.dumps(audit_findings, indent=2)
            }
            
            analysis_prompt = AnalysisPrompt(
                template=self.prompt_templates[AnalysisType.COMPLIANCE_REVIEW],
                variables=prompt_variables,
                analysis_type=AnalysisType.COMPLIANCE_REVIEW,
                temperature=0.2,
                max_tokens=3000
            )
            
            ai_response = await self.context.sample(
                messages=[
                    {
                        "role": "system",
                        "content": f"You are a compliance expert with deep knowledge of {framework} and other security frameworks. Provide practical, implementable compliance recommendations."
                    },
                    {
                        "role": "user",
                        "content": analysis_prompt.render()
                    }
                ],
                temperature=analysis_prompt.temperature,
                max_tokens=analysis_prompt.max_tokens
            )
            
            structured_response = await self._parse_compliance_review(ai_response, framework)
            
            await self.context.info("AI compliance review completed")
            return structured_response
            
        except Exception as e:
            raise FastMCPError(
                message=f"AI compliance review failed: {str(e)}",
                category=ErrorCategory.TOOL_EXECUTION,
                context=self.context
            )
    
    async def _parse_threat_analysis(
        self,
        ai_response: str,
        original_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Parse and structure AI threat analysis response."""
        try:
            # Extract structured information from AI response
            analysis_id = f"threat_analysis_{datetime.utcnow().timestamp()}"
            
            # Basic parsing - in production, this would be more sophisticated
            lines = ai_response.split('\n')
            sections = {}
            current_section = None
            current_content = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Detect section headers
                if any(header in line.lower() for header in ['severity', 'attack vector', 'impact', 'recommendations', 'mitre', 'confidence']):
                    if current_section:
                        sections[current_section] = '\n'.join(current_content)
                    current_section = line
                    current_content = []
                else:
                    current_content.append(line)
            
            # Add final section
            if current_section:
                sections[current_section] = '\n'.join(current_content)
            
            # Extract threat level (simple regex-based extraction)
            threat_level_match = re.search(r'(\d+)/10|(\d+) out of 10|severity[:\s]*(\d+)', ai_response.lower())
            threat_level = 5  # default
            if threat_level_match:
                threat_level = int(threat_level_match.group(1) or threat_level_match.group(2) or threat_level_match.group(3))
            
            return {
                "analysis_id": analysis_id,
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "analysis_type": "threat_assessment",
                "threat_level": threat_level,
                "confidence_score": 0.85,  # Would be extracted from AI response
                "raw_analysis": ai_response,
                "structured_sections": sections,
                "alerts_analyzed": len(original_data),
                "key_findings": self._extract_key_findings(ai_response),
                "recommendations": self._extract_recommendations(ai_response),
                "mitre_techniques": self._extract_mitre_techniques(ai_response)
            }
            
        except Exception as e:
            await self.context.warning(f"Failed to parse threat analysis: {str(e)}")
            return {
                "analysis_id": f"threat_analysis_{datetime.utcnow().timestamp()}",
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "raw_analysis": ai_response,
                "parsing_error": str(e)
            }
    
    async def _parse_incident_analysis(
        self,
        ai_response: str,
        incident_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Parse AI incident analysis response."""
        return {
            "incident_id": incident_data.get("incident_id", f"incident_{datetime.utcnow().timestamp()}"),
            "analysis_timestamp": datetime.utcnow().isoformat() + 'Z',
            "severity_assessment": self._extract_severity(ai_response),
            "timeline": self._extract_timeline(ai_response),
            "containment_actions": self._extract_actions(ai_response, "containment"),
            "eradication_steps": self._extract_actions(ai_response, "eradication"),
            "recovery_procedures": self._extract_actions(ai_response, "recovery"),
            "lessons_learned": self._extract_lessons_learned(ai_response),
            "raw_analysis": ai_response
        }
    
    async def _parse_behavioral_analysis(
        self,
        ai_response: str,
        behavior_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Parse AI behavioral analysis response."""
        return {
            "analysis_id": f"behavioral_{datetime.utcnow().timestamp()}",
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "anomaly_score": self._extract_anomaly_score(ai_response),
            "detected_anomalies": self._extract_anomalies(ai_response),
            "risk_assessment": self._extract_risk_level(ai_response),
            "recommended_actions": self._extract_recommendations(ai_response),
            "false_positive_likelihood": self._extract_false_positive_likelihood(ai_response),
            "raw_analysis": ai_response
        }
    
    async def _parse_compliance_review(
        self,
        ai_response: str,
        framework: str
    ) -> Dict[str, Any]:
        """Parse AI compliance review response."""
        return {
            "review_id": f"compliance_{framework}_{datetime.utcnow().timestamp()}",
            "framework": framework,
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "overall_score": self._extract_compliance_score(ai_response),
            "compliance_gaps": self._extract_gaps(ai_response),
            "remediation_priorities": self._extract_priorities(ai_response),
            "implementation_timeline": self._extract_timeline(ai_response),
            "cost_estimates": self._extract_cost_estimates(ai_response),
            "raw_analysis": ai_response
        }
    
    # Helper methods for extracting information from AI responses
    def _extract_key_findings(self, text: str) -> List[str]:
        """Extract key findings from AI response."""
        # Simple implementation - would be more sophisticated in production
        findings = []
        lines = text.split('\n')
        for line in lines:
            if any(indicator in line.lower() for indicator in ['finding:', 'key:', 'important:', '•', '-']):
                findings.append(line.strip())
        return findings[:5]  # Top 5 findings
    
    def _extract_recommendations(self, text: str) -> List[str]:
        """Extract recommendations from AI response."""
        recommendations = []
        lines = text.split('\n')
        in_recommendations = False
        
        for line in lines:
            if 'recommendation' in line.lower():
                in_recommendations = True
                continue
            
            if in_recommendations and (line.strip().startswith(('1.', '2.', '3.', '-', '•')) or 
                                     any(action in line.lower() for action in ['should', 'must', 'recommend', 'implement'])):
                recommendations.append(line.strip())
                
        return recommendations[:7]  # Top 7 recommendations
    
    def _extract_mitre_techniques(self, text: str) -> List[str]:
        """Extract MITRE ATT&CK techniques from AI response."""
        # Look for MITRE technique patterns (T1234)
        techniques = re.findall(r'T\d{4}(?:\.\d{3})?', text)
        return list(set(techniques))  # Remove duplicates
    
    def _extract_severity(self, text: str) -> str:
        """Extract severity level from AI response."""
        severity_keywords = {
            'critical': ['critical', 'severe', 'urgent'],
            'high': ['high', 'significant', 'major'],
            'medium': ['medium', 'moderate'],
            'low': ['low', 'minor', 'minimal']
        }
        
        text_lower = text.lower()
        for severity, keywords in severity_keywords.items():
            if any(keyword in text_lower for keyword in keywords):
                return severity
        
        return 'medium'  # default
    
    def _extract_timeline(self, text: str) -> List[Dict[str, str]]:
        """Extract timeline information from AI response."""
        # Simple implementation - would be more sophisticated
        timeline = []
        lines = text.split('\n')
        
        for line in lines:
            if any(time_indicator in line.lower() for time_indicator in ['timeline', 'sequence', 'step', 'phase']):
                timeline.append({
                    "step": line.strip(),
                    "timestamp": "estimated"
                })
                
        return timeline[:10]  # Limit to 10 timeline items
    
    def _extract_actions(self, text: str, action_type: str) -> List[str]:
        """Extract specific action types from AI response."""
        actions = []
        lines = text.split('\n')
        in_section = False
        
        for line in lines:
            if action_type.lower() in line.lower():
                in_section = True
                continue
                
            if in_section and (line.strip().startswith(('1.', '2.', '3.', '-', '•')) or
                              any(action in line.lower() for action in ['isolate', 'block', 'disable', 'remove', 'update'])):
                actions.append(line.strip())
                
        return actions[:5]  # Top 5 actions
    
    def _extract_anomaly_score(self, text: str) -> float:
        """Extract anomaly score from behavioral analysis."""
        score_match = re.search(r'score[:\s]*(\d+(?:\.\d+)?)', text.lower())
        if score_match:
            return float(score_match.group(1))
        return 0.5  # default neutral score
    
    def _extract_anomalies(self, text: str) -> List[Dict[str, Any]]:
        """Extract detected anomalies from behavioral analysis."""
        anomalies = []
        lines = text.split('\n')
        
        for line in lines:
            if any(indicator in line.lower() for indicator in ['anomaly', 'unusual', 'deviation', 'suspicious']):
                anomalies.append({
                    "description": line.strip(),
                    "severity": self._extract_severity(line),
                    "confidence": 0.8  # default confidence
                })
                
        return anomalies[:5]  # Top 5 anomalies
    
    def _extract_risk_level(self, text: str) -> str:
        """Extract risk level from analysis."""
        return self._extract_severity(text)  # Same logic as severity
    
    def _extract_false_positive_likelihood(self, text: str) -> float:
        """Extract false positive likelihood."""
        fp_match = re.search(r'false positive.*?(\d+(?:\.\d+)?)', text.lower())
        if fp_match:
            return float(fp_match.group(1))
        return 0.3  # default moderate likelihood
    
    def _extract_compliance_score(self, text: str) -> int:
        """Extract compliance score from review."""
        score_match = re.search(r'score[:\s]*(\d+)', text.lower())
        if score_match:
            return int(score_match.group(1))
        return 75  # default score
    
    def _extract_gaps(self, text: str) -> List[str]:
        """Extract compliance gaps."""
        gaps = []
        lines = text.split('\n')
        
        for line in lines:
            if any(indicator in line.lower() for indicator in ['gap', 'missing', 'non-compliant', 'deficiency']):
                gaps.append(line.strip())
                
        return gaps[:5]  # Top 5 gaps
    
    def _extract_priorities(self, text: str) -> List[Dict[str, str]]:
        """Extract remediation priorities."""
        priorities = []
        lines = text.split('\n')
        
        for i, line in enumerate(lines):
            if any(indicator in line.lower() for indicator in ['priority', 'urgent', 'critical', 'high']):
                priorities.append({
                    "priority": f"P{i+1}",
                    "description": line.strip(),
                    "urgency": self._extract_severity(line)
                })
                
        return priorities[:5]  # Top 5 priorities
    
    def _extract_cost_estimates(self, text: str) -> Dict[str, str]:
        """Extract cost estimates from compliance review."""
        # Simple cost extraction - would be more sophisticated
        cost_keywords = ['cost', 'budget', 'expense', 'investment']
        estimates = {}
        
        lines = text.split('\n')
        for line in lines:
            if any(keyword in line.lower() for keyword in cost_keywords):
                estimates["estimated_cost"] = "See detailed analysis"
                break
                
        return estimates
    
    def _extract_lessons_learned(self, text: str) -> List[str]:
        """Extract lessons learned from incident analysis."""
        lessons = []
        lines = text.split('\n')
        in_lessons = False
        
        for line in lines:
            if 'lesson' in line.lower():
                in_lessons = True
                continue
                
            if in_lessons and (line.strip().startswith(('1.', '2.', '3.', '-', '•')) or
                              any(lesson in line.lower() for lesson in ['learn', 'improve', 'prevent', 'ensure'])):
                lessons.append(line.strip())
                
        return lessons[:5]  # Top 5 lessons