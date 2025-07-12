"""Advanced security analysis algorithms for threat detection and risk assessment."""

import re
import statistics
import math
from functools import lru_cache
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import Enum
import sys
import os

# Clean import within the package
from wazuh_mcp_server.utils.logging import get_logger

logger = get_logger(__name__)


class RiskLevel(Enum):
    """Risk assessment levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskFactor:
    """Individual risk factor contribution."""
    name: str
    score: float
    weight: float
    description: str


@dataclass
class RiskAssessment:
    """Comprehensive risk assessment result."""
    overall_score: float
    risk_level: RiskLevel
    factors: List[RiskFactor]
    recommendations: List[str]
    confidence: float
    timestamp: datetime


class SecurityAnalyzer:
    """Advanced security analysis engine with ML-inspired algorithms."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        
        # Pre-compiled regex patterns for performance
        self.attack_patterns = {
            'brute_force': re.compile(r'(brute|force|failed|login|authentication)', re.IGNORECASE),
            'malware': re.compile(r'(malware|virus|trojan|backdoor|rootkit)', re.IGNORECASE),
            'injection': re.compile(r'(injection|sql|xss|script|command)', re.IGNORECASE),
            'privilege_escalation': re.compile(r'(privilege|escalation|sudo|admin)', re.IGNORECASE),
            'lateral_movement': re.compile(r'(lateral|movement|remote|ssh|rdp)', re.IGNORECASE),
            'data_exfiltration': re.compile(r'(exfiltration|data|transfer|download)', re.IGNORECASE)
        }
        
        # Cache for parsed timestamps to avoid repeated parsing
        self._timestamp_cache = {}
        
        # MITRE ATT&CK technique mappings (cached as class variable)
        self.mitre_techniques = self._get_mitre_techniques()
        
        # Alert severity weights
        self.severity_weights = {
            1: 0.1, 2: 0.2, 3: 0.3, 4: 0.4, 5: 0.5,
            6: 0.6, 7: 0.7, 8: 0.8, 9: 0.9, 10: 1.0,
            11: 1.2, 12: 1.4, 13: 1.6, 14: 1.8, 15: 2.0
        }
    
    @lru_cache(maxsize=1)
    def _get_mitre_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Get MITRE ATT&CK technique mappings (cached for performance)."""
        return {
            "T1078": {"name": "Valid Accounts", "tactic": "Initial Access", "weight": 0.8},
            "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "weight": 0.9},
            "T1566": {"name": "Phishing", "tactic": "Initial Access", "weight": 0.7},
            "T1055": {"name": "Process Injection", "tactic": "Defense Evasion", "weight": 0.8},
            "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation", "weight": 0.9},
            "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "weight": 0.9},
            "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery", "weight": 0.4},
            "T1021": {"name": "Remote Services", "tactic": "Lateral Movement", "weight": 0.7},
            "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "weight": 0.8},
        }
    
    def _parse_timestamp_cached(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp with caching for performance."""
        if timestamp_str in self._timestamp_cache:
            return self._timestamp_cache[timestamp_str]
        
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            self._timestamp_cache[timestamp_str] = timestamp
            return timestamp
        except (ValueError, TypeError, AttributeError):
            return None
    
    def calculate_comprehensive_risk_score(
        self, 
        alerts: List[Dict[str, Any]], 
        vulnerabilities: Optional[List[Dict[str, Any]]] = None,
        time_window_hours: int = 24
    ) -> RiskAssessment:
        """Calculate comprehensive risk score with multiple factors."""
        
        if not alerts:
            return RiskAssessment(
                overall_score=0.0,
                risk_level=RiskLevel.LOW,
                factors=[],
                recommendations=["No alerts to analyze"],
                confidence=1.0,
                timestamp=datetime.utcnow()
            )
        
        factors = []
        
        # Factor 1: Alert Severity and Frequency
        severity_factor = self._analyze_alert_severity(alerts)
        factors.append(severity_factor)
        
        # Factor 2: Time-based clustering
        clustering_factor = self._analyze_time_clustering(alerts, time_window_hours)
        factors.append(clustering_factor)
        
        # Factor 3: Attack diversity
        diversity_factor = self._analyze_attack_diversity(alerts)
        factors.append(diversity_factor)
        
        # Factor 4: MITRE ATT&CK technique detection
        mitre_factor = self._analyze_mitre_techniques(alerts)
        factors.append(mitre_factor)
        
        # Factor 5: Behavioral anomalies
        anomaly_factor = self._analyze_behavioral_anomalies(alerts)
        factors.append(anomaly_factor)
        
        # Factor 6: Vulnerability correlation (if available)
        if vulnerabilities:
            vuln_factor = self._analyze_vulnerability_correlation(alerts, vulnerabilities)
            factors.append(vuln_factor)
        
        # Calculate weighted overall score
        total_weight = sum(factor.weight for factor in factors)
        overall_score = sum(factor.score * factor.weight for factor in factors) / total_weight
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(factors, alerts)
        
        # Calculate confidence based on data quality and quantity
        confidence = self._calculate_confidence(alerts, len(factors))
        
        return RiskAssessment(
            overall_score=round(overall_score, 2),
            risk_level=risk_level,
            factors=factors,
            recommendations=recommendations,
            confidence=confidence,
            timestamp=datetime.utcnow()
        )
    
    def _analyze_alert_severity(self, alerts: List[Dict[str, Any]]) -> RiskFactor:
        """Analyze alert severity patterns."""
        if not alerts:
            return RiskFactor("Alert Severity", 0.0, 0.3, "No alerts to analyze")
        
        severity_scores = []
        for alert in alerts:
            level = alert.get("rule", {}).get("level", 0)
            severity_scores.append(self.severity_weights.get(level, 0))
        
        avg_severity = statistics.mean(severity_scores)
        max_severity = max(severity_scores)
        
        # Boost score if there are high-severity alerts
        score = min(avg_severity * 50 + max_severity * 30, 100)
        
        return RiskFactor(
            "Alert Severity",
            score,
            0.3,
            f"Average severity: {avg_severity:.2f}, Max: {max_severity:.2f}"
        )
    
    def _analyze_time_clustering(self, alerts: List[Dict[str, Any]], window_hours: int) -> RiskFactor:
        """Analyze temporal clustering of alerts."""
        if len(alerts) < 2:
            return RiskFactor("Time Clustering", 0.0, 0.2, "Insufficient alerts for clustering analysis")
        
        # Parse timestamps
        timestamps = []
        for alert in alerts:
            try:
                timestamp_str = alert.get("timestamp", "")
                if not timestamp_str:
                    continue
                
                # Handle various timestamp formats safely
                if timestamp_str.endswith("Z"):
                    timestamp_str = timestamp_str[:-1] + "+00:00"
                elif "+" not in timestamp_str and "Z" not in timestamp_str:
                    timestamp_str += "+00:00"
                
                timestamp = datetime.fromisoformat(timestamp_str)
                timestamps.append(timestamp)
            except (ValueError, TypeError, AttributeError) as e:
                logger.warning(f"Failed to parse timestamp '{timestamp_str}': {e}")
                continue
        
        if len(timestamps) < 2:
            return RiskFactor("Time Clustering", 0.0, 0.2, "Invalid timestamps")
        
        timestamps.sort()
        
        # Calculate clustering score based on time gaps
        gaps = []
        for i in range(1, len(timestamps)):
            gap = (timestamps[i] - timestamps[i-1]).total_seconds()
            gaps.append(gap)
        
        # Look for suspicious clustering (many alerts in short time)
        short_gaps = [gap for gap in gaps if gap < 300]  # 5 minutes
        clustering_ratio = len(short_gaps) / len(gaps) if gaps else 0
        
        score = min(clustering_ratio * 100, 100)
        
        return RiskFactor(
            "Time Clustering",
            score,
            0.2,
            f"Clustering ratio: {clustering_ratio:.2f}, Short gaps: {len(short_gaps)}"
        )
    
    def _analyze_attack_diversity(self, alerts: List[Dict[str, Any]]) -> RiskFactor:
        """Analyze diversity of attack types."""
        if not alerts:
            return RiskFactor("Attack Diversity", 0.0, 0.15, "No alerts to analyze")
        
        # Extract rule groups (attack categories)
        rule_groups = []
        for alert in alerts:
            groups = alert.get("rule", {}).get("groups", [])
            rule_groups.extend(groups)
        
        if not rule_groups:
            return RiskFactor("Attack Diversity", 0.0, 0.15, "No rule groups found")
        
        unique_groups = set(rule_groups)
        diversity_score = min(len(unique_groups) * 10, 100)  # More diverse = higher risk
        
        return RiskFactor(
            "Attack Diversity",
            diversity_score,
            0.15,
            f"Unique attack types: {len(unique_groups)}"
        )
    
    def _analyze_mitre_techniques(self, alerts: List[Dict[str, Any]]) -> RiskFactor:
        """Analyze MITRE ATT&CK technique presence."""
        detected_techniques = set()
        
        for alert in alerts:
            description = alert.get("rule", {}).get("description", "").upper()
            groups = alert.get("rule", {}).get("groups", [])
            
            # Simple technique detection based on keywords
            for technique_id, technique_info in self.mitre_techniques.items():
                technique_name = technique_info["name"].upper()
                if any(word in description for word in technique_name.split()) or \
                   any(technique_name.replace(" ", "_").lower() in group.lower() for group in groups):
                    detected_techniques.add(technique_id)
        
        if not detected_techniques:
            return RiskFactor("MITRE Techniques", 0.0, 0.2, "No MITRE techniques detected")
        
        # Calculate score based on technique severity and count
        total_weight = sum(self.mitre_techniques[tid]["weight"] for tid in detected_techniques)
        score = min(total_weight * 20, 100)
        
        return RiskFactor(
            "MITRE Techniques",
            score,
            0.2,
            f"Detected techniques: {len(detected_techniques)}, Weight: {total_weight:.2f}"
        )
    
    def _analyze_behavioral_anomalies(self, alerts: List[Dict[str, Any]]) -> RiskFactor:
        """Analyze behavioral anomalies in alert patterns."""
        if len(alerts) < 5:
            return RiskFactor("Behavioral Anomalies", 0.0, 0.1, "Insufficient data for anomaly detection")
        
        # Analyze agent distribution
        agent_counter = Counter()
        for alert in alerts:
            agent_id = alert.get("agent", {}).get("id", "unknown")
            agent_counter[agent_id] += 1
        
        # Calculate concentration (if most alerts from one agent, it's suspicious)
        total_alerts = len(alerts)
        max_agent_alerts = max(agent_counter.values()) if agent_counter else 0
        concentration = max_agent_alerts / total_alerts if total_alerts > 0 else 0
        
        # Calculate time distribution anomalies
        hour_counter = Counter()
        for alert in alerts:
            try:
                timestamp_str = alert.get("timestamp", "")
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                hour_counter[timestamp.hour] += 1
            except (ValueError, TypeError, AttributeError) as e:
                logger.debug(f"Failed to parse timestamp '{timestamp_str}': {e}")
                continue
        
        # Check for unusual time patterns (e.g., many alerts during off-hours)
        off_hours = [0, 1, 2, 3, 4, 5, 22, 23]
        off_hour_alerts = sum(hour_counter[hour] for hour in off_hours)
        off_hour_ratio = off_hour_alerts / total_alerts if total_alerts > 0 else 0
        
        # Combine anomaly indicators
        anomaly_score = (concentration * 50) + (off_hour_ratio * 30)
        score = min(anomaly_score, 100)
        
        return RiskFactor(
            "Behavioral Anomalies",
            score,
            0.1,
            f"Agent concentration: {concentration:.2f}, Off-hours: {off_hour_ratio:.2f}"
        )
    
    def _analyze_vulnerability_correlation(
        self, 
        alerts: List[Dict[str, Any]], 
        vulnerabilities: List[Dict[str, Any]]
    ) -> RiskFactor:
        """Correlate alerts with known vulnerabilities."""
        if not vulnerabilities:
            return RiskFactor("Vulnerability Correlation", 0.0, 0.05, "No vulnerability data available")
        
        # Extract agents with vulnerabilities
        vulnerable_agents = set()
        critical_vulns = 0
        
        for vuln in vulnerabilities:
            agent_id = vuln.get("agent_id")
            if agent_id:
                vulnerable_agents.add(agent_id)
            
            severity = vuln.get("severity", "").lower()
            if severity in ["critical", "high"]:
                critical_vulns += 1
        
        # Check how many alerts come from vulnerable agents
        alert_agents = set()
        vulnerable_alert_count = 0
        
        for alert in alerts:
            agent_id = alert.get("agent", {}).get("id")
            if agent_id:
                alert_agents.add(agent_id)
                if agent_id in vulnerable_agents:
                    vulnerable_alert_count += 1
        
        if not alert_agents:
            return RiskFactor("Vulnerability Correlation", 0.0, 0.05, "No agent information in alerts")
        
        correlation_ratio = vulnerable_alert_count / len(alerts)
        vuln_severity_factor = min(critical_vulns / len(vulnerabilities), 1.0) if vulnerabilities else 0
        
        score = (correlation_ratio * 70) + (vuln_severity_factor * 30)
        
        return RiskFactor(
            "Vulnerability Correlation",
            score,
            0.05,
            f"Correlation ratio: {correlation_ratio:.2f}, Critical vulns: {critical_vulns}"
        )
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level based on overall score."""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _generate_recommendations(self, factors: List[RiskFactor], alerts: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable security recommendations."""
        recommendations = []
        
        # Analyze factors to generate specific recommendations
        for factor in factors:
            if factor.score > 70:
                if factor.name == "Alert Severity":
                    recommendations.append("Investigate high-severity alerts immediately")
                elif factor.name == "Time Clustering":
                    recommendations.append("Analyze temporal patterns for coordinated attacks")
                elif factor.name == "Attack Diversity":
                    recommendations.append("Implement cross-vector attack correlation")
                elif factor.name == "MITRE Techniques":
                    recommendations.append("Review MITRE ATT&CK framework coverage")
                elif factor.name == "Behavioral Anomalies":
                    recommendations.append("Investigate unusual behavioral patterns")
                elif factor.name == "Vulnerability Correlation":
                    recommendations.append("Prioritize patching on affected systems")
        
        # General recommendations based on alert patterns
        if len(alerts) > 100:
            recommendations.append("Consider implementing alert correlation rules")
        
        # Extract most common agents for focused investigation
        agent_counter = Counter()
        for alert in alerts:
            agent_id = alert.get("agent", {}).get("id")
            if agent_id:
                agent_counter[agent_id] += 1
        
        if agent_counter:
            top_agent = agent_counter.most_common(1)[0]
            if top_agent[1] > 10:
                recommendations.append(f"Focus investigation on agent {top_agent[0]} ({top_agent[1]} alerts)")
        
        return recommendations or ["Continue monitoring current security posture"]
    
    def _calculate_confidence(self, alerts: List[Dict[str, Any]], factor_count: int) -> float:
        """Calculate confidence in the risk assessment."""
        # Base confidence on data quantity and quality
        data_quantity_score = min(len(alerts) / 50, 1.0)  # Normalized to 50 alerts
        factor_coverage_score = min(factor_count / 6, 1.0)  # Normalized to 6 factors
        
        # Check data quality (presence of key fields)
        quality_score = 0
        for alert in alerts[:10]:  # Sample first 10 alerts
            if alert.get("rule", {}).get("level"):
                quality_score += 0.2
            if alert.get("timestamp"):
                quality_score += 0.2
            if alert.get("agent", {}).get("id"):
                quality_score += 0.2
            if alert.get("rule", {}).get("groups"):
                quality_score += 0.2
            if alert.get("rule", {}).get("description"):
                quality_score += 0.2
        
        quality_score = min(quality_score / 10, 1.0)  # Normalize
        
        # Combined confidence
        confidence = (data_quantity_score * 0.4) + (factor_coverage_score * 0.3) + (quality_score * 0.3)
        return round(confidence, 2)
    
    def detect_attack_patterns(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect specific attack patterns in alerts."""
        patterns = {
            "brute_force": self._detect_brute_force(alerts),
            "lateral_movement": self._detect_lateral_movement(alerts),
            "data_exfiltration": self._detect_data_exfiltration(alerts),
            "privilege_escalation": self._detect_privilege_escalation(alerts),
            "persistence": self._detect_persistence(alerts)
        }
        
        return {
            "detected_patterns": {k: v for k, v in patterns.items() if v["detected"]},
            "pattern_count": sum(1 for v in patterns.values() if v["detected"]),
            "confidence": max([v["confidence"] for v in patterns.values()], default=0.0)
        }
    
    def _detect_brute_force(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect brute force attack patterns."""
        brute_force_keywords = ["brute", "force", "failed", "login", "authentication", "password"]
        relevant_alerts = []
        
        for alert in alerts:
            description = alert.get("rule", {}).get("description", "").lower()
            if any(keyword in description for keyword in brute_force_keywords):
                relevant_alerts.append(alert)
        
        if len(relevant_alerts) < 3:
            return {"detected": False, "confidence": 0.0, "evidence": []}
        
        # Check for rapid succession of failed attempts
        timestamps = []
        for alert in relevant_alerts:
            try:
                timestamp_str = alert.get("timestamp", "")
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                timestamps.append(timestamp)
            except (ValueError, TypeError, AttributeError) as e:
                logger.debug(f"Failed to parse timestamp: {e}")
                continue
        
        if len(timestamps) < 3:
            return {"detected": False, "confidence": 0.0, "evidence": []}
        
        timestamps.sort()
        rapid_attempts = 0
        for i in range(1, len(timestamps)):
            if (timestamps[i] - timestamps[i-1]).total_seconds() < 60:  # Within 1 minute
                rapid_attempts += 1
        
        confidence = min(rapid_attempts / len(timestamps), 1.0)
        
        return {
            "detected": confidence > 0.3,
            "confidence": confidence,
            "evidence": [f"{len(relevant_alerts)} authentication-related alerts", f"{rapid_attempts} rapid attempts detected"]
        }
    
    def _detect_lateral_movement(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect lateral movement patterns."""
        # Look for alerts from multiple agents in succession
        agent_timeline = []
        
        for alert in alerts:
            agent_id = alert.get("agent", {}).get("id")
            timestamp_str = alert.get("timestamp", "")
            
            if agent_id and timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    agent_timeline.append((timestamp, agent_id))
                except (ValueError, TypeError, AttributeError):
                    # Skip invalid timestamp formats
                    continue
        
        if len(agent_timeline) < 3:
            return {"detected": False, "confidence": 0.0, "evidence": []}
        
        agent_timeline.sort()
        
        # Look for different agents being compromised in succession
        agent_transitions = 0
        unique_agents = set()
        
        for i in range(1, len(agent_timeline)):
            prev_agent = agent_timeline[i-1][1]
            curr_agent = agent_timeline[i][1]
            
            unique_agents.add(prev_agent)
            unique_agents.add(curr_agent)
            
            if prev_agent != curr_agent:
                # Check if transition happened within reasonable timeframe
                time_diff = (agent_timeline[i][0] - agent_timeline[i-1][0]).total_seconds()
                if 300 < time_diff < 3600:  # 5 minutes to 1 hour
                    agent_transitions += 1
        
        confidence = min(agent_transitions / max(len(unique_agents) - 1, 1), 1.0)
        
        return {
            "detected": confidence > 0.3 and len(unique_agents) > 2,
            "confidence": confidence,
            "evidence": [f"Activity across {len(unique_agents)} agents", f"{agent_transitions} suspicious transitions"]
        }
    
    def _detect_data_exfiltration(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect data exfiltration patterns."""
        exfil_keywords = ["exfiltration", "upload", "transfer", "copy", "download", "ftp", "ssh", "scp"]
        relevant_alerts = []
        
        for alert in alerts:
            description = alert.get("rule", {}).get("description", "").lower()
            groups = [g.lower() for g in alert.get("rule", {}).get("groups", [])]
            
            if any(keyword in description for keyword in exfil_keywords) or \
               any(keyword in group for group in groups for keyword in exfil_keywords):
                relevant_alerts.append(alert)
        
        confidence = min(len(relevant_alerts) / 10, 1.0)  # Normalize to 10 alerts
        
        return {
            "detected": len(relevant_alerts) > 2,
            "confidence": confidence,
            "evidence": [f"{len(relevant_alerts)} data transfer related alerts"]
        }
    
    def _detect_privilege_escalation(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect privilege escalation patterns."""
        privesc_keywords = ["privilege", "escalation", "sudo", "admin", "root", "elevation"]
        relevant_alerts = []
        
        for alert in alerts:
            description = alert.get("rule", {}).get("description", "").lower()
            groups = [g.lower() for g in alert.get("rule", {}).get("groups", [])]
            
            if any(keyword in description for keyword in privesc_keywords) or \
               any(keyword in group for group in groups for keyword in privesc_keywords):
                relevant_alerts.append(alert)
        
        confidence = min(len(relevant_alerts) / 5, 1.0)  # Normalize to 5 alerts
        
        return {
            "detected": len(relevant_alerts) > 1,
            "confidence": confidence,
            "evidence": [f"{len(relevant_alerts)} privilege-related alerts"]
        }
    
    def _detect_persistence(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect persistence mechanism patterns."""
        persistence_keywords = ["persistence", "startup", "service", "scheduled", "cron", "registry", "autorun"]
        relevant_alerts = []
        
        for alert in alerts:
            description = alert.get("rule", {}).get("description", "").lower()
            groups = [g.lower() for g in alert.get("rule", {}).get("groups", [])]
            
            if any(keyword in description for keyword in persistence_keywords) or \
               any(keyword in group for group in groups for keyword in persistence_keywords):
                relevant_alerts.append(alert)
        
        confidence = min(len(relevant_alerts) / 3, 1.0)  # Normalize to 3 alerts
        
        return {
            "detected": len(relevant_alerts) > 0,
            "confidence": confidence,
            "evidence": [f"{len(relevant_alerts)} persistence-related alerts"]
        }