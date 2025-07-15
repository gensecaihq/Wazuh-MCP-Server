"""Tests for security analyzer module."""

import pytest
from datetime import datetime, timedelta
from wazuh_mcp_server.analyzers.security_analyzer import SecurityAnalyzer, RiskLevel


class TestSecurityAnalyzer:
    """Test cases for SecurityAnalyzer."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = SecurityAnalyzer()
        
        # Sample alerts for testing
        self.sample_alerts = [
            {
                "id": "1",
                "timestamp": (datetime.utcnow() - timedelta(minutes=5)).isoformat() + "Z",
                "rule": {
                    "id": "5710",
                    "level": 10,
                    "description": "Multiple authentication failures",
                    "groups": ["authentication_failed", "pci_dss_8.2.3"]
                },
                "agent": {
                    "id": "001",
                    "name": "web-server-01",
                    "ip": "192.168.1.10"
                }
            },
            {
                "id": "2",
                "timestamp": (datetime.utcnow() - timedelta(minutes=3)).isoformat() + "Z",
                "rule": {
                    "id": "5712",
                    "level": 12,
                    "description": "Possible attack detected",
                    "groups": ["attack", "intrusion_attempt"]
                },
                "agent": {
                    "id": "002",
                    "name": "web-server-02",
                    "ip": "192.168.1.11"
                }
            },
            {
                "id": "3",
                "timestamp": (datetime.utcnow() - timedelta(minutes=1)).isoformat() + "Z",
                "rule": {
                    "id": "5715",
                    "level": 8,
                    "description": "Login success",
                    "groups": ["authentication_success"]
                },
                "agent": {
                    "id": "001",
                    "name": "web-server-01",
                    "ip": "192.168.1.10"
                }
            }
        ]
        
        self.sample_vulnerabilities = [
            {
                "agent_id": "001",
                "severity": "critical",
                "title": "Remote Code Execution",
                "cve": "CVE-2023-1234"
            },
            {
                "agent_id": "002",
                "severity": "high",
                "title": "SQL Injection",
                "cve": "CVE-2023-5678"
            }
        ]
    
    def test_calculate_risk_score_empty_alerts(self):
        """Test risk calculation with no alerts."""
        assessment = self.analyzer.calculate_comprehensive_risk_score([])
        
        assert assessment.overall_score == 0.0
        assert assessment.risk_level == RiskLevel.LOW
        assert assessment.confidence == 1.0
        assert len(assessment.factors) == 0
        assert "No alerts to analyze" in assessment.recommendations
    
    def test_calculate_risk_score_with_alerts(self):
        """Test risk calculation with sample alerts."""
        assessment = self.analyzer.calculate_comprehensive_risk_score(
            self.sample_alerts
        )
        
        assert assessment.overall_score > 0
        assert isinstance(assessment.risk_level, RiskLevel)
        assert 0 <= assessment.confidence <= 1
        assert len(assessment.factors) > 0
        assert len(assessment.recommendations) > 0
        assert isinstance(assessment.timestamp, datetime)
    
    def test_calculate_risk_score_with_vulnerabilities(self):
        """Test risk calculation including vulnerabilities."""
        assessment = self.analyzer.calculate_comprehensive_risk_score(
            self.sample_alerts,
            self.sample_vulnerabilities
        )
        
        assert assessment.overall_score > 0
        assert len(assessment.factors) > 0
        
        # Should have vulnerability correlation factor
        factor_names = [factor.name for factor in assessment.factors]
        assert "Vulnerability Correlation" in factor_names
    
    def test_analyze_alert_severity(self):
        """Test alert severity analysis."""
        factor = self.analyzer._analyze_alert_severity(self.sample_alerts)
        
        assert factor.name == "Alert Severity"
        assert factor.score > 0
        assert factor.weight == 0.3
        assert "severity" in factor.description.lower()
    
    def test_analyze_time_clustering(self):
        """Test time clustering analysis."""
        factor = self.analyzer._analyze_time_clustering(self.sample_alerts, 24)
        
        assert factor.name == "Time Clustering"
        assert factor.weight == 0.2
        assert isinstance(factor.score, float)
    
    def test_analyze_attack_diversity(self):
        """Test attack diversity analysis."""
        factor = self.analyzer._analyze_attack_diversity(self.sample_alerts)
        
        assert factor.name == "Attack Diversity"
        assert factor.weight == 0.15
        assert factor.score >= 0
    
    def test_analyze_mitre_techniques(self):
        """Test MITRE ATT&CK technique analysis."""
        factor = self.analyzer._analyze_mitre_techniques(self.sample_alerts)
        
        assert factor.name == "MITRE Techniques"
        assert factor.weight == 0.2
        assert isinstance(factor.score, float)
    
    def test_analyze_behavioral_anomalies(self):
        """Test behavioral anomaly analysis."""
        factor = self.analyzer._analyze_behavioral_anomalies(self.sample_alerts)
        
        assert factor.name == "Behavioral Anomalies"
        assert factor.weight == 0.1
        assert isinstance(factor.score, float)
    
    def test_analyze_vulnerability_correlation(self):
        """Test vulnerability correlation analysis."""
        factor = self.analyzer._analyze_vulnerability_correlation(
            self.sample_alerts,
            self.sample_vulnerabilities
        )
        
        assert factor.name == "Vulnerability Correlation"
        assert factor.weight == 0.05
        assert isinstance(factor.score, float)
    
    def test_determine_risk_level_critical(self):
        """Test risk level determination for critical score."""
        risk_level = self.analyzer._determine_risk_level(85.0)
        assert risk_level == RiskLevel.CRITICAL
    
    def test_determine_risk_level_high(self):
        """Test risk level determination for high score."""
        risk_level = self.analyzer._determine_risk_level(65.0)
        assert risk_level == RiskLevel.HIGH
    
    def test_determine_risk_level_medium(self):
        """Test risk level determination for medium score."""
        risk_level = self.analyzer._determine_risk_level(45.0)
        assert risk_level == RiskLevel.MEDIUM
    
    def test_determine_risk_level_low(self):
        """Test risk level determination for low score."""
        risk_level = self.analyzer._determine_risk_level(25.0)
        assert risk_level == RiskLevel.LOW
    
    def test_detect_attack_patterns(self):
        """Test attack pattern detection."""
        patterns = self.analyzer.detect_attack_patterns(self.sample_alerts)
        
        assert "detected_patterns" in patterns
        assert "pattern_count" in patterns
        assert "confidence" in patterns
        assert isinstance(patterns["pattern_count"], int)
        assert isinstance(patterns["confidence"], float)
    
    def test_detect_brute_force_pattern(self):
        """Test brute force pattern detection."""
        # Create alerts that look like brute force
        brute_force_alerts = [
            {
                "id": f"{i}",
                "timestamp": (datetime.utcnow() - timedelta(seconds=i*30)).isoformat() + "Z",
                "rule": {
                    "id": "5710",
                    "level": 10,
                    "description": "Multiple authentication failures",
                    "groups": ["authentication_failed"]
                },
                "agent": {"id": "001", "name": "server", "ip": "192.168.1.10"}
            }
            for i in range(5)
        ]
        
        pattern = self.analyzer._detect_brute_force(brute_force_alerts)
        
        assert isinstance(pattern["detected"], bool)
        assert isinstance(pattern["confidence"], float)
        assert isinstance(pattern["evidence"], list)
    
    def test_detect_lateral_movement_pattern(self):
        """Test lateral movement pattern detection."""
        pattern = self.analyzer._detect_lateral_movement(self.sample_alerts)
        
        assert isinstance(pattern["detected"], bool)
        assert isinstance(pattern["confidence"], float)
        assert isinstance(pattern["evidence"], list)
    
    def test_generate_recommendations(self):
        """Test recommendation generation."""
        factors = [
            self.analyzer._analyze_alert_severity(self.sample_alerts),
            self.analyzer._analyze_time_clustering(self.sample_alerts, 24)
        ]
        
        recommendations = self.analyzer._generate_recommendations(factors, self.sample_alerts)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        assert all(isinstance(rec, str) for rec in recommendations)
    
    def test_calculate_confidence(self):
        """Test confidence calculation."""
        confidence = self.analyzer._calculate_confidence(self.sample_alerts, 5)
        
        assert isinstance(confidence, float)
        assert 0 <= confidence <= 1
    
    def test_mitre_techniques_mapping(self):
        """Test MITRE ATT&CK techniques mapping."""
        assert len(self.analyzer.mitre_techniques) > 0
        
        for technique_id, technique_info in self.analyzer.mitre_techniques.items():
            assert technique_id.startswith("T")
            assert "name" in technique_info
            assert "tactic" in technique_info
            assert "weight" in technique_info
            assert isinstance(technique_info["weight"], (int, float))
    
    def test_severity_weights_mapping(self):
        """Test severity weights mapping."""
        assert len(self.analyzer.severity_weights) == 15
        
        for level, weight in self.analyzer.severity_weights.items():
            assert 1 <= level <= 15
            assert isinstance(weight, (int, float))
            assert weight > 0