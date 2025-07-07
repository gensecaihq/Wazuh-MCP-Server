#!/usr/bin/env python3
"""
Example usage of Wazuh MCP Server as a Python package.

This script demonstrates how to use the Wazuh MCP Server programmatically
in your own Python applications.
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta

# Import the Wazuh MCP Server components
from wazuh_mcp_server import WazuhAPIClient, WazuhConfig, create_client


async def basic_usage_example():
    """Basic usage example with manual configuration."""
    print("🔷 Basic Usage Example")
    print("=" * 50)
    
    # Method 1: Create config manually
    config = WazuhConfig(
        host="your-wazuh-server.com",
        port=55000,
        username="your-username",
        password="your-password",
        verify_ssl=False  # Set to True in production
    )
    
    # Create and initialize client
    client = WazuhAPIClient(config)
    
    try:
        # Initialize connection
        init_result = await client.initialize()
        print(f"✅ Connected to Wazuh server")
        print(f"   Server info: {init_result['server_info']}")
        
        # Get recent alerts
        alerts = await client.get_alerts(limit=10)
        print(f"📊 Retrieved {len(alerts['alerts'])} recent alerts")
        
        # Get agent information
        agents = await client.get_agents(status="active")
        print(f"🖥️  Found {agents['summary']['active']} active agents")
        
        # Perform threat analysis
        threat_analysis = await client.analyze_threats(time_range=3600)  # Last hour
        risk_level = threat_analysis['risk_assessment']['risk_level']
        print(f"⚠️  Current risk level: {risk_level}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        await client.close()


async def environment_config_example():
    """Example using environment variables for configuration."""
    print("\n🔷 Environment Configuration Example")
    print("=" * 50)
    
    # Method 2: Load config from environment variables
    # Set these environment variables or use a .env file:
    # WAZUH_HOST=your-wazuh-server.com
    # WAZUH_USER=your-username
    # WAZUH_PASS=your-password
    # VERIFY_SSL=false
    
    try:
        # This will load configuration from environment variables
        client = await create_client()
        
        print("✅ Connected using environment configuration")
        
        # Get security events from the last 24 hours
        security_events = await client.get_security_events(
            time_range=24 * 3600,  # 24 hours
            limit=50
        )
        
        print(f"🔍 Security events in last 24h: {security_events['total_events']}")
        
        # Show pattern analysis
        patterns = security_events['patterns_detected']
        if patterns:
            print("🎯 Attack patterns detected:")
            for pattern in patterns[:3]:  # Show first 3 patterns
                print(f"   - {pattern['pattern_type']}: {pattern['description']}")
        
        await client.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("💡 Make sure to set WAZUH_HOST, WAZUH_USER, WAZUH_PASS environment variables")


async def compliance_check_example():
    """Example of compliance checking functionality."""
    print("\n🔷 Compliance Check Example")
    print("=" * 50)
    
    try:
        client = await create_client()
        
        # Check PCI DSS compliance
        pci_report = await client.check_compliance(
            framework="pci_dss",
            include_evidence=True,
            include_recommendations=True
        )
        
        print(f"📋 PCI DSS Compliance Score: {pci_report['overall_score']:.1f}%")
        print(f"   Status: {pci_report['status']}")
        
        if pci_report.get('recommendations'):
            print("💡 Top recommendations:")
            for rec in pci_report['recommendations'][:3]:
                print(f"   - {rec}")
        
        # Check GDPR compliance
        gdpr_report = await client.check_compliance("gdpr")
        print(f"🇪🇺 GDPR Compliance Score: {gdpr_report['overall_score']:.1f}%")
        
        await client.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")


async def vulnerability_analysis_example():
    """Example of vulnerability analysis."""
    print("\n🔷 Vulnerability Analysis Example")
    print("=" * 50)
    
    try:
        client = await create_client()
        
        # Get vulnerabilities for all agents
        vulnerabilities = await client.get_vulnerabilities(limit=100)
        
        summary = vulnerabilities['summary']
        print(f"🛡️  Total vulnerabilities found: {summary['total_vulnerabilities']}")
        print(f"   Critical: {summary['critical_count']}")
        print(f"   High: {summary['high_count']}")
        
        # Show top CVEs
        if summary['top_cves']:
            print("🎯 Most common CVEs:")
            for cve_info in summary['top_cves'][:5]:
                print(f"   - {cve_info['cve']}: {cve_info['count']} occurrences")
        
        await client.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")


async def agent_monitoring_example():
    """Example of agent health monitoring."""
    print("\n🔷 Agent Health Monitoring Example")
    print("=" * 50)
    
    try:
        client = await create_client()
        
        # Get all agents with health assessment
        agents = await client.get_agents()
        
        health_summary = agents['summary']['health_summary']
        print(f"🖥️  Agent Health Summary:")
        print(f"   Healthy: {health_summary['healthy']}")
        print(f"   Warning: {health_summary['warning']}")
        print(f"   Critical: {health_summary['critical']}")
        
        # Show platform distribution
        platform_dist = agents['summary']['platform_distribution']
        print(f"\n🌐 Platform Distribution:")
        for platform, count in platform_dist.items():
            print(f"   {platform}: {count}")
        
        await client.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")


async def custom_integration_example():
    """Example of custom integration with your application."""
    print("\n🔷 Custom Integration Example")
    print("=" * 50)
    
    class SecurityDashboard:
        """Example custom class that integrates Wazuh data."""
        
        def __init__(self):
            self.client = None
            self.data = {}
        
        async def initialize(self):
            """Initialize the dashboard with Wazuh connection."""
            self.client = await create_client()
            await self.refresh_data()
        
        async def refresh_data(self):
            """Refresh all dashboard data."""
            print("🔄 Refreshing security dashboard data...")
            
            # Gather data in parallel
            alerts_task = self.client.get_alerts(limit=50)
            agents_task = self.client.get_agents()
            threats_task = self.client.analyze_threats(time_range=3600)
            
            alerts, agents, threats = await asyncio.gather(
                alerts_task, agents_task, threats_task
            )
            
            self.data = {
                'alerts': alerts,
                'agents': agents,
                'threats': threats,
                'last_updated': datetime.utcnow()
            }
            
            print("✅ Dashboard data refreshed")
        
        def get_summary(self):
            """Get dashboard summary."""
            if not self.data:
                return "No data available"
            
            return {
                'total_alerts': len(self.data['alerts']['alerts']),
                'active_agents': self.data['agents']['summary']['active'],
                'risk_level': self.data['threats']['risk_assessment']['risk_level'],
                'last_updated': self.data['last_updated'].isoformat()
            }
        
        async def close(self):
            """Clean up resources."""
            if self.client:
                await self.client.close()
    
    try:
        # Use custom dashboard
        dashboard = SecurityDashboard()
        await dashboard.initialize()
        
        summary = dashboard.get_summary()
        print(f"📊 Security Dashboard Summary:")
        print(f"   Total alerts: {summary['total_alerts']}")
        print(f"   Active agents: {summary['active_agents']}")
        print(f"   Risk level: {summary['risk_level']}")
        print(f"   Last updated: {summary['last_updated']}")
        
        await dashboard.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")


async def main():
    """Run all examples."""
    print("🚀 Wazuh MCP Server - Package Usage Examples")
    print("=" * 60)
    print("This script demonstrates how to use the Wazuh MCP Server")
    print("as a Python package in your own applications.")
    print()
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Check if environment variables are set
    required_vars = ['WAZUH_HOST', 'WAZUH_USER', 'WAZUH_PASS']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print("⚠️  Warning: Missing environment variables:", missing_vars)
        print("   Some examples may not work without proper configuration.")
        print("   Please set these variables or create a .env file.")
        print()
    
    # Run examples
    examples = [
        ("Basic Usage", basic_usage_example),
        ("Environment Config", environment_config_example),
        ("Compliance Check", compliance_check_example),
        ("Vulnerability Analysis", vulnerability_analysis_example),
        ("Agent Monitoring", agent_monitoring_example),
        ("Custom Integration", custom_integration_example),
    ]
    
    for name, example_func in examples:
        try:
            await example_func()
        except Exception as e:
            print(f"\n❌ Example '{name}' failed: {e}")
        
        print("\n" + "-" * 60)
        await asyncio.sleep(1)  # Brief pause between examples
    
    print("\n✅ All examples completed!")
    print("\n📚 For more information, check the documentation at:")
    print("   https://github.com/gensecaihq/Wazuh-MCP-Server")


if __name__ == "__main__":
    # Run the examples
    asyncio.run(main())
