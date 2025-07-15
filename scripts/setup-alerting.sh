#!/bin/bash
# Alerting Setup Script for Wazuh MCP Server v3.0.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$PROJECT_ROOT/config"
ALERTING_DIR="$CONFIG_DIR/alerting"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS] [COMMAND]

Alerting setup script for Wazuh MCP Server v3.0.0

COMMANDS:
    setup       Setup complete alerting stack
    validate    Validate alerting configuration
    test        Test alerting rules
    reload      Reload alerting configuration
    status      Show alerting status
    clean       Clean up alerting configuration

OPTIONS:
    -h, --help          Show this help message
    -v, --verbose       Enable verbose output
    -d, --dry-run       Show what would be done without executing
    -f, --force         Force overwrite existing configuration

EXAMPLES:
    $0 setup               # Setup complete alerting stack
    $0 validate            # Validate configuration
    $0 test                # Test alerting rules
    $0 reload              # Reload configuration

EOF
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check if services are running
    if ! docker compose -f "$PROJECT_ROOT/docker-compose.yml" ps | grep -q "Up"; then
        log_warn "Some services are not running. Consider starting them first."
    fi
    
    log_info "Dependencies check completed"
}

# Setup alerting directories
setup_directories() {
    log_info "Setting up alerting directories..."
    
    mkdir -p "$ALERTING_DIR/prometheus"
    mkdir -p "$ALERTING_DIR/alertmanager"
    mkdir -p "$ALERTING_DIR/grafana"
    mkdir -p "$ALERTING_DIR/templates"
    mkdir -p "$ALERTING_DIR/scripts"
    
    log_info "Alerting directories created"
}

# Generate alerting configuration
generate_alerting_config() {
    log_info "Generating alerting configuration..."
    
    # Create Prometheus alerting config
    cat > "$ALERTING_DIR/prometheus/prometheus.yml" << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'wazuh-mcp-production'
    environment: '${ENVIRONMENT:-production}'

rule_files:
  - "/etc/prometheus/rules/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
      timeout: 10s
      api_version: v2

scrape_configs:
  - job_name: 'wazuh-mcp-servers'
    static_configs:
      - targets: ['wazuh-mcp-server:9090']
    scrape_interval: 5s
    metrics_path: /metrics
    scheme: http
    
  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
    metrics_path: /metrics
    scheme: http
    
  - job_name: 'haproxy'
    static_configs:
      - targets: ['haproxy:8080']
    metrics_path: /stats
    scheme: http
    
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
    
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
    
  - job_name: 'alertmanager'
    static_configs:
      - targets: ['alertmanager:9093']
    
  - job_name: 'grafana'
    static_configs:
      - targets: ['grafana:3000']
    metrics_path: /metrics
    scheme: http
EOF
    
    # Create AlertManager notification templates
    cat > "$ALERTING_DIR/templates/email.tmpl" << 'EOF'
{{ define "email.subject" }}
[{{ .Status | toUpper }}] {{ .GroupLabels.alertname }} - {{ .GroupLabels.severity | toUpper }}
{{ end }}

{{ define "email.html" }}
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        .header { background-color: #f0f0f0; padding: 20px; }
        .alert { margin: 10px 0; padding: 15px; border-left: 4px solid #ddd; }
        .critical { border-left-color: #d32f2f; background-color: #ffebee; }
        .high { border-left-color: #f57c00; background-color: #fff3e0; }
        .medium { border-left-color: #1976d2; background-color: #e3f2fd; }
        .low { border-left-color: #388e3c; background-color: #e8f5e8; }
        .resolved { border-left-color: #4caf50; background-color: #e8f5e8; }
        .label { font-weight: bold; }
        .value { font-family: monospace; }
        .footer { margin-top: 20px; padding: 10px; background-color: #f5f5f5; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Wazuh MCP Server Alert</h1>
        <p><strong>Status:</strong> {{ .Status | toUpper }}</p>
        <p><strong>Generated:</strong> {{ .CommonAnnotations.timestamp }}</p>
    </div>
    
    {{ range .Alerts }}
    <div class="alert {{ .Labels.severity }}">
        <h2>{{ .Annotations.summary }}</h2>
        <p>{{ .Annotations.description }}</p>
        
        <table>
            <tr><td class="label">Severity:</td><td class="value">{{ .Labels.severity }}</td></tr>
            <tr><td class="label">Service:</td><td class="value">{{ .Labels.service }}</td></tr>
            <tr><td class="label">Instance:</td><td class="value">{{ .Labels.instance }}</td></tr>
            <tr><td class="label">Started:</td><td class="value">{{ .StartsAt }}</td></tr>
            {{ if .EndsAt }}
            <tr><td class="label">Ended:</td><td class="value">{{ .EndsAt }}</td></tr>
            {{ end }}
        </table>
        
        {{ if .Annotations.runbook_url }}
        <p><a href="{{ .Annotations.runbook_url }}">View Runbook</a></p>
        {{ end }}
        
        {{ if .Annotations.dashboard_url }}
        <p><a href="{{ .Annotations.dashboard_url }}">View Dashboard</a></p>
        {{ end }}
    </div>
    {{ end }}
    
    <div class="footer">
        <p>This alert was generated by the Wazuh MCP Server monitoring system.</p>
        <p>For more information, visit the <a href="https://docs.wazuh-mcp.local">documentation</a>.</p>
    </div>
</body>
</html>
{{ end }}
EOF
    
    # Create Slack notification template
    cat > "$ALERTING_DIR/templates/slack.tmpl" << 'EOF'
{{ define "slack.title" }}
{{ if eq .Status "firing" }}:fire:{{ else }}:white_check_mark:{{ end }} {{ .GroupLabels.alertname }} - {{ .GroupLabels.severity | toUpper }}
{{ end }}

{{ define "slack.text" }}
{{ if eq .Status "firing" }}
*Alert Status:* FIRING :fire:
{{ else }}
*Alert Status:* RESOLVED :white_check_mark:
{{ end }}

{{ range .Alerts }}
*Summary:* {{ .Annotations.summary }}
*Description:* {{ .Annotations.description }}
*Severity:* {{ .Labels.severity }}
*Service:* {{ .Labels.service }}
*Instance:* {{ .Labels.instance }}
*Started:* {{ .StartsAt }}
{{ if .EndsAt }}*Ended:* {{ .EndsAt }}{{ end }}

{{ if .Annotations.runbook_url }}
<{{ .Annotations.runbook_url }}|View Runbook>
{{ end }}
{{ if .Annotations.dashboard_url }}
<{{ .Annotations.dashboard_url }}|View Dashboard>
{{ end }}
{{ end }}
{{ end }}
EOF
    
    # Create alerting test script
    cat > "$ALERTING_DIR/scripts/test-alerts.sh" << 'EOF'
#!/bin/bash
# Test alerting system

echo "Testing alerting system..."

# Test critical alert
curl -X POST http://localhost:9093/api/v1/alerts -H "Content-Type: application/json" -d '[
    {
        "labels": {
            "alertname": "TestCriticalAlert",
            "severity": "critical",
            "service": "wazuh-mcp-server",
            "instance": "localhost:9090"
        },
        "annotations": {
            "summary": "Test critical alert",
            "description": "This is a test critical alert for validation",
            "runbook_url": "https://docs.wazuh-mcp.local/runbooks/test"
        },
        "startsAt": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
        "endsAt": "'$(date -u -d "+5 minutes" +%Y-%m-%dT%H:%M:%SZ)'"
    }
]'

echo "Test alert sent to AlertManager"

# Test high priority alert
curl -X POST http://localhost:9093/api/v1/alerts -H "Content-Type: application/json" -d '[
    {
        "labels": {
            "alertname": "TestHighAlert",
            "severity": "high",
            "service": "wazuh-mcp-server",
            "instance": "localhost:9090"
        },
        "annotations": {
            "summary": "Test high priority alert",
            "description": "This is a test high priority alert for validation"
        },
        "startsAt": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
        "endsAt": "'$(date -u -d "+3 minutes" +%Y-%m-%dT%H:%M:%SZ)'"
    }
]'

echo "Test alerts sent successfully"
EOF
    
    chmod +x "$ALERTING_DIR/scripts/test-alerts.sh"
    
    log_info "Alerting configuration generated"
}

# Setup monitoring exporters
setup_exporters() {
    log_info "Setting up monitoring exporters..."
    
    # Create node exporter service
    cat > "$ALERTING_DIR/docker-compose.monitoring.yml" << EOF
version: '3.8'

services:
  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--path.rootfs=/rootfs'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    networks:
      - monitoring
    restart: unless-stopped

  redis-exporter:
    image: oliver006/redis_exporter:latest
    container_name: redis-exporter
    ports:
      - "9121:9121"
    environment:
      - REDIS_ADDR=redis://redis:6379
      - REDIS_PASSWORD=\${REDIS_PASSWORD}
    depends_on:
      - redis
    networks:
      - monitoring
    restart: unless-stopped

  haproxy-exporter:
    image: prom/haproxy-exporter:latest
    container_name: haproxy-exporter
    ports:
      - "9101:9101"
    command:
      - '--haproxy.scrape-uri=http://haproxy:8080/stats;csv'
    depends_on:
      - haproxy
    networks:
      - monitoring
    restart: unless-stopped

networks:
  monitoring:
    external: true
EOF
    
    log_info "Monitoring exporters configured"
}

# Validate alerting configuration
validate_config() {
    log_info "Validating alerting configuration..."
    
    # Check Prometheus configuration
    if docker run --rm -v "$CONFIG_DIR/prometheus:/etc/prometheus" prom/prometheus:latest promtool check config /etc/prometheus/prometheus.yml; then
        log_info "Prometheus configuration is valid"
    else
        log_error "Prometheus configuration is invalid"
        return 1
    fi
    
    # Check AlertManager configuration
    if docker run --rm -v "$CONFIG_DIR/alertmanager:/etc/alertmanager" prom/alertmanager:latest amtool check-config /etc/alertmanager/alertmanager.yml; then
        log_info "AlertManager configuration is valid"
    else
        log_error "AlertManager configuration is invalid"
        return 1
    fi
    
    # Check alert rules
    if docker run --rm -v "$CONFIG_DIR/prometheus:/etc/prometheus" prom/prometheus:latest promtool check rules /etc/prometheus/rules/*.yml; then
        log_info "Alert rules are valid"
    else
        log_error "Alert rules are invalid"
        return 1
    fi
    
    log_info "All configurations are valid"
}

# Test alerting system
test_alerting() {
    log_info "Testing alerting system..."
    
    # Check if services are running
    if ! docker-compose ps | grep -q "prometheus.*Up"; then
        log_error "Prometheus is not running"
        return 1
    fi
    
    if ! docker-compose ps | grep -q "alertmanager.*Up"; then
        log_error "AlertManager is not running"
        return 1
    fi
    
    # Test Prometheus API
    if curl -s "http://localhost:9090/api/v1/status/config" | grep -q "status.*success"; then
        log_info "Prometheus API is responding"
    else
        log_error "Prometheus API is not responding"
        return 1
    fi
    
    # Test AlertManager API
    if curl -s "http://localhost:9093/api/v1/status" | grep -q "status.*success"; then
        log_info "AlertManager API is responding"
    else
        log_error "AlertManager API is not responding"
        return 1
    fi
    
    # Run test alerts
    if [ -f "$ALERTING_DIR/scripts/test-alerts.sh" ]; then
        log_info "Running test alerts..."
        bash "$ALERTING_DIR/scripts/test-alerts.sh"
    fi
    
    log_info "Alerting system tests completed"
}

# Reload alerting configuration
reload_config() {
    log_info "Reloading alerting configuration..."
    
    # Reload Prometheus
    if curl -X POST "http://localhost:9090/-/reload"; then
        log_info "Prometheus configuration reloaded"
    else
        log_error "Failed to reload Prometheus configuration"
        return 1
    fi
    
    # Reload AlertManager
    if curl -X POST "http://localhost:9093/-/reload"; then
        log_info "AlertManager configuration reloaded"
    else
        log_error "Failed to reload AlertManager configuration"
        return 1
    fi
    
    log_info "Configuration reload completed"
}

# Show alerting status
show_status() {
    log_info "Showing alerting status..."
    
    echo "=== Service Status ==="
    docker-compose ps | grep -E "prometheus|alertmanager|grafana"
    
    echo -e "\n=== Active Alerts ==="
    curl -s "http://localhost:9090/api/v1/alerts" | jq '.data[] | select(.state == "firing") | {alertname: .labels.alertname, severity: .labels.severity, instance: .labels.instance}'
    
    echo -e "\n=== AlertManager Status ==="
    curl -s "http://localhost:9093/api/v1/status" | jq '.data'
    
    echo -e "\n=== Prometheus Targets ==="
    curl -s "http://localhost:9090/api/v1/targets" | jq '.data.activeTargets[] | {job: .labels.job, instance: .labels.instance, health: .health}'
    
    echo -e "\n=== Alert Rules ==="
    curl -s "http://localhost:9090/api/v1/rules" | jq '.data.groups[] | {name: .name, rules: [.rules[] | {alert: .name, state: .state}]}'
}

# Clean up alerting configuration
cleanup() {
    log_info "Cleaning up alerting configuration..."
    
    # Stop monitoring services
    docker compose -f "$ALERTING_DIR/docker-compose.monitoring.yml" down || true
    
    # Remove generated files
    rm -rf "$ALERTING_DIR/prometheus/prometheus.yml"
    rm -rf "$ALERTING_DIR/templates/"
    rm -rf "$ALERTING_DIR/scripts/"
    
    log_info "Alerting configuration cleaned up"
}

# Main function
main() {
    local command=${1:-setup}
    
    case $command in
        setup)
            check_dependencies
            setup_directories
            generate_alerting_config
            setup_exporters
            validate_config
            log_info "Alerting setup completed successfully"
            ;;
        validate)
            validate_config
            ;;
        test)
            test_alerting
            ;;
        reload)
            reload_config
            ;;
        status)
            show_status
            ;;
        clean)
            cleanup
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--verbose)
            set -x
            shift
            ;;
        -d|--dry-run)
            log_info "Dry run mode - showing what would be done"
            exit 0
            ;;
        -f|--force)
            log_info "Force mode enabled"
            shift
            ;;
        *)
            break
            ;;
    esac
done

# Run main function
main "$@"