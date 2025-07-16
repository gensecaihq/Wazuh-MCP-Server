#!/bin/bash
# High Availability Deployment Script for Wazuh MCP Server v3.0.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_ROOT/docker compose.ha.yml"
ENV_FILE="$PROJECT_ROOT/.env"
CONFIG_DIR="$PROJECT_ROOT/config"
CERTS_DIR="$PROJECT_ROOT/certs"
LOGS_DIR="$PROJECT_ROOT/logs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker compose &> /dev/null; then
        error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check Docker version
    DOCKER_VERSION=$(docker version --format '{{.Server.Version}}')
    log "Docker version: $DOCKER_VERSION"
    
    # Check available memory
    AVAILABLE_MEMORY=$(free -m | awk 'NR==2{print $7}')
    if [ "$AVAILABLE_MEMORY" -lt 8192 ]; then
        warn "Less than 8GB of available memory detected. HA deployment may be unstable."
    fi
    
    # Check disk space
    AVAILABLE_DISK=$(df -h "$PROJECT_ROOT" | awk 'NR==2{print $4}' | sed 's/G//')
    if [ "${AVAILABLE_DISK%.*}" -lt 20 ]; then
        warn "Less than 20GB of available disk space detected."
    fi
    
    log "Prerequisites check completed"
}

# Create directories
create_directories() {
    log "Creating required directories..."
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$CERTS_DIR"
    mkdir -p "$LOGS_DIR"
    mkdir -p "$CONFIG_DIR/grafana/datasources"
    mkdir -p "$CONFIG_DIR/grafana/dashboards"
    mkdir -p "$CONFIG_DIR/prometheus"
    mkdir -p "$CONFIG_DIR/alertmanager"
    
    log "Directories created"
}

# Generate SSL certificates
generate_certificates() {
    log "Generating SSL certificates..."
    
    if [ ! -f "$CERTS_DIR/wazuh-mcp.pem" ]; then
        # Generate private key
        openssl genrsa -out "$CERTS_DIR/wazuh-mcp.key" 2048
        
        # Generate certificate signing request
        openssl req -new -key "$CERTS_DIR/wazuh-mcp.key" -out "$CERTS_DIR/wazuh-mcp.csr" -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        
        # Generate self-signed certificate
        openssl x509 -req -days 365 -in "$CERTS_DIR/wazuh-mcp.csr" -signkey "$CERTS_DIR/wazuh-mcp.key" -out "$CERTS_DIR/wazuh-mcp.crt"
        
        # Combine certificate and key for HAProxy
        cat "$CERTS_DIR/wazuh-mcp.crt" "$CERTS_DIR/wazuh-mcp.key" > "$CERTS_DIR/wazuh-mcp.pem"
        
        # Generate DH parameters
        openssl dhparam -out "$CERTS_DIR/dhparam.pem" 2048
        
        log "SSL certificates generated"
    else
        log "SSL certificates already exist"
    fi
}

# Setup environment variables
setup_environment() {
    log "Setting up environment variables..."
    
    if [ ! -f "$ENV_FILE" ]; then
        cat > "$ENV_FILE" << EOF
# Wazuh MCP Server Configuration
WAZUH_API_URL=https://your-wazuh-server:55000
WAZUH_API_USER=your-api-user
WAZUH_API_PASSWORD=your-api-password

# JWT Configuration
JWT_SECRET_KEY=$(openssl rand -base64 64)

# Admin Configuration
ADMIN_PASSWORD=$(openssl rand -base64 32)

# Redis Configuration
REDIS_PASSWORD=$(openssl rand -base64 32)

# HAProxy Configuration
HAPROXY_STATS_PASSWORD=$(openssl rand -base64 16)

# Grafana Configuration
GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 16)

# Cluster Configuration
CLUSTER_MODE=true
ENABLE_METRICS=true
LOG_LEVEL=INFO
EOF
        
        log "Environment file created: $ENV_FILE"
        warn "Please edit $ENV_FILE with your actual Wazuh server details"
    else
        log "Environment file already exists"
    fi
}

# Create monitoring configuration
create_monitoring_config() {
    log "Creating monitoring configuration..."
    
    # Prometheus configuration
    cat > "$CONFIG_DIR/prometheus-ha.yml" << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'wazuh-mcp-ha'
    replica: 'prometheus-ha'

rule_files:
  - "alerts.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager-ha:9093

scrape_configs:
  - job_name: 'wazuh-mcp-servers'
    static_configs:
      - targets:
        - wazuh-mcp-server-1:9090
        - wazuh-mcp-server-2:9090
        - wazuh-mcp-server-3:9090
    scrape_interval: 5s
    metrics_path: /metrics
    scheme: http

  - job_name: 'haproxy'
    static_configs:
      - targets:
        - load-balancer:8080
    metrics_path: /stats
    scheme: http

  - job_name: 'redis-primary'
    static_configs:
      - targets:
        - redis-primary:6379
    
  - job_name: 'redis-sentinels'
    static_configs:
      - targets:
        - redis-sentinel-1:26379
        - redis-sentinel-2:26379
        - redis-sentinel-3:26379
EOF

    # AlertManager configuration
    cat > "$CONFIG_DIR/alertmanager.yml" << EOF
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alerts@wazuh-mcp.local'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
- name: 'web.hook'
  webhook_configs:
  - url: 'http://127.0.0.1:5001/'
    send_resolved: true

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'dev', 'instance']
EOF

    # Grafana datasource configuration
    cat > "$CONFIG_DIR/grafana/datasources/prometheus.yml" << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus-ha:9090
    isDefault: true
    editable: true
EOF

    log "Monitoring configuration created"
}

# Health check function
check_health() {
    log "Performing health checks..."
    
    # Check if all services are running
    if docker compose -f "$COMPOSE_FILE" ps | grep -q "Exit"; then
        error "Some services have exited"
        docker compose -f "$COMPOSE_FILE" ps
        return 1
    fi
    
    # Check MCP server health
    for i in {1..3}; do
        if ! curl -k -f "https://localhost:8443/health" > /dev/null 2>&1; then
            warn "MCP server health check failed for instance $i"
        else
            log "MCP server instance $i is healthy"
        fi
    done
    
    # Check Redis health
    if ! docker compose -f "$COMPOSE_FILE" exec redis-primary redis-cli ping > /dev/null 2>&1; then
        error "Redis primary is not responding"
        return 1
    fi
    
    # Check HAProxy health
    if ! curl -f "http://localhost:8080/stats" > /dev/null 2>&1; then
        error "HAProxy is not responding"
        return 1
    fi
    
    log "Health checks completed successfully"
}

# Deploy function
deploy() {
    log "Starting HA deployment..."
    
    # Pull latest images
    log "Pulling Docker images..."
    docker compose -f "$COMPOSE_FILE" pull
    
    # Build custom images
    log "Building custom images..."
    docker compose -f "$COMPOSE_FILE" build
    
    # Start services
    log "Starting services..."
    docker compose -f "$COMPOSE_FILE" up -d
    
    # Wait for services to be ready
    log "Waiting for services to be ready..."
    sleep 30
    
    # Perform health checks
    check_health
    
    log "HA deployment completed successfully!"
    log "Services available at:"
    log "  - MCP Server: https://localhost:8443"
    log "  - HAProxy Stats: http://localhost:8080/stats"
    log "  - Grafana: http://localhost:3000"
    log "  - Prometheus: http://localhost:9091"
    log "  - AlertManager: http://localhost:9093"
}

# Stop function
stop() {
    log "Stopping HA deployment..."
    docker compose -f "$COMPOSE_FILE" down
    log "HA deployment stopped"
}

# Status function
status() {
    log "Checking HA deployment status..."
    docker compose -f "$COMPOSE_FILE" ps
    
    # Check cluster status
    log "Cluster status:"
    docker compose -f "$COMPOSE_FILE" exec redis-primary redis-cli info replication
    
    # Check sentinel status
    log "Sentinel status:"
    docker compose -f "$COMPOSE_FILE" exec redis-sentinel-1 redis-cli -p 26379 info sentinel
}

# Logs function
logs() {
    local service=${1:-}
    if [ -n "$service" ]; then
        docker compose -f "$COMPOSE_FILE" logs -f "$service"
    else
        docker compose -f "$COMPOSE_FILE" logs -f
    fi
}

# Scale function
scale() {
    local service=${1:-}
    local replicas=${2:-3}
    
    if [ -z "$service" ]; then
        error "Please specify a service to scale"
        exit 1
    fi
    
    log "Scaling $service to $replicas replicas..."
    docker compose -f "$COMPOSE_FILE" up -d --scale "$service=$replicas"
}

# Backup function
backup() {
    log "Creating backup..."
    
    local backup_dir="$PROJECT_ROOT/backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup Redis data
    docker compose -f "$COMPOSE_FILE" exec redis-primary redis-cli bgsave
    docker cp "$(docker compose -f "$COMPOSE_FILE" ps -q redis-primary):/data/dump.rdb" "$backup_dir/"
    
    # Backup configuration
    cp -r "$CONFIG_DIR" "$backup_dir/"
    cp "$ENV_FILE" "$backup_dir/"
    
    log "Backup created at: $backup_dir"
}

# Main function
main() {
    case "${1:-}" in
        "deploy")
            check_prerequisites
            create_directories
            generate_certificates
            setup_environment
            create_monitoring_config
            deploy
            ;;
        "stop")
            stop
            ;;
        "status")
            status
            ;;
        "logs")
            logs "${2:-}"
            ;;
        "scale")
            scale "${2:-}" "${3:-3}"
            ;;
        "backup")
            backup
            ;;
        "health")
            check_health
            ;;
        *)
            echo "Usage: $0 {deploy|stop|status|logs|scale|backup|health}"
            echo ""
            echo "Commands:"
            echo "  deploy  - Deploy the HA stack"
            echo "  stop    - Stop the HA stack"
            echo "  status  - Show deployment status"
            echo "  logs    - Show logs (optionally for specific service)"
            echo "  scale   - Scale a service"
            echo "  backup  - Create a backup"
            echo "  health  - Run health checks"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"