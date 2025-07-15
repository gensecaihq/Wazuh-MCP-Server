#!/bin/bash
# Docker-aware backup script for Wazuh MCP Server v3.0.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-/backup/wazuh-mcp-docker}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Check if Docker services are running
check_docker_services() {
    log_info "Checking Docker services..."
    
    if ! docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" ps | grep -q "Up"; then
        log_error "No Docker services are running"
        return 1
    fi
    
    log_info "Docker services are running"
    return 0
}

# Create consistent backup with Docker
create_docker_backup() {
    local backup_name="docker-backup-$(date +%Y%m%d_%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    log_info "Creating Docker-aware backup: $backup_name"
    mkdir -p "$backup_path"
    
    # Stop services gracefully
    log_info "Stopping services gracefully..."
    docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" stop
    
    # Create volume backups
    log_info "Backing up Docker volumes..."
    local volumes=$(docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" config --volumes)
    
    for volume in $volumes; do
        log_info "Backing up volume: $volume"
        docker run --rm \
            -v "${volume}:/source:ro" \
            -v "$backup_path:/backup" \
            alpine:latest \
            tar -czf "/backup/${volume}.tar.gz" -C /source .
    done
    
    # Backup container configurations
    log_info "Backing up container configurations..."
    docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" config > "$backup_path/docker-compose.yml"
    
    # Backup environment files
    if [ -f "$PROJECT_ROOT/.env" ]; then
        cp "$PROJECT_ROOT/.env" "$backup_path/.env"
    fi
    
    # Backup custom configurations
    if [ -d "$PROJECT_ROOT/config" ]; then
        cp -r "$PROJECT_ROOT/config" "$backup_path/"
    fi
    
    # Backup certificates
    if [ -d "$PROJECT_ROOT/certs" ]; then
        cp -r "$PROJECT_ROOT/certs" "$backup_path/"
    fi
    
    # Create backup metadata
    cat > "$backup_path/backup_metadata.json" << EOF
{
    "backup_type": "docker",
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "version": "3.0.0",
    "hostname": "$(hostname)",
    "compose_file": "$COMPOSE_FILE",
    "volumes": [$(echo "$volumes" | sed 's/^/"/; s/$/"/; s/\n/", "/g' | tr -d '\n')],
    "containers": [$(docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" ps --services | sed 's/^/"/; s/$/"/; s/\n/", "/g' | tr -d '\n')]
}
EOF
    
    # Restart services
    log_info "Restarting services..."
    docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" up -d
    
    # Verify services are healthy
    log_info "Verifying service health..."
    sleep 30
    
    local healthy=true
    for service in $(docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" ps --services); do
        if ! docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" ps "$service" | grep -q "Up"; then
            log_error "Service $service is not healthy after restart"
            healthy=false
        fi
    done
    
    if [ "$healthy" = false ]; then
        log_error "Some services failed to start after backup"
        return 1
    fi
    
    # Compress backup
    log_info "Compressing backup..."
    tar -czf "$backup_path.tar.gz" -C "$BACKUP_DIR" "$backup_name"
    rm -rf "$backup_path"
    
    log_info "Docker backup completed: $backup_path.tar.gz"
    echo "$backup_path.tar.gz"
}

# Restore from Docker backup
restore_docker_backup() {
    local backup_file="$1"
    local restore_dir="$BACKUP_DIR/restore-$(date +%Y%m%d_%H%M%S)"
    
    if [ -z "$backup_file" ] || [ ! -f "$backup_file" ]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi
    
    log_info "Restoring from Docker backup: $backup_file"
    mkdir -p "$restore_dir"
    
    # Extract backup
    log_info "Extracting backup..."
    tar -xzf "$backup_file" -C "$restore_dir"
    
    local backup_content=$(ls "$restore_dir")
    local backup_path="$restore_dir/$backup_content"
    
    # Verify backup metadata
    if [ ! -f "$backup_path/backup_metadata.json" ]; then
        log_error "Backup metadata not found"
        return 1
    fi
    
    # Read metadata
    local volumes=$(jq -r '.volumes[]' "$backup_path/backup_metadata.json")
    local containers=$(jq -r '.containers[]' "$backup_path/backup_metadata.json")
    
    # Stop current services
    log_info "Stopping current services..."
    docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" down -v
    
    # Restore volumes
    log_info "Restoring Docker volumes..."
    for volume in $volumes; do
        log_info "Restoring volume: $volume"
        
        # Create volume if it doesn't exist
        docker volume create "$volume" || true
        
        # Restore volume data
        docker run --rm \
            -v "${volume}:/target" \
            -v "$backup_path:/backup:ro" \
            alpine:latest \
            tar -xzf "/backup/${volume}.tar.gz" -C /target
    done
    
    # Restore configuration files
    log_info "Restoring configuration files..."
    
    if [ -f "$backup_path/docker-compose.yml" ]; then
        cp "$backup_path/docker-compose.yml" "$PROJECT_ROOT/$COMPOSE_FILE"
    fi
    
    if [ -f "$backup_path/.env" ]; then
        cp "$backup_path/.env" "$PROJECT_ROOT/"
    fi
    
    if [ -d "$backup_path/config" ]; then
        cp -r "$backup_path/config" "$PROJECT_ROOT/"
    fi
    
    if [ -d "$backup_path/certs" ]; then
        cp -r "$backup_path/certs" "$PROJECT_ROOT/"
    fi
    
    # Start services
    log_info "Starting restored services..."
    docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" up -d
    
    # Verify restore
    log_info "Verifying restore..."
    sleep 60
    
    local restore_success=true
    for service in $containers; do
        if ! docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" ps "$service" | grep -q "Up"; then
            log_error "Service $service failed to start after restore"
            restore_success=false
        fi
    done
    
    # Test application health
    if [ "$restore_success" = true ]; then
        if curl -k -f "https://localhost:8443/health" > /dev/null 2>&1; then
            log_info "Application health check passed"
        else
            log_error "Application health check failed"
            restore_success=false
        fi
    fi
    
    # Cleanup
    rm -rf "$restore_dir"
    
    if [ "$restore_success" = true ]; then
        log_info "Docker backup restore completed successfully"
        return 0
    else
        log_error "Docker backup restore failed"
        return 1
    fi
}

# Live backup without downtime
live_backup() {
    local backup_name="live-backup-$(date +%Y%m%d_%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    log_info "Creating live backup: $backup_name"
    mkdir -p "$backup_path"
    
    # Backup volumes while services are running
    log_info "Creating live volume backups..."
    local volumes=$(docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" config --volumes)
    
    for volume in $volumes; do
        log_info "Creating live backup of volume: $volume"
        
        # Use a temporary container to create backup
        docker run --rm \
            -v "${volume}:/source:ro" \
            -v "$backup_path:/backup" \
            --name "backup-${volume}-$(date +%s)" \
            alpine:latest \
            sh -c "cd /source && tar -czf /backup/${volume}.tar.gz ."
    done
    
    # Backup application state
    log_info "Backing up application state..."
    
    # Trigger Redis save
    local redis_container=$(docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" ps -q redis)
    if [ -n "$redis_container" ]; then
        docker exec "$redis_container" redis-cli BGSAVE
        
        # Wait for save to complete
        local last_save=$(docker exec "$redis_container" redis-cli LASTSAVE)
        while true; do
            local current_save=$(docker exec "$redis_container" redis-cli LASTSAVE)
            if [ "$current_save" -gt "$last_save" ]; then
                break
            fi
            sleep 1
        done
    fi
    
    # Create snapshot metadata
    cat > "$backup_path/snapshot_metadata.json" << EOF
{
    "backup_type": "live",
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "version": "3.0.0",
    "hostname": "$(hostname)",
    "services_running": true,
    "snapshot_method": "live",
    "consistency_level": "application"
}
EOF
    
    # Compress backup
    log_info "Compressing live backup..."
    tar -czf "$backup_path.tar.gz" -C "$BACKUP_DIR" "$backup_name"
    rm -rf "$backup_path"
    
    log_info "Live backup completed: $backup_path.tar.gz"
    echo "$backup_path.tar.gz"
}

# Backup specific service
backup_service() {
    local service_name="$1"
    local backup_name="service-${service_name}-$(date +%Y%m%d_%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    if [ -z "$service_name" ]; then
        log_error "Service name not specified"
        return 1
    fi
    
    log_info "Creating backup for service: $service_name"
    mkdir -p "$backup_path"
    
    # Get service container
    local container=$(docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" ps -q "$service_name")
    if [ -z "$container" ]; then
        log_error "Service not found: $service_name"
        return 1
    fi
    
    # Backup container volumes
    local volumes=$(docker inspect "$container" --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}')
    
    for volume_pair in $volumes; do
        local source=$(echo "$volume_pair" | cut -d: -f1)
        local dest=$(echo "$volume_pair" | cut -d: -f2)
        
        if [[ "$source" == /var/lib/docker/volumes/* ]]; then
            # Docker volume
            local volume_name=$(basename "$source")
            docker run --rm \
                -v "${volume_name}:/source:ro" \
                -v "$backup_path:/backup" \
                alpine:latest \
                tar -czf "/backup/${volume_name}.tar.gz" -C /source .
        fi
    done
    
    # Backup container configuration
    docker inspect "$container" > "$backup_path/container_config.json"
    
    # Create service metadata
    cat > "$backup_path/service_metadata.json" << EOF
{
    "service_name": "$service_name",
    "container_id": "$container",
    "backup_type": "service",
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "version": "3.0.0"
}
EOF
    
    # Compress backup
    tar -czf "$backup_path.tar.gz" -C "$BACKUP_DIR" "$backup_name"
    rm -rf "$backup_path"
    
    log_info "Service backup completed: $backup_path.tar.gz"
    echo "$backup_path.tar.gz"
}

# List Docker backups
list_docker_backups() {
    log_info "Available Docker backups:"
    
    if [ ! -d "$BACKUP_DIR" ]; then
        log_warn "Backup directory not found: $BACKUP_DIR"
        return 1
    fi
    
    find "$BACKUP_DIR" -name "*.tar.gz" -type f -printf '%TY-%Tm-%Td %TH:%TM:%TS %s %f\n' | sort -r
}

# Verify backup integrity
verify_backup() {
    local backup_file="$1"
    
    if [ -z "$backup_file" ] || [ ! -f "$backup_file" ]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi
    
    log_info "Verifying backup integrity: $backup_file"
    
    # Check if tar file is valid
    if ! tar -tzf "$backup_file" > /dev/null 2>&1; then
        log_error "Backup file is corrupted"
        return 1
    fi
    
    # Extract metadata
    local temp_dir=$(mktemp -d)
    tar -xzf "$backup_file" -C "$temp_dir"
    
    local backup_content=$(ls "$temp_dir")
    local metadata_file="$temp_dir/$backup_content/backup_metadata.json"
    
    if [ -f "$metadata_file" ]; then
        log_info "Backup metadata found"
        jq . "$metadata_file"
    else
        log_warn "Backup metadata not found"
    fi
    
    # Verify volume backups
    local volumes=$(find "$temp_dir" -name "*.tar.gz" -type f)
    local volume_count=$(echo "$volumes" | wc -l)
    
    log_info "Volume backups found: $volume_count"
    
    for volume_backup in $volumes; do
        if tar -tzf "$volume_backup" > /dev/null 2>&1; then
            log_info "Volume backup valid: $(basename "$volume_backup")"
        else
            log_error "Volume backup corrupted: $(basename "$volume_backup")"
            rm -rf "$temp_dir"
            return 1
        fi
    done
    
    rm -rf "$temp_dir"
    log_info "Backup verification completed successfully"
    return 0
}

# Main function
main() {
    case "${1:-}" in
        "create")
            check_docker_services
            create_docker_backup
            ;;
        "restore")
            restore_docker_backup "${2:-}"
            ;;
        "live")
            check_docker_services
            live_backup
            ;;
        "service")
            check_docker_services
            backup_service "${2:-}"
            ;;
        "list")
            list_docker_backups
            ;;
        "verify")
            verify_backup "${2:-}"
            ;;
        *)
            echo "Usage: $0 {create|restore|live|service|list|verify}"
            echo ""
            echo "Commands:"
            echo "  create   - Create full Docker backup (with downtime)"
            echo "  restore  - Restore from Docker backup"
            echo "  live     - Create live backup (no downtime)"
            echo "  service  - Backup specific service"
            echo "  list     - List available backups"
            echo "  verify   - Verify backup integrity"
            echo ""
            echo "Examples:"
            echo "  $0 create"
            echo "  $0 restore /backup/docker-backup-20250715_020000.tar.gz"
            echo "  $0 live"
            echo "  $0 service redis"
            echo "  $0 verify /backup/docker-backup-20250715_020000.tar.gz"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"