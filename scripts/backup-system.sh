#!/bin/bash
# Automated Backup System for Wazuh MCP Server v3.0.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$PROJECT_ROOT/config/backup.conf"
BACKUP_BASE_DIR="${BACKUP_DIR:-/backup/wazuh-mcp}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
COMPRESSION_LEVEL="${COMPRESSION_LEVEL:-6}"
ENCRYPTION_KEY="${ENCRYPTION_KEY:-}"
NOTIFICATION_EMAIL="${NOTIFICATION_EMAIL:-}"
S3_BUCKET="${S3_BUCKET:-}"
S3_REGION="${S3_REGION:-us-east-1}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="$PROJECT_ROOT/logs/backup.log"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "$@"
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    log "WARN" "$@"
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    log "ERROR" "$@"
    echo -e "${RED}[ERROR]${NC} $*"
}

# Load configuration
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        log_info "Configuration loaded from $CONFIG_FILE"
    else
        log_warn "Configuration file not found: $CONFIG_FILE"
        create_default_config
    fi
}

# Create default configuration
create_default_config() {
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" << EOF
# Wazuh MCP Server Backup Configuration

# Backup settings
BACKUP_DIR="/backup/wazuh-mcp"
RETENTION_DAYS=30
COMPRESSION_LEVEL=6
ENABLE_ENCRYPTION=true
ENCRYPTION_KEY=""

# Database settings
REDIS_BACKUP_ENABLED=true
REDIS_BACKUP_METHOD="rdb"  # rdb or aof

# Application settings
CONFIG_BACKUP_ENABLED=true
LOGS_BACKUP_ENABLED=true
CERTS_BACKUP_ENABLED=true

# Remote storage
S3_BACKUP_ENABLED=false
S3_BUCKET=""
S3_REGION="us-east-1"
S3_STORAGE_CLASS="STANDARD_IA"

# Notification settings
NOTIFICATION_ENABLED=true
NOTIFICATION_EMAIL=""
NOTIFICATION_SLACK_WEBHOOK=""

# Monitoring
PROMETHEUS_METRICS_ENABLED=true
BACKUP_METRICS_PORT=9091
EOF
    log_info "Default configuration created: $CONFIG_FILE"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
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
    
    # Check backup directory
    if [ ! -d "$BACKUP_BASE_DIR" ]; then
        log_info "Creating backup directory: $BACKUP_BASE_DIR"
        mkdir -p "$BACKUP_BASE_DIR"
    fi
    
    # Check disk space
    local available_space=$(df -BG "$BACKUP_BASE_DIR" | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$available_space" -lt 10 ]; then
        log_warn "Less than 10GB available for backups"
    fi
    
    # Check AWS CLI if S3 backup is enabled
    if [ "${S3_BACKUP_ENABLED:-false}" = "true" ]; then
        if ! command -v aws &> /dev/null; then
            log_error "AWS CLI is not installed but S3 backup is enabled"
            exit 1
        fi
    fi
    
    log_info "Prerequisites check completed"
}

# Generate backup metadata
generate_metadata() {
    local backup_dir=$1
    local backup_type=$2
    
    cat > "$backup_dir/metadata.json" << EOF
{
    "backup_type": "$backup_type",
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "version": "3.0.0",
    "hostname": "$(hostname)",
    "user": "$(whoami)",
    "retention_days": $RETENTION_DAYS,
    "compression_level": $COMPRESSION_LEVEL,
    "encrypted": $([ -n "$ENCRYPTION_KEY" ] && echo "true" || echo "false"),
    "components": {
        "redis": ${REDIS_BACKUP_ENABLED:-true},
        "config": ${CONFIG_BACKUP_ENABLED:-true},
        "logs": ${LOGS_BACKUP_ENABLED:-true},
        "certificates": ${CERTS_BACKUP_ENABLED:-true}
    }
}
EOF
}

# Redis backup
backup_redis() {
    local backup_dir=$1
    local redis_dir="$backup_dir/redis"
    
    log_info "Starting Redis backup..."
    mkdir -p "$redis_dir"
    
    # Check if Redis is running
    if ! docker-compose -f "$PROJECT_ROOT/docker-compose.yml" ps redis | grep -q "Up"; then
        log_error "Redis container is not running"
        return 1
    fi
    
    # Get Redis container ID
    local redis_container=$(docker-compose -f "$PROJECT_ROOT/docker-compose.yml" ps -q redis)
    
    if [ "${REDIS_BACKUP_METHOD:-rdb}" = "rdb" ]; then
        # RDB backup
        log_info "Creating RDB backup..."
        
        # Trigger background save
        docker exec "$redis_container" redis-cli BGSAVE
        
        # Wait for backup to complete
        local last_save=$(docker exec "$redis_container" redis-cli LASTSAVE)
        while true; do
            local current_save=$(docker exec "$redis_container" redis-cli LASTSAVE)
            if [ "$current_save" -gt "$last_save" ]; then
                break
            fi
            sleep 1
        done
        
        # Copy RDB file
        docker cp "$redis_container:/data/dump.rdb" "$redis_dir/"
        
        # Verify backup
        if [ -f "$redis_dir/dump.rdb" ]; then
            log_info "Redis RDB backup completed successfully"
        else
            log_error "Redis RDB backup failed"
            return 1
        fi
    else
        # AOF backup
        log_info "Creating AOF backup..."
        
        # Trigger AOF rewrite
        docker exec "$redis_container" redis-cli BGREWRITEAOF
        
        # Wait for rewrite to complete
        while docker exec "$redis_container" redis-cli INFO persistence | grep -q "aof_rewrite_in_progress:1"; do
            sleep 1
        done
        
        # Copy AOF file
        docker cp "$redis_container:/data/appendonly.aof" "$redis_dir/"
        
        # Verify backup
        if [ -f "$redis_dir/appendonly.aof" ]; then
            log_info "Redis AOF backup completed successfully"
        else
            log_error "Redis AOF backup failed"
            return 1
        fi
    fi
    
    # Save Redis configuration
    docker exec "$redis_container" redis-cli CONFIG GET "*" > "$redis_dir/redis-config.txt"
    
    # Save Redis info
    docker exec "$redis_container" redis-cli INFO ALL > "$redis_dir/redis-info.txt"
    
    log_info "Redis backup completed"
}

# Configuration backup
backup_config() {
    local backup_dir=$1
    local config_dir="$backup_dir/config"
    
    log_info "Starting configuration backup..."
    mkdir -p "$config_dir"
    
    # Backup configuration files
    if [ -d "$PROJECT_ROOT/config" ]; then
        cp -r "$PROJECT_ROOT/config/" "$config_dir/"
        log_info "Configuration files backed up"
    fi
    
    # Backup environment file
    if [ -f "$PROJECT_ROOT/.env" ]; then
        # Create sanitized version (remove sensitive values)
        grep -v "PASSWORD\|SECRET\|KEY" "$PROJECT_ROOT/.env" > "$config_dir/.env.template"
        log_info "Environment template backed up"
    fi
    
    # Backup Docker Compose files
    cp "$PROJECT_ROOT"/docker-compose*.yml "$config_dir/"
    
    # Backup scripts
    if [ -d "$PROJECT_ROOT/scripts" ]; then
        cp -r "$PROJECT_ROOT/scripts/" "$config_dir/"
        log_info "Scripts backed up"
    fi
    
    log_info "Configuration backup completed"
}

# Certificates backup
backup_certificates() {
    local backup_dir=$1
    local certs_dir="$backup_dir/certs"
    
    log_info "Starting certificates backup..."
    mkdir -p "$certs_dir"
    
    if [ -d "$PROJECT_ROOT/certs" ]; then
        cp -r "$PROJECT_ROOT/certs/" "$certs_dir/"
        
        # Verify certificate files
        local cert_count=$(find "$certs_dir" -name "*.crt" -o -name "*.pem" -o -name "*.key" | wc -l)
        log_info "Certificates backed up: $cert_count files"
    else
        log_warn "Certificates directory not found"
    fi
    
    log_info "Certificates backup completed"
}

# Logs backup
backup_logs() {
    local backup_dir=$1
    local logs_dir="$backup_dir/logs"
    
    log_info "Starting logs backup..."
    mkdir -p "$logs_dir"
    
    if [ -d "$PROJECT_ROOT/logs" ]; then
        # Backup recent logs (last 7 days)
        find "$PROJECT_ROOT/logs" -name "*.log" -mtime -7 -exec cp {} "$logs_dir/" \;
        
        # Compress old logs
        find "$PROJECT_ROOT/logs" -name "*.log" -mtime +7 -exec gzip -c {} \; > "$logs_dir/archived-logs.tar.gz"
        
        local log_count=$(find "$logs_dir" -type f | wc -l)
        log_info "Logs backed up: $log_count files"
    else
        log_warn "Logs directory not found"
    fi
    
    log_info "Logs backup completed"
}

# Compress backup
compress_backup() {
    local backup_dir=$1
    local backup_name=$(basename "$backup_dir")
    local compressed_file="$backup_dir.tar.gz"
    
    log_info "Compressing backup..."
    
    # Create compressed archive
    tar -czf "$compressed_file" -C "$(dirname "$backup_dir")" "$backup_name"
    
    # Remove uncompressed directory
    rm -rf "$backup_dir"
    
    # Verify compression
    if [ -f "$compressed_file" ]; then
        local size=$(du -h "$compressed_file" | cut -f1)
        log_info "Backup compressed: $compressed_file ($size)"
        echo "$compressed_file"
    else
        log_error "Backup compression failed"
        return 1
    fi
}

# Encrypt backup
encrypt_backup() {
    local backup_file=$1
    local encrypted_file="$backup_file.enc"
    
    if [ -z "$ENCRYPTION_KEY" ]; then
        log_info "Encryption key not provided, skipping encryption"
        echo "$backup_file"
        return 0
    fi
    
    log_info "Encrypting backup..."
    
    # Encrypt using AES-256
    openssl enc -aes-256-cbc -salt -in "$backup_file" -out "$encrypted_file" -k "$ENCRYPTION_KEY"
    
    # Remove unencrypted file
    rm "$backup_file"
    
    # Verify encryption
    if [ -f "$encrypted_file" ]; then
        log_info "Backup encrypted: $encrypted_file"
        echo "$encrypted_file"
    else
        log_error "Backup encryption failed"
        return 1
    fi
}

# Upload to S3
upload_to_s3() {
    local backup_file=$1
    local s3_key="wazuh-mcp-backups/$(basename "$backup_file")"
    
    if [ "${S3_BACKUP_ENABLED:-false}" != "true" ]; then
        log_info "S3 backup disabled, skipping upload"
        return 0
    fi
    
    log_info "Uploading backup to S3..."
    
    # Upload to S3
    aws s3 cp "$backup_file" "s3://$S3_BUCKET/$s3_key" \
        --region "$S3_REGION" \
        --storage-class "${S3_STORAGE_CLASS:-STANDARD_IA}"
    
    if [ $? -eq 0 ]; then
        log_info "Backup uploaded to S3: s3://$S3_BUCKET/$s3_key"
    else
        log_error "S3 upload failed"
        return 1
    fi
}

# Clean old backups
cleanup_old_backups() {
    local retention_days=${1:-$RETENTION_DAYS}
    
    log_info "Cleaning up backups older than $retention_days days..."
    
    # Local cleanup
    local deleted_count=0
    while IFS= read -r -d '' backup_file; do
        rm "$backup_file"
        ((deleted_count++))
    done < <(find "$BACKUP_BASE_DIR" -name "*.tar.gz*" -mtime +$retention_days -print0)
    
    if [ $deleted_count -gt 0 ]; then
        log_info "Deleted $deleted_count old local backups"
    fi
    
    # S3 cleanup
    if [ "${S3_BACKUP_ENABLED:-false}" = "true" ]; then
        local cutoff_date=$(date -d "$retention_days days ago" +%Y-%m-%d)
        aws s3 ls "s3://$S3_BUCKET/wazuh-mcp-backups/" --recursive | \
            awk '$1 < "'$cutoff_date'" {print $4}' | \
            xargs -I {} aws s3 rm "s3://$S3_BUCKET/{}"
        
        log_info "S3 cleanup completed"
    fi
}

# Send notification
send_notification() {
    local status=$1
    local message=$2
    local backup_file=$3
    
    if [ "${NOTIFICATION_ENABLED:-false}" != "true" ]; then
        return 0
    fi
    
    local subject="Wazuh MCP Backup $status"
    local body="Backup Status: $status\nMessage: $message\nBackup File: $backup_file\nTimestamp: $(date)\nHostname: $(hostname)"
    
    # Email notification
    if [ -n "$NOTIFICATION_EMAIL" ]; then
        echo "$body" | mail -s "$subject" "$NOTIFICATION_EMAIL"
    fi
    
    # Slack notification
    if [ -n "$NOTIFICATION_SLACK_WEBHOOK" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$subject: $message\"}" \
            "$NOTIFICATION_SLACK_WEBHOOK"
    fi
    
    log_info "Notification sent: $status"
}

# Update metrics
update_metrics() {
    local status=$1
    local backup_file=$2
    local duration=$3
    
    if [ "${PROMETHEUS_METRICS_ENABLED:-false}" != "true" ]; then
        return 0
    fi
    
    local metrics_file="/tmp/backup_metrics.prom"
    local timestamp=$(date +%s)
    
    # Backup status (1 for success, 0 for failure)
    local status_value=$([ "$status" = "SUCCESS" ] && echo 1 || echo 0)
    
    # Backup size
    local size_bytes=0
    if [ -f "$backup_file" ]; then
        size_bytes=$(stat -c%s "$backup_file")
    fi
    
    cat > "$metrics_file" << EOF
# HELP wazuh_mcp_backup_status Status of the last backup (1=success, 0=failure)
# TYPE wazuh_mcp_backup_status gauge
wazuh_mcp_backup_status $status_value $timestamp

# HELP wazuh_mcp_backup_duration_seconds Duration of the backup operation in seconds
# TYPE wazuh_mcp_backup_duration_seconds gauge
wazuh_mcp_backup_duration_seconds $duration $timestamp

# HELP wazuh_mcp_backup_size_bytes Size of the backup file in bytes
# TYPE wazuh_mcp_backup_size_bytes gauge
wazuh_mcp_backup_size_bytes $size_bytes $timestamp

# HELP wazuh_mcp_backup_timestamp_seconds Timestamp of the last backup
# TYPE wazuh_mcp_backup_timestamp_seconds gauge
wazuh_mcp_backup_timestamp_seconds $timestamp $timestamp
EOF
    
    log_info "Metrics updated"
}

# Full backup
full_backup() {
    local start_time=$(date +%s)
    local backup_dir="$BACKUP_BASE_DIR/full-$(date +%Y%m%d_%H%M%S)"
    
    log_info "Starting full backup to: $backup_dir"
    mkdir -p "$backup_dir"
    
    # Generate metadata
    generate_metadata "$backup_dir" "full"
    
    # Backup components
    local backup_status="SUCCESS"
    local backup_message="Full backup completed successfully"
    
    if [ "${REDIS_BACKUP_ENABLED:-true}" = "true" ]; then
        if ! backup_redis "$backup_dir"; then
            backup_status="FAILED"
            backup_message="Redis backup failed"
        fi
    fi
    
    if [ "${CONFIG_BACKUP_ENABLED:-true}" = "true" ]; then
        if ! backup_config "$backup_dir"; then
            backup_status="FAILED"
            backup_message="Configuration backup failed"
        fi
    fi
    
    if [ "${CERTS_BACKUP_ENABLED:-true}" = "true" ]; then
        if ! backup_certificates "$backup_dir"; then
            backup_status="FAILED"
            backup_message="Certificates backup failed"
        fi
    fi
    
    if [ "${LOGS_BACKUP_ENABLED:-true}" = "true" ]; then
        if ! backup_logs "$backup_dir"; then
            backup_status="FAILED"
            backup_message="Logs backup failed"
        fi
    fi
    
    # Compress backup
    local compressed_file=""
    if [ "$backup_status" = "SUCCESS" ]; then
        compressed_file=$(compress_backup "$backup_dir")
        if [ $? -ne 0 ]; then
            backup_status="FAILED"
            backup_message="Backup compression failed"
        fi
    fi
    
    # Encrypt backup
    local final_file="$compressed_file"
    if [ "$backup_status" = "SUCCESS" ] && [ -n "$ENCRYPTION_KEY" ]; then
        final_file=$(encrypt_backup "$compressed_file")
        if [ $? -ne 0 ]; then
            backup_status="FAILED"
            backup_message="Backup encryption failed"
        fi
    fi
    
    # Upload to S3
    if [ "$backup_status" = "SUCCESS" ]; then
        if ! upload_to_s3 "$final_file"; then
            backup_status="FAILED"
            backup_message="S3 upload failed"
        fi
    fi
    
    # Calculate duration
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Update metrics
    update_metrics "$backup_status" "$final_file" "$duration"
    
    # Send notification
    send_notification "$backup_status" "$backup_message" "$final_file"
    
    # Log completion
    if [ "$backup_status" = "SUCCESS" ]; then
        log_info "Full backup completed successfully: $final_file (${duration}s)"
    else
        log_error "Full backup failed: $backup_message (${duration}s)"
    fi
    
    return $([ "$backup_status" = "SUCCESS" ] && echo 0 || echo 1)
}

# Incremental backup
incremental_backup() {
    local start_time=$(date +%s)
    local backup_dir="$BACKUP_BASE_DIR/incremental-$(date +%Y%m%d_%H%M%S)"
    
    log_info "Starting incremental backup to: $backup_dir"
    mkdir -p "$backup_dir"
    
    # Generate metadata
    generate_metadata "$backup_dir" "incremental"
    
    # Backup only changed files since last backup
    local last_backup_time=$(find "$BACKUP_BASE_DIR" -name "*.tar.gz*" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f1)
    
    if [ -z "$last_backup_time" ]; then
        log_warn "No previous backup found, performing full backup"
        full_backup
        return
    fi
    
    # Find changed files since last backup
    local changed_files=$(find "$PROJECT_ROOT" -type f -newer "$last_backup_time" 2>/dev/null)
    
    if [ -z "$changed_files" ]; then
        log_info "No changes detected since last backup"
        return 0
    fi
    
    # Backup changed files
    echo "$changed_files" | while read -r file; do
        local rel_path=$(realpath --relative-to="$PROJECT_ROOT" "$file")
        local backup_file="$backup_dir/$rel_path"
        mkdir -p "$(dirname "$backup_file")"
        cp "$file" "$backup_file"
    done
    
    # Compress and process backup
    local compressed_file=$(compress_backup "$backup_dir")
    local final_file="$compressed_file"
    
    if [ -n "$ENCRYPTION_KEY" ]; then
        final_file=$(encrypt_backup "$compressed_file")
    fi
    
    upload_to_s3 "$final_file"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    update_metrics "SUCCESS" "$final_file" "$duration"
    send_notification "SUCCESS" "Incremental backup completed" "$final_file"
    
    log_info "Incremental backup completed: $final_file (${duration}s)"
}

# Restore backup
restore_backup() {
    local backup_file=$1
    local restore_dir="$PROJECT_ROOT/restore-$(date +%Y%m%d_%H%M%S)"
    
    if [ -z "$backup_file" ]; then
        log_error "Backup file not specified"
        return 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi
    
    log_info "Starting restore from: $backup_file"
    mkdir -p "$restore_dir"
    
    # Decrypt if encrypted
    local work_file="$backup_file"
    if [[ "$backup_file" == *.enc ]]; then
        if [ -z "$ENCRYPTION_KEY" ]; then
            log_error "Encryption key required for encrypted backup"
            return 1
        fi
        
        local decrypted_file="${backup_file%.enc}"
        openssl enc -aes-256-cbc -d -in "$backup_file" -out "$decrypted_file" -k "$ENCRYPTION_KEY"
        work_file="$decrypted_file"
    fi
    
    # Extract backup
    tar -xzf "$work_file" -C "$restore_dir"
    
    # Stop services
    log_info "Stopping services..."
    docker-compose -f "$PROJECT_ROOT/docker-compose.yml" down
    
    # Restore components
    local restore_success=true
    
    # Restore Redis data
    if [ -d "$restore_dir/redis" ]; then
        log_info "Restoring Redis data..."
        local redis_data_dir="$PROJECT_ROOT/data/redis"
        mkdir -p "$redis_data_dir"
        
        if [ -f "$restore_dir/redis/dump.rdb" ]; then
            cp "$restore_dir/redis/dump.rdb" "$redis_data_dir/"
        fi
        
        if [ -f "$restore_dir/redis/appendonly.aof" ]; then
            cp "$restore_dir/redis/appendonly.aof" "$redis_data_dir/"
        fi
    fi
    
    # Restore configuration
    if [ -d "$restore_dir/config" ]; then
        log_info "Restoring configuration..."
        cp -r "$restore_dir/config/"* "$PROJECT_ROOT/"
    fi
    
    # Restore certificates
    if [ -d "$restore_dir/certs" ]; then
        log_info "Restoring certificates..."
        cp -r "$restore_dir/certs" "$PROJECT_ROOT/"
    fi
    
    # Start services
    log_info "Starting services..."
    docker-compose -f "$PROJECT_ROOT/docker-compose.yml" up -d
    
    # Verify restore
    sleep 30
    if curl -k -f "https://localhost:8443/health" > /dev/null 2>&1; then
        log_info "Restore completed successfully"
        send_notification "SUCCESS" "Restore completed successfully" "$backup_file"
    else
        log_error "Restore verification failed"
        restore_success=false
    fi
    
    # Cleanup
    rm -rf "$restore_dir"
    if [[ "$work_file" != "$backup_file" ]]; then
        rm "$work_file"
    fi
    
    return $([ "$restore_success" = true ] && echo 0 || echo 1)
}

# List backups
list_backups() {
    log_info "Available backups:"
    
    # Local backups
    echo "Local backups:"
    find "$BACKUP_BASE_DIR" -name "*.tar.gz*" -type f -printf '%TY-%Tm-%Td %TH:%TM:%TS %s %p\n' | sort -r | head -20
    
    # S3 backups
    if [ "${S3_BACKUP_ENABLED:-false}" = "true" ]; then
        echo -e "\nS3 backups:"
        aws s3 ls "s3://$S3_BUCKET/wazuh-mcp-backups/" --recursive | tail -20
    fi
}

# Schedule backup
schedule_backup() {
    local backup_type=${1:-full}
    local schedule=${2:-"0 2 * * *"}  # Default: 2 AM daily
    
    log_info "Scheduling $backup_type backup with cron: $schedule"
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "$schedule $SCRIPT_DIR/backup-system.sh $backup_type") | crontab -
    
    log_info "Backup scheduled successfully"
}

# Main function
main() {
    case "${1:-}" in
        "full")
            load_config
            check_prerequisites
            full_backup
            cleanup_old_backups
            ;;
        "incremental")
            load_config
            check_prerequisites
            incremental_backup
            cleanup_old_backups
            ;;
        "restore")
            load_config
            restore_backup "${2:-}"
            ;;
        "list")
            load_config
            list_backups
            ;;
        "cleanup")
            load_config
            cleanup_old_backups "${2:-$RETENTION_DAYS}"
            ;;
        "schedule")
            schedule_backup "${2:-full}" "${3:-0 2 * * *}"
            ;;
        "config")
            create_default_config
            ;;
        *)
            echo "Usage: $0 {full|incremental|restore|list|cleanup|schedule|config}"
            echo ""
            echo "Commands:"
            echo "  full        - Perform full backup"
            echo "  incremental - Perform incremental backup"
            echo "  restore     - Restore from backup file"
            echo "  list        - List available backups"
            echo "  cleanup     - Clean up old backups"
            echo "  schedule    - Schedule backup with cron"
            echo "  config      - Create default configuration"
            echo ""
            echo "Examples:"
            echo "  $0 full"
            echo "  $0 restore /backup/wazuh-mcp/full-20250715_020000.tar.gz"
            echo "  $0 schedule full '0 2 * * *'"
            echo "  $0 cleanup 7"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"