#!/bin/bash
# Local Security Scanning Script for Wazuh MCP Server v3.0.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_ROOT/security-reports"
VENV_PATH="$PROJECT_ROOT/venv"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Initialize variables
SCAN_TYPE="all"
VERBOSE=false
FAIL_ON_HIGH=false
GENERATE_REPORT=true
SEND_NOTIFICATION=false

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

log_debug() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}[DEBUG]${NC} $*"
    fi
}

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS] [SCAN_TYPE]

Local security scanning tool for Wazuh MCP Server v3.0.0

SCAN_TYPE:
    all            Run all security scans (default)
    sast           Static Application Security Testing
    deps           Dependency vulnerability scanning
    secrets        Secrets detection
    container      Docker container security
    iac            Infrastructure as Code scanning
    licenses       License compliance check
    quick          Quick security scan (essential checks only)

OPTIONS:
    -h, --help          Show this help message
    -v, --verbose       Enable verbose output
    -f, --fail-on-high  Fail on high severity findings
    -n, --no-report     Skip report generation
    -s, --send-notify   Send notifications on completion
    -o, --output DIR    Output directory for reports (default: security-reports)

EXAMPLES:
    $0                    # Run all security scans
    $0 sast              # Run only SAST scan
    $0 -v -f all         # Run all scans with verbose output, fail on high severity
    $0 --no-report quick # Run quick scan without generating report

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -f|--fail-on-high)
                FAIL_ON_HIGH=true
                shift
                ;;
            -n|--no-report)
                GENERATE_REPORT=false
                shift
                ;;
            -s|--send-notify)
                SEND_NOTIFICATION=true
                shift
                ;;
            -o|--output)
                REPORTS_DIR="$2"
                shift 2
                ;;
            all|sast|deps|secrets|container|iac|licenses|quick)
                SCAN_TYPE="$1"
                shift
                ;;
            *)
                log_error "Unknown argument: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Setup environment
setup_environment() {
    log_info "Setting up security scanning environment..."
    
    # Create reports directory
    mkdir -p "$REPORTS_DIR"
    
    # Check if virtual environment exists
    if [ ! -d "$VENV_PATH" ]; then
        log_info "Creating virtual environment..."
        python3 -m venv "$VENV_PATH"
    fi
    
    # Activate virtual environment
    source "$VENV_PATH/bin/activate"
    
    # Install/upgrade security tools
    log_info "Installing security scanning tools..."
    pip install --upgrade pip
    pip install bandit[toml] safety semgrep pip-audit detect-secrets gitpython
    
    # Install additional tools if not present
    if ! command -v docker &> /dev/null; then
        log_warn "Docker not found. Container scanning will be skipped."
    fi
    
    if ! command -v trivy &> /dev/null; then
        log_warn "Trivy not found. Advanced container scanning will be limited."
    fi
    
    if ! command -v gitleaks &> /dev/null; then
        log_warn "GitLeaks not found. Advanced secrets scanning will be limited."
    fi
}

# SAST (Static Application Security Testing)
run_sast_scan() {
    log_info "Running Static Application Security Testing (SAST)..."
    
    local sast_dir="$REPORTS_DIR/sast"
    mkdir -p "$sast_dir"
    
    # Bandit scan
    log_info "Running Bandit security scan..."
    bandit -r "$PROJECT_ROOT/src" -f json -o "$sast_dir/bandit-report.json" -l || true
    bandit -r "$PROJECT_ROOT/src" -f txt -o "$sast_dir/bandit-report.txt" -l || true
    
    if [ "$VERBOSE" = true ]; then
        cat "$sast_dir/bandit-report.txt"
    fi
    
    # Semgrep scan
    log_info "Running Semgrep security scan..."
    semgrep --config=auto --json --output="$sast_dir/semgrep-report.json" "$PROJECT_ROOT/src" || true
    semgrep --config=auto --text --output="$sast_dir/semgrep-report.txt" "$PROJECT_ROOT/src" || true
    
    if [ "$VERBOSE" = true ]; then
        cat "$sast_dir/semgrep-report.txt"
    fi
    
    # Custom security checks
    log_info "Running custom security checks..."
    
    # Check for hardcoded secrets
    grep -r "password\|secret\|key" --include="*.py" "$PROJECT_ROOT/src" | grep -v "example\|test" > "$sast_dir/hardcoded-secrets.txt" || true
    
    # Check for SQL injection patterns
    grep -r "execute\|query" --include="*.py" "$PROJECT_ROOT/src" | grep -E "(format|%|f\")" > "$sast_dir/sql-injection-patterns.txt" || true
    
    # Check for XSS patterns
    grep -r "render\|template" --include="*.py" "$PROJECT_ROOT/src" | grep -v "safe\|escape" > "$sast_dir/xss-patterns.txt" || true
    
    log_info "SAST scan completed. Results saved to $sast_dir"
}

# Dependency vulnerability scanning
run_dependency_scan() {
    log_info "Running dependency vulnerability scanning..."
    
    local deps_dir="$REPORTS_DIR/dependencies"
    mkdir -p "$deps_dir"
    
    # Safety check
    log_info "Running Safety vulnerability check..."
    safety check --json --output "$deps_dir/safety-report.json" || true
    safety check --output "$deps_dir/safety-report.txt" || true
    
    if [ "$VERBOSE" = true ]; then
        cat "$deps_dir/safety-report.txt"
    fi
    
    # pip-audit
    log_info "Running pip-audit..."
    pip-audit --desc --format=json --output="$deps_dir/pip-audit-report.json" || true
    pip-audit --desc --format=text --output="$deps_dir/pip-audit-report.txt" || true
    
    if [ "$VERBOSE" = true ]; then
        cat "$deps_dir/pip-audit-report.txt"
    fi
    
    # Check for outdated packages
    log_info "Checking for outdated packages..."
    pip list --outdated --format=json > "$deps_dir/outdated-packages.json" || true
    pip list --outdated > "$deps_dir/outdated-packages.txt" || true
    
    # License check
    log_info "Checking package licenses..."
    pip-licenses --format=json --output-file="$deps_dir/licenses.json" || true
    pip-licenses --format=plain-vertical --output-file="$deps_dir/licenses.txt" || true
    
    log_info "Dependency scan completed. Results saved to $deps_dir"
}

# Secrets detection
run_secrets_scan() {
    log_info "Running secrets detection..."
    
    local secrets_dir="$REPORTS_DIR/secrets"
    mkdir -p "$secrets_dir"
    
    # detect-secrets
    log_info "Running detect-secrets..."
    detect-secrets scan --all-files --force-use-all-plugins --exclude-files '\.git/.*' > "$secrets_dir/detect-secrets-baseline.json" || true
    detect-secrets audit "$secrets_dir/detect-secrets-baseline.json" > "$secrets_dir/detect-secrets-report.txt" || true
    
    # GitLeaks (if available)
    if command -v gitleaks &> /dev/null; then
        log_info "Running GitLeaks..."
        gitleaks detect --config="$PROJECT_ROOT/.gitleaks.toml" --report-format=json --report-path="$secrets_dir/gitleaks-report.json" || true
        gitleaks detect --config="$PROJECT_ROOT/.gitleaks.toml" --report-format=sarif --report-path="$secrets_dir/gitleaks-report.sarif" || true
    fi
    
    # Custom secrets patterns
    log_info "Searching for custom secret patterns..."
    
    # API keys
    grep -r "api[_-]key" --include="*.py" --include="*.yml" --include="*.yaml" --include="*.json" "$PROJECT_ROOT" | grep -v "example\|test" > "$secrets_dir/api-keys.txt" || true
    
    # Database connections
    grep -r "mysql://\|postgres://\|mongodb://\|redis://" --include="*.py" --include="*.yml" --include="*.yaml" "$PROJECT_ROOT" | grep -v "example\|test" > "$secrets_dir/database-connections.txt" || true
    
    # JWT secrets
    grep -r "jwt[_-]secret" --include="*.py" --include="*.yml" --include="*.yaml" "$PROJECT_ROOT" | grep -v "example\|test" > "$secrets_dir/jwt-secrets.txt" || true
    
    # Private keys
    find "$PROJECT_ROOT" -name "*.key" -o -name "*.pem" -o -name "*.p12" -o -name "*.pfx" | grep -v "example\|test" > "$secrets_dir/private-keys.txt" || true
    
    if [ "$VERBOSE" = true ]; then
        cat "$secrets_dir/detect-secrets-report.txt"
    fi
    
    log_info "Secrets scan completed. Results saved to $secrets_dir"
}

# Container security scanning
run_container_scan() {
    log_info "Running container security scanning..."
    
    local container_dir="$REPORTS_DIR/container"
    mkdir -p "$container_dir"
    
    if ! command -v docker &> /dev/null; then
        log_warn "Docker not found. Skipping container security scan."
        return
    fi
    
    # Build image for scanning
    log_info "Building Docker image for scanning..."
    docker build -t wazuh-mcp-server:security-scan "$PROJECT_ROOT" > "$container_dir/build.log" 2>&1 || true
    
    # Trivy scan (if available)
    if command -v trivy &> /dev/null; then
        log_info "Running Trivy vulnerability scan..."
        trivy image --format json --output "$container_dir/trivy-report.json" wazuh-mcp-server:security-scan || true
        trivy image --format table --output "$container_dir/trivy-report.txt" wazuh-mcp-server:security-scan || true
    fi
    
    # Docker security checks
    log_info "Running Docker security checks..."
    
    # Check Dockerfile
    if [ -f "$PROJECT_ROOT/Dockerfile" ]; then
        # Check for non-root user
        if grep -q "USER" "$PROJECT_ROOT/Dockerfile"; then
            echo "✅ Dockerfile uses non-root user" > "$container_dir/dockerfile-checks.txt"
        else
            echo "❌ Dockerfile should specify non-root user" > "$container_dir/dockerfile-checks.txt"
        fi
        
        # Check for specific versions
        if grep -q ":latest" "$PROJECT_ROOT/Dockerfile"; then
            echo "❌ Dockerfile uses 'latest' tag" >> "$container_dir/dockerfile-checks.txt"
        else
            echo "✅ Dockerfile uses specific version tags" >> "$container_dir/dockerfile-checks.txt"
        fi
        
        # Check for HEALTHCHECK
        if grep -q "HEALTHCHECK" "$PROJECT_ROOT/Dockerfile"; then
            echo "✅ Dockerfile includes HEALTHCHECK" >> "$container_dir/dockerfile-checks.txt"
        else
            echo "⚠️  Dockerfile should include HEALTHCHECK" >> "$container_dir/dockerfile-checks.txt"
        fi
    fi
    
    # Check docker compose security
    if [ -f "$PROJECT_ROOT/docker compose.yml" ]; then
        log_info "Checking docker compose security..."
        
        # Check for privileged mode
        if grep -q "privileged:" "$PROJECT_ROOT/docker compose.yml"; then
            echo "❌ docker compose.yml uses privileged mode" > "$container_dir/compose-checks.txt"
        else
            echo "✅ docker compose.yml doesn't use privileged mode" > "$container_dir/compose-checks.txt"
        fi
        
        # Check for host network
        if grep -q "network_mode.*host" "$PROJECT_ROOT/docker compose.yml"; then
            echo "❌ docker compose.yml uses host network" >> "$container_dir/compose-checks.txt"
        else
            echo "✅ docker compose.yml uses isolated network" >> "$container_dir/compose-checks.txt"
        fi
        
        # Check for volume mounts
        if grep -q "/:/host" "$PROJECT_ROOT/docker compose.yml"; then
            echo "❌ docker compose.yml mounts host root filesystem" >> "$container_dir/compose-checks.txt"
        else
            echo "✅ docker compose.yml doesn't mount dangerous volumes" >> "$container_dir/compose-checks.txt"
        fi
    fi
    
    if [ "$VERBOSE" = true ]; then
        cat "$container_dir/dockerfile-checks.txt"
        cat "$container_dir/compose-checks.txt"
    fi
    
    log_info "Container scan completed. Results saved to $container_dir"
}

# Infrastructure as Code scanning
run_iac_scan() {
    log_info "Running Infrastructure as Code scanning..."
    
    local iac_dir="$REPORTS_DIR/iac"
    mkdir -p "$iac_dir"
    
    # Check Docker files
    log_info "Scanning Docker configurations..."
    
    # Basic Docker security checks
    if [ -f "$PROJECT_ROOT/Dockerfile" ]; then
        {
            echo "=== Dockerfile Security Analysis ==="
            echo "File: $PROJECT_ROOT/Dockerfile"
            echo ""
            
            # Check for ADD instead of COPY
            if grep -q "^ADD" "$PROJECT_ROOT/Dockerfile"; then
                echo "❌ Use COPY instead of ADD for better security"
            else
                echo "✅ Using COPY instead of ADD"
            fi
            
            # Check for curl/wget without verification
            if grep -q "curl\|wget" "$PROJECT_ROOT/Dockerfile" && ! grep -q "gpg\|sha256" "$PROJECT_ROOT/Dockerfile"; then
                echo "⚠️  Downloads should be verified with checksums"
            fi
            
            # Check for apt-get upgrade
            if grep -q "apt-get upgrade" "$PROJECT_ROOT/Dockerfile"; then
                echo "❌ Avoid apt-get upgrade in Dockerfile"
            else
                echo "✅ Not using apt-get upgrade"
            fi
            
            # Check for secrets in ENV
            if grep -q "ENV.*PASSWORD\|ENV.*SECRET\|ENV.*KEY" "$PROJECT_ROOT/Dockerfile"; then
                echo "❌ Avoid hardcoded secrets in ENV"
            else
                echo "✅ No hardcoded secrets in ENV"
            fi
            
        } > "$iac_dir/dockerfile-analysis.txt"
    fi
    
    # Check docker compose files
    find "$PROJECT_ROOT" -name "docker compose*.yml" -o -name "docker compose*.yaml" | while read -r compose_file; do
        {
            echo "=== Docker Compose Security Analysis ==="
            echo "File: $compose_file"
            echo ""
            
            # Check for exposed ports
            if grep -q "ports:" "$compose_file"; then
                echo "⚠️  Exposed ports found - ensure they're necessary"
                grep -n "ports:" "$compose_file"
            fi
            
            # Check for environment variables
            if grep -q "environment:" "$compose_file"; then
                echo "⚠️  Environment variables found - ensure no secrets"
                grep -A5 "environment:" "$compose_file"
            fi
            
            # Check for privileged containers
            if grep -q "privileged:" "$compose_file"; then
                echo "❌ Privileged containers found"
                grep -n "privileged:" "$compose_file"
            fi
            
            # Check for host network
            if grep -q "network_mode.*host" "$compose_file"; then
                echo "❌ Host network mode found"
                grep -n "network_mode.*host" "$compose_file"
            fi
            
        } > "$iac_dir/compose-analysis-$(basename "$compose_file").txt"
    done
    
    # Check Kubernetes files if present
    if find "$PROJECT_ROOT" -name "*.yaml" -o -name "*.yml" | grep -q "k8s\|kubernetes"; then
        log_info "Kubernetes configurations found - basic security check..."
        
        find "$PROJECT_ROOT" -name "*.yaml" -o -name "*.yml" | grep "k8s\|kubernetes" | while read -r k8s_file; do
            {
                echo "=== Kubernetes Security Analysis ==="
                echo "File: $k8s_file"
                echo ""
                
                # Check for privileged containers
                if grep -q "privileged.*true" "$k8s_file"; then
                    echo "❌ Privileged containers found"
                fi
                
                # Check for host network
                if grep -q "hostNetwork.*true" "$k8s_file"; then
                    echo "❌ Host network found"
                fi
                
                # Check for host PID
                if grep -q "hostPID.*true" "$k8s_file"; then
                    echo "❌ Host PID namespace found"
                fi
                
                # Check for security context
                if grep -q "securityContext" "$k8s_file"; then
                    echo "✅ Security context found"
                else
                    echo "⚠️  Security context should be defined"
                fi
                
            } > "$iac_dir/k8s-analysis-$(basename "$k8s_file").txt"
        done
    fi
    
    if [ "$VERBOSE" = true ]; then
        find "$iac_dir" -name "*.txt" -exec cat {} \;
    fi
    
    log_info "IaC scan completed. Results saved to $iac_dir"
}

# License compliance check
run_license_scan() {
    log_info "Running license compliance check..."
    
    local license_dir="$REPORTS_DIR/licenses"
    mkdir -p "$license_dir"
    
    # Check package licenses
    log_info "Checking Python package licenses..."
    pip-licenses --format=json --output-file="$license_dir/python-licenses.json" || true
    pip-licenses --format=plain-vertical --output-file="$license_dir/python-licenses.txt" || true
    
    # Check for GPL licenses (potential issues)
    log_info "Checking for GPL licenses..."
    {
        echo "=== GPL License Check ==="
        grep -i "gpl\|gnu" "$license_dir/python-licenses.txt" || echo "No GPL licenses found"
        echo ""
        
        echo "=== Commercial License Check ==="
        grep -i "commercial\|proprietary" "$license_dir/python-licenses.txt" || echo "No commercial licenses found"
        echo ""
        
        echo "=== Unknown License Check ==="
        grep -i "unknown\|none" "$license_dir/python-licenses.txt" || echo "No unknown licenses found"
        
    } > "$license_dir/license-analysis.txt"
    
    # Check project license
    if [ -f "$PROJECT_ROOT/LICENSE" ]; then
        cp "$PROJECT_ROOT/LICENSE" "$license_dir/project-license.txt"
        echo "✅ Project license found" >> "$license_dir/license-analysis.txt"
    else
        echo "❌ Project license not found" >> "$license_dir/license-analysis.txt"
    fi
    
    if [ "$VERBOSE" = true ]; then
        cat "$license_dir/license-analysis.txt"
    fi
    
    log_info "License scan completed. Results saved to $license_dir"
}

# Quick security scan
run_quick_scan() {
    log_info "Running quick security scan..."
    
    local quick_dir="$REPORTS_DIR/quick"
    mkdir -p "$quick_dir"
    
    # Essential checks only
    log_info "Running essential security checks..."
    
    # Check for obvious secrets
    grep -r "password\|secret\|key" --include="*.py" --include="*.yml" "$PROJECT_ROOT" | grep -v "example\|test" > "$quick_dir/potential-secrets.txt" || true
    
    # Check for SQL injection patterns
    grep -r "execute.*format\|query.*%" --include="*.py" "$PROJECT_ROOT" > "$quick_dir/sql-injection.txt" || true
    
    # Check for unsafe deserialization
    grep -r "pickle\|yaml\.load\|eval\|exec" --include="*.py" "$PROJECT_ROOT" > "$quick_dir/unsafe-patterns.txt" || true
    
    # Check permissions
    find "$PROJECT_ROOT" -name "*.sh" -type f ! -perm 755 > "$quick_dir/permission-issues.txt" || true
    
    # Quick dependency check
    safety check --short-report --output "$quick_dir/safety-quick.txt" || true
    
    # Summary
    {
        echo "=== Quick Security Scan Summary ==="
        echo "Date: $(date)"
        echo ""
        
        echo "Potential secrets found: $(wc -l < "$quick_dir/potential-secrets.txt")"
        echo "SQL injection patterns: $(wc -l < "$quick_dir/sql-injection.txt")"
        echo "Unsafe patterns: $(wc -l < "$quick_dir/unsafe-patterns.txt")"
        echo "Permission issues: $(wc -l < "$quick_dir/permission-issues.txt")"
        
    } > "$quick_dir/quick-summary.txt"
    
    if [ "$VERBOSE" = true ]; then
        cat "$quick_dir/quick-summary.txt"
    fi
    
    log_info "Quick scan completed. Results saved to $quick_dir"
}

# Generate security report
generate_security_report() {
    if [ "$GENERATE_REPORT" = false ]; then
        log_info "Skipping report generation"
        return
    fi
    
    log_info "Generating security report..."
    
    local report_file="$REPORTS_DIR/security-report.html"
    local timestamp=$(date)
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Wazuh MCP Server Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .high { color: #d32f2f; }
        .medium { color: #f57c00; }
        .low { color: #388e3c; }
        .info { color: #1976d2; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .summary { background-color: #e3f2fd; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Wazuh MCP Server Security Report</h1>
        <p><strong>Generated:</strong> $timestamp</p>
        <p><strong>Scan Type:</strong> $SCAN_TYPE</p>
        <p><strong>Project:</strong> $(basename "$PROJECT_ROOT")</p>
    </div>
EOF
    
    # Add scan results
    for scan_dir in "$REPORTS_DIR"/*; do
        if [ -d "$scan_dir" ]; then
            local scan_name=$(basename "$scan_dir")
            echo "<div class=\"section\">" >> "$report_file"
            echo "<h2>$scan_name Results</h2>" >> "$report_file"
            
            # Add summary files
            find "$scan_dir" -name "*.txt" -type f | while read -r file; do
                echo "<h3>$(basename "$file")</h3>" >> "$report_file"
                echo "<pre>" >> "$report_file"
                cat "$file" | head -50 >> "$report_file"
                echo "</pre>" >> "$report_file"
            done
            
            echo "</div>" >> "$report_file"
        fi
    done
    
    # Close HTML
    echo "</body></html>" >> "$report_file"
    
    log_info "Security report generated: $report_file"
}

# Send notification
send_notification() {
    if [ "$SEND_NOTIFICATION" = false ]; then
        return
    fi
    
    log_info "Sending security scan notification..."
    
    local summary="Security scan completed for $(basename "$PROJECT_ROOT")"
    local report_count=$(find "$REPORTS_DIR" -name "*.txt" -type f | wc -l)
    
    # Simple notification (can be extended)
    echo "Security Scan Complete" | mail -s "Wazuh MCP Security Scan" "${NOTIFICATION_EMAIL:-admin@localhost}" || true
    
    log_info "Notification sent"
}

# Main execution
main() {
    log_info "Starting Wazuh MCP Server Security Scanner"
    log_info "Scan type: $SCAN_TYPE"
    log_info "Project root: $PROJECT_ROOT"
    log_info "Reports directory: $REPORTS_DIR"
    
    setup_environment
    
    case $SCAN_TYPE in
        "all")
            run_sast_scan
            run_dependency_scan
            run_secrets_scan
            run_container_scan
            run_iac_scan
            run_license_scan
            ;;
        "sast")
            run_sast_scan
            ;;
        "deps")
            run_dependency_scan
            ;;
        "secrets")
            run_secrets_scan
            ;;
        "container")
            run_container_scan
            ;;
        "iac")
            run_iac_scan
            ;;
        "licenses")
            run_license_scan
            ;;
        "quick")
            run_quick_scan
            ;;
        *)
            log_error "Unknown scan type: $SCAN_TYPE"
            exit 1
            ;;
    esac
    
    generate_security_report
    send_notification
    
    log_info "Security scanning completed successfully"
    log_info "Reports available in: $REPORTS_DIR"
    
    # Check for high severity issues if requested
    if [ "$FAIL_ON_HIGH" = true ]; then
        local high_issues=$(find "$REPORTS_DIR" -name "*.txt" -type f -exec grep -l "HIGH\|CRITICAL\|❌" {} \; 2>/dev/null | wc -l)
        if [ "$high_issues" -gt 0 ]; then
            log_error "High severity security issues found. Failing build."
            exit 1
        fi
    fi
}

# Parse arguments and run
parse_args "$@"
main