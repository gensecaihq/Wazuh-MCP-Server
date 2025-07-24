#!/bin/bash
# Test Deployment Script for Wazuh MCP Server v3.0.0
# ===================================================
# Comprehensive testing for production deployment

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_test() {
    echo -e "${BLUE}[TEST]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Test result functions
test_pass() {
    ((TESTS_PASSED++))
    ((TESTS_TOTAL++))
    echo -e "${GREEN}✅ PASS${NC} - $1"
}

test_fail() {
    ((TESTS_FAILED++))
    ((TESTS_TOTAL++))
    echo -e "${RED}❌ FAIL${NC} - $1"
}

# Test functions
test_docker_prerequisites() {
    log_test "Testing Docker prerequisites..."
    
    # Test Docker
    if command -v docker &> /dev/null; then
        test_pass "Docker is installed"
    else
        test_fail "Docker is not installed"
        return 1
    fi
    
    # Test Docker daemon
    if docker info &> /dev/null; then
        test_pass "Docker daemon is running"
    else
        test_fail "Docker daemon is not running"
        return 1
    fi
    
    # Test Docker Compose
    if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
        test_pass "Docker Compose is available"
    else
        test_fail "Docker Compose is not available"
        return 1
    fi
    
    return 0
}

test_build_process() {
    log_test "Testing Docker build process..."
    
    # Test minimal build
    if docker-compose -f docker-compose.minimal.yml build --no-cache &> /tmp/build.log; then
        test_pass "Docker build successful"
    else
        test_fail "Docker build failed"
        log_error "Build log:"
        cat /tmp/build.log | tail -20
        return 1
    fi
    
    return 0
}

test_container_startup() {
    log_test "Testing container startup..."
    
    # Set minimal test environment
    export WAZUH_API_URL="https://test-wazuh:55000"
    export WAZUH_API_USERNAME="test-user"
    export WAZUH_API_PASSWORD="test-password"
    export MCP_SERVER_MODE="remote"
    export OAUTH_ENABLED="false"
    export ENABLE_METRICS="false"
    
    # Start minimal stack
    if docker-compose -f docker-compose.minimal.yml up -d &> /tmp/startup.log; then
        test_pass "Container startup successful"
    else
        test_fail "Container startup failed"
        log_error "Startup log:"
        cat /tmp/startup.log | tail -20
        return 1
    fi
    
    # Wait for container to be ready
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if docker-compose -f docker-compose.minimal.yml ps | grep -q "healthy\|Up"; then
            test_pass "Container is running"
            break
        fi
        
        if [[ $attempt -eq $max_attempts ]]; then
            test_fail "Container failed to start within timeout"
            return 1
        fi
        
        sleep 2
        ((attempt++))
    done
    
    return 0
}

test_health_endpoint() {
    log_test "Testing health endpoint..."
    
    local max_attempts=20
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -f -k -s "https://localhost:8443/health" &> /dev/null; then
            test_pass "Health endpoint responds"
            
            # Test health response content
            local health_response=$(curl -f -k -s "https://localhost:8443/health")
            if echo "$health_response" | grep -q "healthy\|ok\|status"; then
                test_pass "Health endpoint returns valid response"
            else
                test_fail "Health endpoint returns invalid response"
            fi
            return 0
        fi
        
        if [[ $attempt -eq $max_attempts ]]; then
            test_fail "Health endpoint not responding"
            return 1
        fi
        
        sleep 3
        ((attempt++))
    done
}

test_container_logs() {
    log_test "Testing container logs..."
    
    # Check for error patterns in logs
    local logs=$(docker-compose -f docker-compose.minimal.yml logs --tail=50 2>&1)
    
    if echo "$logs" | grep -qi "error\|exception\|failed\|fatal"; then
        test_fail "Container logs contain errors"
        echo "Error logs:"
        echo "$logs" | grep -i "error\|exception\|failed\|fatal" | head -5
    else
        test_pass "Container logs are clean"
    fi
    
    # Check for successful startup patterns
    if echo "$logs" | grep -qi "server.*start\|listening\|ready"; then
        test_pass "Container shows successful startup"
    else
        test_fail "Container does not show successful startup"
    fi
    
    return 0
}

test_self_contained_mode() {
    log_test "Testing self-contained mode..."
    
    # Check that no local files are being mounted
    local volumes=$(docker-compose -f docker-compose.minimal.yml config | grep -A 20 "volumes:" | grep -v "driver: local")
    
    if echo "$volumes" | grep -q "\\./"; then
        test_fail "Local file mounts detected - not self-contained"
        echo "Local mounts found:"
        echo "$volumes" | grep "\\."
    else
        test_pass "No local file dependencies found"
    fi
    
    # Check that configuration is auto-generated
    local config_logs=$(docker-compose -f docker-compose.minimal.yml logs | grep -i "generat\|config\|self-contained")
    if [[ -n "$config_logs" ]]; then
        test_pass "Auto-configuration is working"
    else
        test_fail "No evidence of auto-configuration"
    fi
    
    return 0
}

test_backward_compatibility() {
    log_test "Testing v2.0.0 backward compatibility..."
    
    # Test stdio mode detection
    export MCP_SERVER_MODE="auto"
    export CLAUDE_DESKTOP_CONFIG="true"
    
    # Restart container with stdio detection
    docker-compose -f docker-compose.minimal.yml restart &> /dev/null
    sleep 10
    
    # Check logs for stdio mode activation
    local stdio_logs=$(docker-compose -f docker-compose.minimal.yml logs | grep -i "stdio\|v2\|compatibility")
    if [[ -n "$stdio_logs" ]]; then
        test_pass "v2.0.0 compatibility mode detected"
    else
        test_warn "v2.0.0 compatibility mode not explicitly tested"
    fi
    
    return 0
}

test_resource_usage() {
    log_test "Testing resource usage..."
    
    # Get container stats
    local stats=$(docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" | grep wazuh-mcp)
    
    if [[ -n "$stats" ]]; then
        test_pass "Container resource stats available"
        echo "Resource usage:"
        echo "$stats"
        
        # Check if within reasonable limits
        local memory=$(echo "$stats" | awk '{print $3}' | grep -o '[0-9.]*' | head -1)
        if (( $(echo "$memory < 512" | bc -l) )); then
            test_pass "Memory usage within limits (<512MB)"
        else
            test_fail "Memory usage too high (>512MB)"
        fi
    else
        test_fail "Cannot retrieve container resource stats"
    fi
    
    return 0
}

test_security_hardening() {
    log_test "Testing security hardening..."
    
    # Check container runs as non-root
    local user_info=$(docker-compose -f docker-compose.minimal.yml exec -T wazuh-mcp-server-minimal whoami 2>/dev/null || echo "failed")
    if [[ "$user_info" == "wazuh-mcp" ]]; then
        test_pass "Container runs as non-root user"
    else
        test_fail "Container may be running as root"
    fi
    
    # Check read-only filesystem (where applicable)
    local mount_info=$(docker inspect wazuh-mcp-server-minimal | grep -i readonly || echo "")
    if [[ -n "$mount_info" ]]; then
        test_pass "Read-only filesystem configuration found"
    else
        test_warn "Read-only filesystem not verified"
    fi
    
    return 0
}

# Cleanup function
cleanup_test() {
    log_info "Cleaning up test environment..."
    
    # Stop containers
    docker-compose -f docker-compose.minimal.yml down &> /dev/null || true
    
    # Remove test logs
    rm -f /tmp/build.log /tmp/startup.log
    
    log_info "Cleanup completed"
}

test_warn() {
    echo -e "${YELLOW}⚠️  WARN${NC} - $1"
}

# Main test execution
main() {
    log_info "Starting Wazuh MCP Server v3.0.0 Deployment Tests"
    echo "=========================================================="
    
    # Cleanup any existing test environment
    cleanup_test
    
    # Run test suites
    echo
    log_info "Phase 1: Prerequisites"
    test_docker_prerequisites || exit 1
    
    echo
    log_info "Phase 2: Build Process"
    test_build_process || exit 1
    
    echo
    log_info "Phase 3: Container Startup"
    test_container_startup || exit 1
    
    echo
    log_info "Phase 4: Health Checks"
    test_health_endpoint
    
    echo
    log_info "Phase 5: Log Analysis"
    test_container_logs
    
    echo
    log_info "Phase 6: Self-Contained Mode"
    test_self_contained_mode
    
    echo
    log_info "Phase 7: Backward Compatibility"
    test_backward_compatibility
    
    echo
    log_info "Phase 8: Resource Usage"
    test_resource_usage
    
    echo
    log_info "Phase 9: Security Hardening"
    test_security_hardening
    
    # Show final results
    echo
    echo "=========================================================="
    log_info "Test Results Summary"
    echo "Total Tests: $TESTS_TOTAL"
    echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo
        echo -e "${GREEN}🎉 ALL TESTS PASSED!${NC}"
        echo "✅ Deployment is ready for production"
        cleanup_test
        exit 0
    else
        echo
        echo -e "${RED}❌ SOME TESTS FAILED${NC}"
        echo "Please review the failures above before deploying to production"
        
        # Show container logs for debugging
        echo
        log_info "Container logs for debugging:"
        docker-compose -f docker-compose.minimal.yml logs --tail=20
        
        cleanup_test
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    "--cleanup")
        cleanup_test
        exit 0
        ;;
    "--help"|"-h")
        echo "Wazuh MCP Server v3.0.0 Deployment Test Script"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --cleanup    Clean up test environment"
        echo "  --help, -h   Show this help message"
        echo
        echo "This script tests:"
        echo "  - Docker prerequisites"
        echo "  - Build process"
        echo "  - Container startup"
        echo "  - Health endpoints"
        echo "  - Log analysis"
        echo "  - Self-contained mode"
        echo "  - Backward compatibility"
        echo "  - Resource usage"
        echo "  - Security hardening"
        exit 0
        ;;
    *)
        main
        ;;
esac