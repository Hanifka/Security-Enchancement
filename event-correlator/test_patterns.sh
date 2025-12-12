#!/bin/bash

# Event Correlation Engine Test Script
# This script provides quick testing capabilities for the event correlation patterns

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORRELATOR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE} Event Correlation Engine Tests ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python3 is required but not installed."
        exit 1
    fi
    
    if ! python3 -c "import yaml" 2>/dev/null; then
        log_warning "PyYAML not installed. Installing..."
        pip3 install PyYAML
    fi
    
    log_success "Dependencies check passed"
}

setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Create test directories
    mkdir -p /tmp/test_correlator
    
    # Install correlator in development mode
    cd "$CORRELATOR_DIR"
    if [ -f "setup.py" ]; then
        pip3 install -e . >/dev/null 2>&1 || log_warning "Could not install correlator package"
    fi
    
    log_success "Test environment setup complete"
}

run_dry_run_test() {
    log_info "Running dry-run test with sample events..."
    
    # Create a test configuration
    cat > /tmp/test_correlator/test_config.yaml << 'EOF'
input:
  files:
    - /tmp/test_correlator/sample_events.jsonl
  poll_interval: 0.1

output:
  default_file: /tmp/test_correlator/test_output.jsonl

database:
  path: /tmp/test_correlator/test_state.db

rules:
  - name: "brute_force_test"
    pattern_type: "threshold"
    description: "Test brute force detection"
    enabled: true
    conditions:
      - field: "data.event_type"
        equals: "ssh_login"
      - field: "data.status"
        equals: "failed"
    window: 300
    min_occurrences: 3
    entity_path: "data.srcip"
    timestamp_path: "timestamp"
    ttl: 3600

  - name: "privilege_escalation_test"
    pattern_type: "threshold"
    description: "Test privilege escalation detection"
    enabled: true
    conditions:
      - field: "data.event_type"
        equals: "privilege_escalation"
    window: 600
    min_occurrences: 1
    entity_path: "data.user"
    timestamp_path: "timestamp"
    ttl: 3600

logging:
  level: INFO
  file: /tmp/test_correlator/test.log
EOF

    # Copy sample events
    cp "$CORRELATOR_DIR/examples/sample_events.jsonl" /tmp/test_correlator/sample_events.jsonl
    
    # Run correlator in background
    cd "$CORRELATOR_DIR"
    timeout 30 python3 correlator.py /tmp/test_correlator/test_config.yaml --dry-run --debug > /tmp/test_correlator/output.log 2>&1 &
    CORRELATOR_PID=$!
    
    # Wait for processing
    sleep 5
    
    # Check if patterns triggered
    if grep -q "Correlation match" /tmp/test_correlator/output.log; then
        log_success "Patterns triggered successfully!"
        log_info "Correlator output:"
        grep "Correlation match" /tmp/test_correlator/output.log | head -5
    else
        log_warning "No correlations detected (this might be normal for sample data)"
    fi
    
    # Kill correlator
    kill $CORRELATOR_PID 2>/dev/null || true
    wait $CORRELATOR_PID 2>/dev/null || true
}

test_specific_patterns() {
    log_info "Testing specific correlation patterns..."
    
    # Test brute force detection
    log_info "Testing brute force pattern..."
    cat > /tmp/test_correlator/brute_force_test.yaml << 'EOF'
input:
  files:
    - /tmp/test_correlator/sample_events.jsonl
  poll_interval: 0.1

output:
  default_file: /tmp/test_correlator/brute_force_output.jsonl

database:
  path: /tmp/test_correlator/brute_force_state.db

rules:
  - name: "ssh_brute_force"
    pattern_type: "threshold"
    description: "Detect SSH brute force"
    enabled: true
    conditions:
      - field: "data.event_type"
        equals: "ssh_login"
      - field: "data.status"
        equals: "failed"
    window: 300
    min_occurrences: 3
    entity_path: "data.srcip"
    timestamp_path: "timestamp"
    ttl: 3600

logging:
  level: WARNING
EOF

    # Run brute force test
    cd "$CORRELATOR_DIR"
    timeout 10 python3 correlator.py /tmp/test_correlator/brute_force_test.yaml >/dev/null 2>&1
    
    if [ -f "/tmp/test_correlator/brute_force_output.jsonl" ]; then
        MATCHES=$(wc -l < /tmp/test_correlator/brute_force_output.jsonl)
        log_success "Brute force test generated $MATCHES correlations"
        if [ $MATCHES -gt 0 ]; then
            echo "Sample output:"
            head -2 /tmp/test_correlator/brute_force_output.jsonl | python3 -m json.tool
        fi
    else
        log_warning "No output file created for brute force test"
    fi
}

test_state_management() {
    log_info "Testing state management..."
    
    # Test reset functionality
    cd "$CORRELATOR_DIR"
    python3 correlator.py --reset
    
    if [ ! -f "/tmp/test_correlator/test_state.db" ]; then
        log_success "State reset completed successfully"
    else
        log_warning "State database still exists"
    fi
    
    # Test with persistence
    log_info "Testing state persistence..."
    
    cat > /tmp/test_correlator/persistence_test.yaml << 'EOF'
input:
  files:
    - /tmp/test_correlator/sample_events.jsonl
  poll_interval: 0.1

output:
  default_file: /tmp/test_correlator/persistence_output.jsonl

database:
  path: /tmp/test_correlator/persistence_state.db

rules:
  - name: "state_test"
    pattern_type: "threshold"
    description: "Test state persistence"
    enabled: true
    conditions:
      - field: "data.event_type"
        equals: "ssh_login"
    window: 3600
    min_occurrences: 1
    entity_path: "data.srcip"
    timestamp_path: "timestamp"
    ttl: 3600

logging:
  level: WARNING
EOF

    # Run persistence test
    timeout 5 python3 correlator.py /tmp/test_correlator/persistence_test.yaml >/dev/null 2>&1
    
    # Check if database was created
    if [ -f "/tmp/test_correlator/persistence_state.db" ]; then
        log_success "State database created successfully"
        # Check database content
        TABLES=$(sqlite3 /tmp/test_correlator/persistence_state.db ".tables" 2>/dev/null || echo "")
        if [[ $TABLES == *"event_state"* ]]; then
            log_success "Database tables created correctly"
        fi
    else
        log_warning "State database not created"
    fi
}

validate_configuration() {
    log_info "Validating configuration files..."
    
    # Test main config
    if python3 -c "
import yaml
with open('$CORRELATOR_DIR/config.yaml') as f:
    yaml.safe_load(f)
print('Main config valid')
"; then
        log_success "Main configuration is valid"
    else
        log_error "Main configuration has errors"
    fi
    
    # Test example configs
    for config in "$CORRELATOR_DIR/examples"/*.yaml; do
        if [ -f "$config" ]; then
            if python3 -c "
import yaml
with open('$config') as f:
    yaml.safe_load(f)
print(f'$config valid')
"; then
                log_success "$(basename "$config") configuration is valid"
            else
                log_error "$(basename "$config") configuration has errors"
            fi
        fi
    done
}

cleanup() {
    log_info "Cleaning up test files..."
    rm -rf /tmp/test_correlator
    log_success "Cleanup completed"
}

show_results_summary() {
    echo
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE} Test Results Summary ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
    echo "All tests completed. Check the logs above for detailed results."
    echo
    echo -e "${YELLOW}Next Steps:${NC}"
    echo "1. Review correlation outputs in /tmp/test_correlator/"
    echo "2. Test with your own log files by updating input.files in config"
    echo "3. Customize rules in config.yaml for your environment"
    echo "4. Set up systemd service for production deployment"
    echo "5. Integrate with your SIEM/alerting system"
    echo
    echo -e "${GREEN}Copy-paste commands for manual testing:${NC}"
    echo
    echo "# Test with debug output"
    echo "cd $CORRELATOR_DIR"
    echo "python3 correlator.py config.yaml --debug"
    echo
    echo "# Test in dry-run mode"
    echo "cd $CORRELATOR_DIR"
    echo "python3 correlator.py config.yaml --dry-run"
    echo
    echo "# Reset state database"
    echo "cd $CORRELATOR_DIR"
    echo "python3 correlator.py --reset"
    echo
    echo "# Test specific configuration"
    echo "cd $CORRELATOR_DIR"
    echo "python3 correlator.py examples/config_brute_force.yaml --debug"
    echo
    echo "# Monitor output files"
    echo "tail -f /tmp/*_correlations.jsonl"
    echo
    echo "# Check logs"
    echo "tail -f /var/log/correlator.log"
}

# Main execution
main() {
    show_header
    
    case "${1:-all}" in
        "deps")
            check_dependencies
            ;;
        "setup")
            setup_test_environment
            ;;
        "dry-run")
            run_dry_run_test
            ;;
        "patterns")
            test_specific_patterns
            ;;
        "state")
            test_state_management
            ;;
        "config")
            validate_configuration
            ;;
        "cleanup")
            cleanup
            ;;
        "all")
            check_dependencies
            setup_test_environment
            validate_configuration
            run_dry_run_test
            test_specific_patterns
            test_state_management
            show_results_summary
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [command]"
            echo
            echo "Commands:"
            echo "  all        Run all tests (default)"
            echo "  deps       Check dependencies only"
            echo "  setup      Setup test environment only"
            echo "  dry-run    Test correlation patterns in dry-run mode"
            echo "  patterns   Test specific correlation patterns"
            echo "  state      Test state management functionality"
            echo "  config     Validate configuration files"
            echo "  cleanup    Clean up test files"
            echo "  help       Show this help message"
            echo
            echo "Examples:"
            echo "  $0                    # Run all tests"
            echo "  $0 dry-run           # Test patterns only"
            echo "  $0 config            # Validate configs only"
            echo "  $0 cleanup           # Clean up test files"
            ;;
        *)
            log_error "Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Trap cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"