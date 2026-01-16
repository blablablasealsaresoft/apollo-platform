#!/bin/bash
#
# Apollo Platform - Stress Testing Runner Script
#
# This script runs k6 stress tests against the Apollo platform.
# Designed to push the system beyond normal capacity to find limits.
#
# Usage:
#   ./run-stress-tests.sh [options]
#
# Options:
#   -t, --test       Test type: api, concurrent, database, all (default: all)
#   -i, --intensity  Intensity: medium, high, extreme, breaking (default: high)
#   -s, --scenario   Scenario for concurrent users: standard, peak, burst, breaking (default: peak)
#   -u, --url        API base URL (default: http://localhost:3000/api)
#   -o, --output     Output directory for results (default: ./results)
#   -h, --help       Show this help message
#
# Examples:
#   ./run-stress-tests.sh                           # Run all tests with defaults
#   ./run-stress-tests.sh -t api -i extreme         # Run extreme API stress test
#   ./run-stress-tests.sh -t concurrent -s breaking # Find concurrent user limit
#   ./run-stress-tests.sh -t database               # Run database stress tests
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Default values
TEST_TYPE="all"
INTENSITY="high"
SCENARIO="peak"
API_URL="http://localhost:3000/api"
OUTPUT_DIR="./results"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="${SCRIPT_DIR}/../performance-tests"

# Function to display usage
usage() {
    echo "Apollo Platform - Stress Testing Runner"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -t, --test       Test type: api, concurrent, database, all (default: all)"
    echo "  -i, --intensity  Intensity: medium, high, extreme, breaking (default: high)"
    echo "  -s, --scenario   Scenario for concurrent users: standard, peak, burst, breaking (default: peak)"
    echo "  -u, --url        API base URL (default: http://localhost:3000/api)"
    echo "  -o, --output     Output directory for results (default: ./results)"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Warning Levels:"
    echo "  medium   - 200 VUs peak, moderate stress"
    echo "  high     - 500 VUs peak, significant stress"
    echo "  extreme  - 1000 VUs peak, extreme stress"
    echo "  breaking - Finds system breaking point"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run all tests with defaults"
    echo "  $0 -t api -i extreme                  # Run extreme API stress test"
    echo "  $0 -t concurrent -s breaking          # Find concurrent user limit"
    echo "  $0 -t database                        # Run database stress tests"
    exit 0
}

# Function to print colored messages
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

log_stress() {
    echo -e "${PURPLE}[STRESS]${NC} $1"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--test)
            TEST_TYPE="$2"
            shift 2
            ;;
        -i|--intensity)
            INTENSITY="$2"
            shift 2
            ;;
        -s|--scenario)
            SCENARIO="$2"
            shift 2
            ;;
        -u|--url)
            API_URL="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate intensity
valid_intensities=("medium" "high" "extreme" "breaking")
if [[ ! " ${valid_intensities[@]} " =~ " ${INTENSITY} " ]]; then
    log_error "Invalid intensity: ${INTENSITY}"
    echo "Valid intensities: ${valid_intensities[*]}"
    exit 1
fi

# Validate concurrent user scenarios
valid_scenarios=("smoke" "standard" "peak" "burst" "sustained" "breaking")
if [[ ! " ${valid_scenarios[@]} " =~ " ${SCENARIO} " ]]; then
    log_error "Invalid scenario: ${SCENARIO}"
    echo "Valid scenarios: ${valid_scenarios[*]}"
    exit 1
fi

# Check if k6 is installed
if ! command -v k6 &> /dev/null; then
    log_error "k6 is not installed. Please install it first:"
    echo "  - macOS: brew install k6"
    echo "  - Linux: snap install k6"
    echo "  - Windows: choco install k6"
    echo "  - Docker: docker pull grafana/k6"
    exit 1
fi

# Create output directory
mkdir -p "${OUTPUT_DIR}"
mkdir -p "${TESTS_DIR}/results"

# Print configuration
echo ""
echo "========================================"
echo "  Apollo Platform Stress Test Runner"
echo "========================================"
echo ""
log_stress "This test will push your system beyond normal capacity!"
echo ""
log_info "Test Type: ${TEST_TYPE}"
log_info "Intensity: ${INTENSITY}"
log_info "Concurrent Scenario: ${SCENARIO}"
log_info "API URL: ${API_URL}"
log_info "Output Directory: ${OUTPUT_DIR}"
echo ""

# Warning for extreme tests
if [ "$INTENSITY" == "extreme" ] || [ "$INTENSITY" == "breaking" ] || [ "$SCENARIO" == "breaking" ]; then
    log_warning "You are about to run an extreme stress test!"
    log_warning "This may cause service degradation or failures."
    log_warning "Ensure you have proper monitoring in place."
    echo ""
    read -p "Are you sure you want to continue? (yes/no) " -r
    echo
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        log_info "Test cancelled."
        exit 0
    fi
fi

# Health check
log_info "Checking API health..."
health_response=$(curl -s -o /dev/null -w "%{http_code}" "${API_URL}/health" 2>/dev/null || echo "000")
if [ "$health_response" != "200" ]; then
    log_warning "API health check failed (HTTP ${health_response}). Tests may fail."
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    log_success "API is healthy"
fi

# Record system baseline before stress test
log_info "Recording baseline metrics..."
baseline_file="${OUTPUT_DIR}/baseline-$(date +%Y%m%d-%H%M%S).txt"
{
    echo "=== Baseline Metrics ==="
    echo "Timestamp: $(date)"
    echo ""
    echo "=== API Response Time ==="
    for i in {1..5}; do
        curl -s -o /dev/null -w "Request $i: %{time_total}s\n" "${API_URL}/health" 2>/dev/null || echo "Request $i: Failed"
    done
} > "${baseline_file}"
log_success "Baseline recorded: ${baseline_file}"

# Function to run a single stress test
run_stress_test() {
    local test_name=$1
    local test_file=$2
    local env_vars=$3

    log_stress "Starting ${test_name} stress test..."

    local start_time=$(date +%s)
    local result_file="${OUTPUT_DIR}/${test_name}-stress-$(date +%Y%m%d-%H%M%S).json"

    if k6 run \
        --env API_URL="${API_URL}" \
        ${env_vars} \
        --out json="${result_file}" \
        "${test_file}"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_success "${test_name} stress test completed in ${duration}s"
        return 0
    else
        log_error "${test_name} stress test failed"
        return 1
    fi
}

# Track test results
total_tests=0
passed_tests=0
failed_tests=0
declare -a failed_test_names

# Run tests based on type
case $TEST_TYPE in
    api)
        ((total_tests++))
        if run_stress_test "api" "${TESTS_DIR}/stress-tests/api-stress.js" "--env INTENSITY=${INTENSITY}"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("api-stress")
        fi
        ;;
    concurrent)
        ((total_tests++))
        if run_stress_test "concurrent-users" "${TESTS_DIR}/stress-tests/concurrent-users.js" "--env SCENARIO=${SCENARIO}"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("concurrent-users")
        fi
        ;;
    database)
        # Run both PostgreSQL and TimescaleDB stress tests
        log_info "Running database stress tests..."
        echo ""

        # PostgreSQL stress
        ((total_tests++))
        if run_stress_test "postgresql" "${TESTS_DIR}/database/postgresql-perf.js" "--env SCENARIO=stress"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("postgresql")
        fi
        echo ""

        # TimescaleDB stress
        ((total_tests++))
        if run_stress_test "timescale" "${TESTS_DIR}/database/timescale-perf.js" "--env SCENARIO=stress"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("timescale")
        fi
        ;;
    all)
        # Run all stress tests
        log_stress "Running all stress tests sequentially..."
        echo ""

        # API stress test
        ((total_tests++))
        if run_stress_test "api" "${TESTS_DIR}/stress-tests/api-stress.js" "--env INTENSITY=${INTENSITY}"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("api-stress")
        fi
        echo ""

        # Concurrent users test
        ((total_tests++))
        if run_stress_test "concurrent-users" "${TESTS_DIR}/stress-tests/concurrent-users.js" "--env SCENARIO=${SCENARIO}"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("concurrent-users")
        fi
        echo ""

        # PostgreSQL stress
        ((total_tests++))
        if run_stress_test "postgresql" "${TESTS_DIR}/database/postgresql-perf.js" "--env SCENARIO=stress"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("postgresql")
        fi
        echo ""

        # TimescaleDB stress
        ((total_tests++))
        if run_stress_test "timescale" "${TESTS_DIR}/database/timescale-perf.js" "--env SCENARIO=stress"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("timescale")
        fi
        ;;
    *)
        log_error "Invalid test type: ${TEST_TYPE}"
        echo "Valid test types: api, concurrent, database, all"
        exit 1
        ;;
esac

# Record post-stress metrics
log_info "Recording post-stress metrics..."
poststress_file="${OUTPUT_DIR}/post-stress-$(date +%Y%m%d-%H%M%S).txt"
{
    echo "=== Post-Stress Metrics ==="
    echo "Timestamp: $(date)"
    echo ""
    echo "=== API Response Time ==="
    for i in {1..5}; do
        curl -s -o /dev/null -w "Request $i: %{time_total}s\n" "${API_URL}/health" 2>/dev/null || echo "Request $i: Failed"
    done
} > "${poststress_file}"
log_success "Post-stress metrics recorded: ${poststress_file}"

# Print summary
echo ""
echo "========================================"
echo "       Stress Test Summary"
echo "========================================"
echo ""
log_info "Total Tests: ${total_tests}"
log_success "Passed: ${passed_tests}"
if [ $failed_tests -gt 0 ]; then
    log_error "Failed: ${failed_tests}"
    echo ""
    log_error "Failed tests: ${failed_test_names[*]}"
else
    log_success "All stress tests passed!"
fi
echo ""
log_info "Results saved to: ${OUTPUT_DIR}"
log_info "Baseline: ${baseline_file}"
log_info "Post-stress: ${poststress_file}"
echo ""

# Recommendations based on results
echo "========================================"
echo "       Recommendations"
echo "========================================"
echo ""
if [ $failed_tests -gt 0 ]; then
    log_warning "Some tests failed. Review the results for:"
    echo "  - Response time degradation"
    echo "  - Error rate increases"
    echo "  - Resource exhaustion"
    echo "  - Connection pool limits"
else
    log_success "System handled stress test successfully."
    echo "Consider running with higher intensity to find limits."
fi
echo ""

# Exit with appropriate code
if [ $failed_tests -gt 0 ]; then
    exit 1
else
    exit 0
fi
