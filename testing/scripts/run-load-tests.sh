#!/bin/bash
#
# Apollo Platform - Load Testing Runner Script
#
# This script runs k6 load tests against the Apollo platform.
# Supports multiple test types and scenarios.
#
# Usage:
#   ./run-load-tests.sh [options]
#
# Options:
#   -t, --test     Test type: auth, search, intelligence, websocket, all (default: all)
#   -s, --scenario Scenario: smoke, load, stress, spike, soak (default: load)
#   -u, --url      API base URL (default: http://localhost:3000/api)
#   -w, --wsurl    WebSocket URL (default: ws://localhost:3000/ws)
#   -o, --output   Output directory for results (default: ./results)
#   -h, --help     Show this help message
#
# Examples:
#   ./run-load-tests.sh                          # Run all tests with defaults
#   ./run-load-tests.sh -t auth -s smoke         # Run auth smoke test
#   ./run-load-tests.sh -t search -s stress      # Run search stress test
#   ./run-load-tests.sh -u http://api.example.com/api -t all -s load
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TEST_TYPE="all"
SCENARIO="load"
API_URL="http://localhost:3000/api"
WS_URL="ws://localhost:3000/ws"
OUTPUT_DIR="./results"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="${SCRIPT_DIR}/../performance-tests"

# Function to display usage
usage() {
    echo "Apollo Platform - Load Testing Runner"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -t, --test     Test type: auth, search, intelligence, websocket, all (default: all)"
    echo "  -s, --scenario Scenario: smoke, load, stress, spike, soak (default: load)"
    echo "  -u, --url      API base URL (default: http://localhost:3000/api)"
    echo "  -w, --wsurl    WebSocket URL (default: ws://localhost:3000/ws)"
    echo "  -o, --output   Output directory for results (default: ./results)"
    echo "  -h, --help     Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run all tests with defaults"
    echo "  $0 -t auth -s smoke                   # Run auth smoke test"
    echo "  $0 -t search -s stress                # Run search stress test"
    echo "  $0 -u http://api.example.com/api -t all -s load"
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

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--test)
            TEST_TYPE="$2"
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
        -w|--wsurl)
            WS_URL="$2"
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

# Validate scenario
valid_scenarios=("smoke" "load" "stress" "spike" "soak")
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
echo "  Apollo Platform Load Test Runner"
echo "========================================"
echo ""
log_info "Test Type: ${TEST_TYPE}"
log_info "Scenario: ${SCENARIO}"
log_info "API URL: ${API_URL}"
log_info "WebSocket URL: ${WS_URL}"
log_info "Output Directory: ${OUTPUT_DIR}"
echo ""

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

# Function to run a single test
run_test() {
    local test_name=$1
    local test_file=$2
    local extra_env=${3:-""}

    log_info "Running ${test_name} test (${SCENARIO} scenario)..."

    local start_time=$(date +%s)
    local result_file="${OUTPUT_DIR}/${test_name}-${SCENARIO}-$(date +%Y%m%d-%H%M%S).json"

    if k6 run \
        --env API_URL="${API_URL}" \
        --env WS_URL="${WS_URL}" \
        --env SCENARIO="${SCENARIO}" \
        ${extra_env} \
        --out json="${result_file}" \
        "${test_file}"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_success "${test_name} test completed in ${duration}s"
        return 0
    else
        log_error "${test_name} test failed"
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
    auth)
        ((total_tests++))
        if run_test "auth" "${TESTS_DIR}/load-tests/auth-load.js"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("auth")
        fi
        ;;
    search)
        ((total_tests++))
        if run_test "search" "${TESTS_DIR}/load-tests/search-load.js"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("search")
        fi
        ;;
    intelligence)
        ((total_tests++))
        if run_test "intelligence" "${TESTS_DIR}/load-tests/intelligence-load.js"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("intelligence")
        fi
        ;;
    websocket)
        ((total_tests++))
        if run_test "websocket" "${TESTS_DIR}/load-tests/websocket-load.js"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("websocket")
        fi
        ;;
    all)
        # Run all load tests
        log_info "Running all load tests sequentially..."
        echo ""

        # Auth test
        ((total_tests++))
        if run_test "auth" "${TESTS_DIR}/load-tests/auth-load.js"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("auth")
        fi
        echo ""

        # Search test
        ((total_tests++))
        if run_test "search" "${TESTS_DIR}/load-tests/search-load.js"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("search")
        fi
        echo ""

        # Intelligence test
        ((total_tests++))
        if run_test "intelligence" "${TESTS_DIR}/load-tests/intelligence-load.js"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("intelligence")
        fi
        echo ""

        # WebSocket test
        ((total_tests++))
        if run_test "websocket" "${TESTS_DIR}/load-tests/websocket-load.js"; then
            ((passed_tests++))
        else
            ((failed_tests++))
            failed_test_names+=("websocket")
        fi
        ;;
    *)
        log_error "Invalid test type: ${TEST_TYPE}"
        echo "Valid test types: auth, search, intelligence, websocket, all"
        exit 1
        ;;
esac

# Print summary
echo ""
echo "========================================"
echo "         Test Summary"
echo "========================================"
echo ""
log_info "Total Tests: ${total_tests}"
log_success "Passed: ${passed_tests}"
if [ $failed_tests -gt 0 ]; then
    log_error "Failed: ${failed_tests}"
    echo ""
    log_error "Failed tests: ${failed_test_names[*]}"
else
    log_success "All tests passed!"
fi
echo ""
log_info "Results saved to: ${OUTPUT_DIR}"
echo ""

# Exit with appropriate code
if [ $failed_tests -gt 0 ]; then
    exit 1
else
    exit 0
fi
