#!/bin/bash

# HTTP Proxy Server Multiprocessing Startup Script
# This script demonstrates how to start the proxy server with multiprocessing enabled

echo "🚀 Starting HTTP Proxy Server with Multiprocessing"
echo "=================================================="

# Configuration (multiprocessing enabled by default)
export PROXY_MULTIPROCESSING_ENABLED=true
export PROXY_MULTIPROCESSING_MODE=process
export PROXY_WORKER_PROCESSES=4
export PROXY_DEBUG=true
export PROXY_DEBUG_LEVEL=INFO

# Display configuration
echo "Configuration:"
echo "  Multiprocessing enabled: $PROXY_MULTIPROCESSING_ENABLED"
echo "  Multiprocessing mode: $PROXY_MULTIPROCESSING_MODE"
echo "  Worker processes: $PROXY_WORKER_PROCESSES"
echo "  Debug mode: $PROXY_DEBUG"
echo "  Debug level: $PROXY_DEBUG_LEVEL"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is not installed or not in PATH"
    exit 1
fi

# Check if the evilpunch package exists
if [ ! -d "evilpunch" ]; then
    echo "❌ evilpunch package directory not found"
    echo "Please run this script from the project root directory"
    exit 1
fi

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "📦 Activating virtual environment..."
    source venv/bin/activate
else
    echo "⚠️  No virtual environment found, using system Python"
fi

# Function to start the proxy server
start_proxy() {
    echo "🔧 Starting proxy server..."
    python3 -c "
import sys
import os
sys.path.insert(0, 'evilpunch')

try:
    from core.http_server import start_proxy_server, get_proxy_status, get_multiprocessing_stats
    import time
    
    print('Starting proxy server on port 8080...')
    result = start_proxy_server(port=8080)
    print(f'Start result: {result}')
    
    if result.get('ok'):
        print('Waiting for server to start...')
        time.sleep(3)
        
        status = get_proxy_status()
        print(f'Server status: {status}')
        
        if status.get('running'):
            print('✅ Server started successfully!')
            print('')
            print('Monitoring endpoints:')
            print('  - Status: http://localhost:8080/_cache/stats')
            print('  - Multiprocessing: http://localhost:8080/_multiprocessing/stats')
            print('  - Cache config: http://localhost:8080/_cache/config')
            print('')
            print('Press Ctrl+C to stop the server...')
            
            # Keep the server running
            try:
                while True:
                    time.sleep(5)
                    # Check status every 5 seconds
                    current_status = get_proxy_status()
                    if not current_status.get('running'):
                        print('❌ Server stopped unexpectedly')
                        break
            except KeyboardInterrupt:
                print('\\n🛑 Stopping server...')
                from core.http_server import stop_proxy_server
                stop_result = stop_proxy_server()
                print(f'Stop result: {stop_result}')
                print('✅ Server stopped')
        else:
            print('❌ Server failed to start')
            print(f'Status: {status}')
    else:
        print('❌ Failed to start server')
        print(f'Error: {result}')
        
except ImportError as e:
    print(f'❌ Import error: {e}')
    print('Make sure you are in the correct directory and dependencies are installed')
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()
"
}

# Function to show help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  start     Start the proxy server (default)"
    echo "  test      Run the test script"
    echo "  perf      Run performance test"
    echo "  help      Show this help message"
    echo ""
    echo "Environment Variables:"
echo "  PROXY_WORKER_PROCESSES    Number of worker processes (default: auto-detected)"
echo "  PROXY_MULTIPROCESSING_MODE Multiprocessing mode: process/thread (default: process)"
echo "  PROXY_MULTIPROCESSING_ENABLED Enable/disable multiprocessing (default: true)"
echo "  PROXY_DEBUG               Enable debug mode (default: true)"
echo "  PROXY_DEBUG_LEVEL         Debug level: DEBUG/INFO/WARN/ERROR (default: INFO)"
    echo ""
    echo "Examples:"
echo "  $0 start                    # Start with multiprocessing enabled (default)"
echo "  PROXY_WORKER_PROCESSES=8 $0 start  # Start with 8 workers"
echo "  PROXY_MULTIPROCESSING_ENABLED=false $0 start  # Disable multiprocessing"
echo "  $0 test                     # Run test script"
echo "  $0 perf                     # Run performance test"
}

# Function to run tests
run_tests() {
    echo "🧪 Running test script..."
    if [ -f "test_multiprocessing_proxy.py" ]; then
        python3 test_multiprocessing_proxy.py
    else
        echo "❌ Test script not found: test_multiprocessing_proxy.py"
        exit 1
    fi
}

# Function to run performance test
run_performance_test() {
    echo "📊 Running performance test..."
    if [ -f "performance_test.py" ]; then
        python3 performance_test.py
    else
        echo "❌ Performance test script not found: performance_test.py"
        exit 1
    fi
}

# Main script logic
case "${1:-start}" in
    start)
        start_proxy
        ;;
    test)
        run_tests
        ;;
    perf)
        run_performance_test
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "❌ Unknown option: $1"
        show_help
        exit 1
        ;;
esac
