#!/usr/bin/env python3
"""
Performance testing script for multiprocessing vs single-threaded HTTP proxy
"""

import os
import sys
import time
import requests
import threading
import statistics
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add the evilpunch package to the path
sys.path.insert(0, str(Path(__file__).parent / "evilpunch"))

def make_request(url, timeout=10):
    """Make a single HTTP request and return timing info"""
    start_time = time.time()
    try:
        response = requests.get(url, timeout=timeout)
        end_time = time.time()
        return {
            'success': True,
            'status_code': response.status_code,
            'response_time': end_time - start_time,
            'error': None
        }
    except Exception as e:
        end_time = time.time()
        return {
            'success': False,
            'status_code': None,
            'response_time': end_time - start_time,
            'error': str(e)
        }

def run_load_test(url, num_requests, concurrent_requests, description):
    """Run a load test with specified parameters"""
    print(f"\n{description}")
    print(f"URL: {url}")
    print(f"Total requests: {num_requests}")
    print(f"Concurrent requests: {concurrent_requests}")
    print("-" * 50)
    
    start_time = time.time()
    results = []
    
    with ThreadPoolExecutor(max_workers=concurrent_requests) as executor:
        # Submit all requests
        future_to_request = {
            executor.submit(make_request, url): i 
            for i in range(num_requests)
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_request):
            result = future.result()
            results.append(result)
            
            # Print progress
            if len(results) % 10 == 0:
                print(f"Completed {len(results)}/{num_requests} requests...")
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Analyze results
    successful_requests = [r for r in results if r['success']]
    failed_requests = [r for r in results if not r['success']]
    
    if successful_requests:
        response_times = [r['response_time'] for r in successful_requests]
        avg_response_time = statistics.mean(response_times)
        min_response_time = min(response_times)
        max_response_time = max(response_times)
        median_response_time = statistics.median(response_times)
        
        # Calculate percentiles
        sorted_times = sorted(response_times)
        p95 = sorted_times[int(len(sorted_times) * 0.95)]
        p99 = sorted_times[int(len(sorted_times) * 0.99)]
        
        print(f"✅ Successful requests: {len(successful_requests)}")
        print(f"❌ Failed requests: {len(failed_requests)}")
        print(f"⏱️  Total time: {total_time:.2f}s")
        print(f"📊 Average response time: {avg_response_time:.3f}s")
        print(f"📊 Median response time: {median_response_time:.3f}s")
        print(f"📊 Min response time: {min_response_time:.3f}s")
        print(f"📊 Max response time: {max_response_time:.3f}s")
        print(f"📊 95th percentile: {p95:.3f}s")
        print(f"📊 99th percentile: {p99:.3f}s")
        print(f"🚀 Requests per second: {len(successful_requests) / total_time:.2f}")
        
        return {
            'successful_requests': len(successful_requests),
            'failed_requests': len(failed_requests),
            'total_time': total_time,
            'avg_response_time': avg_response_time,
            'requests_per_second': len(successful_requests) / total_time,
            'p95_response_time': p95,
            'p99_response_time': p99
        }
    else:
        print("❌ No successful requests")
        return None

def test_single_threaded_mode():
    """Test single-threaded mode performance"""
    print("\n" + "="*60)
    print("TESTING SINGLE-THREADED MODE")
    print("="*60)
    
    # Disable multiprocessing
    os.environ['PROXY_MULTIPROCESSING_ENABLED'] = 'false'
    
    try:
        from core.http_server import start_proxy_server, stop_proxy_server, get_proxy_status
        
        # Start server
        print("Starting single-threaded proxy server...")
        result = start_proxy_server(port=8080)
        if not result.get("ok"):
            print("Failed to start server")
            return None
        
        # Wait for server to start
        time.sleep(3)
        
        # Check status
        status = get_proxy_status()
        print(f"Server status: {status}")
        
        if not status.get("running"):
            print("Server not running")
            return None
        
        # Run load test
        results = run_load_test(
            url="http://localhost:8080/_cache/stats",
            num_requests=100,
            concurrent_requests=10,
            description="Single-threaded mode load test"
        )
        
        # Stop server
        stop_proxy_server()
        time.sleep(2)
        
        return results
        
    except Exception as e:
        print(f"Error in single-threaded test: {e}")
        import traceback
        traceback.print_exc()
        return None

def test_multiprocessing_mode():
    """Test multiprocessing mode performance"""
    print("\n" + "="*60)
    print("TESTING MULTIPROCESSING MODE")
    print("="*60)
    
    # Enable multiprocessing
    os.environ['PROXY_MULTIPROCESSING_ENABLED'] = 'true'
    os.environ['PROXY_MULTIPROCESSING_MODE'] = 'process'
    os.environ['PROXY_WORKER_PROCESSES'] = '4'  # Use 4 workers
    
    try:
        from core.http_server import start_proxy_server, stop_proxy_server, get_proxy_status
        
        # Start server
        print("Starting multiprocessing proxy server...")
        result = start_proxy_server(port=8080)
        if not result.get("ok"):
            print("Failed to start server")
            return None
        
        # Wait for server to start
        time.sleep(3)
        
        # Check status
        status = get_proxy_status()
        print(f"Server status: {status}")
        
        if not status.get("running"):
            print("Server not running")
            return None
        
        # Run load test
        results = run_load_test(
            url="http://localhost:8080/_cache/stats",
            num_requests=100,
            concurrent_requests=20,  # Higher concurrency for multiprocessing
            description="Multiprocessing mode load test"
        )
        
        # Stop server
        stop_proxy_server()
        time.sleep(2)
        
        return results
        
    except Exception as e:
        print(f"Error in multiprocessing test: {e}")
        import traceback
        traceback.print_exc()
        return None

def compare_results(single_results, multi_results):
    """Compare the results of both tests"""
    if not single_results or not multi_results:
        print("Cannot compare results - one or both tests failed")
        return
    
    print("\n" + "="*60)
    print("PERFORMANCE COMPARISON")
    print("="*60)
    
    # Calculate improvements
    rps_improvement = ((multi_results['requests_per_second'] - single_results['requests_per_second']) / 
                      single_results['requests_per_second']) * 100
    
    response_time_improvement = ((single_results['avg_response_time'] - multi_results['avg_response_time']) / 
                                single_results['avg_response_time']) * 100
    
    print(f"📈 Requests per second:")
    print(f"   Single-threaded: {single_results['requests_per_second']:.2f}")
    print(f"   Multiprocessing: {multi_results['requests_per_second']:.2f}")
    print(f"   Improvement: {rps_improvement:+.1f}%")
    
    print(f"\n⏱️  Average response time:")
    print(f"   Single-threaded: {single_results['avg_response_time']:.3f}s")
    print(f"   Multiprocessing: {multi_results['avg_response_time']:.3f}s")
    print(f"   Improvement: {response_time_improvement:+.1f}%")
    
    print(f"\n📊 95th percentile response time:")
    print(f"   Single-threaded: {single_results['p95_response_time']:.3f}s")
    print(f"   Multiprocessing: {multi_results['p95_response_time']:.3f}s")
    
    print(f"\n📊 99th percentile response time:")
    print(f"   Single-threaded: {single_results['p99_response_time']:.3f}s")
    print(f"   Multiprocessing: {multi_results['p99_response_time']:.3f}s")
    
    print(f"\n🎯 Summary:")
    if rps_improvement > 0:
        print(f"   ✅ Multiprocessing provides {rps_improvement:.1f}% better throughput")
    else:
        print(f"   ❌ Multiprocessing shows {abs(rps_improvement):.1f}% worse throughput")
    
    if response_time_improvement > 0:
        print(f"   ✅ Multiprocessing provides {response_time_improvement:.1f}% better response time")
    else:
        print(f"   ❌ Multiprocessing shows {abs(response_time_improvement):.1f}% worse response time")

def main():
    """Main test function"""
    print("🚀 HTTP Proxy Performance Test")
    print("Testing single-threaded vs multiprocessing performance")
    
    # Clean up any existing environment variables
    for key in ['PROXY_MULTIPROCESSING_ENABLED', 'PROXY_MULTIPROCESSING_MODE', 'PROXY_WORKER_PROCESSES']:
        if key in os.environ:
            del os.environ[key]
    
    try:
        # Test single-threaded mode
        single_results = test_single_threaded_mode()
        
        # Test multiprocessing mode
        multi_results = test_multiprocessing_mode()
        
        # Compare results
        compare_results(single_results, multi_results)
        
        print("\n🎉 Performance test completed!")
        
    except KeyboardInterrupt:
        print("\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n💥 Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
